"""인증 서비스: 로그인(A1), 내 정보(A2), 로그아웃(A7). 기준: docs/api-spec.md 2장 "인증", 보안 DEV2·DEV3."""
import os
import secrets
from datetime import timedelta

import bcrypt
from fastapi import APIRouter, Depends, FastAPI, Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app import admin, schemas
from app.ratelimit import SlidingWindowLimiter
from shared import audit, config
from shared.auth import (
    CurrentUser, enforce_permissions, get_current_user, issue_token, require_jwt_secret, session_timeouts,
)
from shared.db import get_db
from shared.errors import ApiError, install_error_handlers
from shared.middleware import install_read_only_guard, install_request_id
from shared.models import User, UserSession, utcnow
from shared.ops import install_ops

SERVICE_NAME = "auth"

# 로그인 잠금 (DEV2): 계정 기준 15분 안 5회 실패 → 15분 잠금
MAX_FAILED_LOGINS = 5
FAILED_LOGIN_WINDOW = timedelta(minutes=15)
LOCK_DURATION = timedelta(minutes=15)
BCRYPT_MAX_BYTES = 72


# 화면별 첫 경로 (web/): 환자 /, 관리 화면 /manage (의사·원무과장·관리자·원장), 나머지 /workspace
HOME_PATHS = {"PATIENT": "/", "DOCTOR": "/manage", "MANAGER": "/manage", "ADMIN": "/manage", "DIRECTOR": "/manage"}
DEFAULT_HOME_PATH = "/workspace"

require_jwt_secret()  # JWT_SECRET 이 없으면 시작하지 않는다.

# 없는 아이디일 때도 bcrypt 확인을 한 번 해서, 틀린 비밀번호와 응답 시간을 같게 만든다.
_DUMMY_HASH = bcrypt.hashpw(secrets.token_bytes(16), bcrypt.gensalt(rounds=config.BCRYPT_ROUNDS))

# IP별 로그인 요청 제한 (같은 IP 1분 20회 기본)
login_limiter = SlidingWindowLimiter(limit=int(os.getenv("LOGIN_RATE_LIMIT_PER_MINUTE", "20")), window_seconds=60)

app = FastAPI(title="인증 서비스", version=config.APP_VERSION)
api = APIRouter(prefix="/api/v1", dependencies=[Depends(enforce_permissions)])

install_ops(app, SERVICE_NAME)
install_error_handlers(app)
install_read_only_guard(app)  # READ_ONLY_MODE 면 로그인도 503 (세션을 DB 에 써야 하므로)
install_request_id(app)  # 마지막에 등록한 미들웨어가 가장 바깥이라, 오류 응답에도 request_id 가 실린다.


def login_failed() -> ApiError:
    # 없는 아이디·틀린 비밀번호·잠김·비활성 모두 같은 문구
    return ApiError(401, "UNAUTHORIZED", "아이디 또는 비밀번호가 올바르지 않습니다")


def check_login_rate(request: Request) -> None:
    ip = audit.client_ip_of(request) or "unknown"
    if not login_limiter.allow(ip):
        raise ApiError(429, "TOO_MANY_REQUESTS", "요청이 너무 많습니다. 잠시 후 다시 시도하세요",
                       headers={"Retry-After": str(login_limiter.retry_after(ip))})


def verify_password(password: str, password_hash: str | None) -> bool:
    """항상 bcrypt 확인을 정확히 한 번 한다 (계정이 없어도). 72바이트를 넘으면 실패."""
    encoded = password.encode("utf-8")
    too_long = len(encoded) > BCRYPT_MAX_BYTES
    target = password_hash.encode("ascii") if password_hash else _DUMMY_HASH
    try:
        matched = bcrypt.checkpw(encoded[:BCRYPT_MAX_BYTES], target)
    except ValueError:  # 저장된 해시가 깨진 경우
        matched = False
    return matched and not too_long and password_hash is not None


@api.post("/auth/login", response_model=schemas.LoginOut, dependencies=[Depends(check_login_rate)])
def login(body: schemas.LoginIn, request: Request, db: Session = Depends(get_db)):
    """로그인. 성공하면 세션을 만들고 출입증(JWT)과 첫 화면 경로를 준다."""
    now = utcnow()
    # FOR UPDATE: 같은 계정에 동시에 들어온 실패가 횟수를 덮어쓰지 않도록 행을 잠근다.
    user = db.scalar(select(User).where(User.login_id == body.login_id).with_for_update())
    password_ok = verify_password(body.password, user.password_hash if user else None)

    if user is None:
        db.rollback()
        audit.write_audit(request, "LOGIN", audit.FAIL, target_type="login_id", target_id=body.login_id)
        raise login_failed()

    if user.locked_until is not None and user.locked_until > now:
        # 잠긴 동안은 맞는 비밀번호도 실패. 실패 횟수·잠금 시간은 늘리지 않는다.
        db.rollback()
        audit.write_audit(request, "LOGIN", audit.DENIED, user_id=user.id, target_type="reason", target_id="LOCKED")
        raise login_failed()

    if not user.is_active:
        db.rollback()
        audit.write_audit(request, "LOGIN", audit.DENIED, user_id=user.id, target_type="reason", target_id="INACTIVE")
        raise login_failed()

    if not password_ok:
        if user.first_failed_at is None or now - user.first_failed_at >= FAILED_LOGIN_WINDOW:
            user.failed_login_count = 1
            user.first_failed_at = now
        else:
            user.failed_login_count += 1
        locked = user.failed_login_count >= MAX_FAILED_LOGINS
        if locked:
            user.locked_until = now + LOCK_DURATION
            user.failed_login_count = 0
            user.first_failed_at = None
        user_id = user.id
        db.commit()
        audit.write_audit(request, "LOGIN", audit.FAIL, user_id=user_id)
        if locked:
            audit.write_audit(request, "LOGIN_LOCKED", audit.DENIED, user_id=user_id)
        raise login_failed()

    # 성공: 실패 기록을 지우고 세션을 만든다.
    idle, absolute = session_timeouts(user.role)
    session = UserSession(
        id=secrets.token_urlsafe(32),
        user_id=user.id,
        last_seen_at=now,
        idle_expires_at=now + idle,
        absolute_expires_at=now + absolute,
        created_at=now,
        updated_at=now,
    )
    user.failed_login_count = 0
    user.first_failed_at = None
    user.locked_until = None
    user.last_login_at = now
    db.add(session)
    token = issue_token(user, session.id, now, session.absolute_expires_at)
    user_out = schemas.UserOut(
        id=user.id, name=user.name, role=user.role, department_id=user.department_id, patient_id=user.patient_id,
    )
    db.commit()  # 세션이 저장된 뒤에만 토큰을 돌려준다.

    audit.write_audit(request, "LOGIN", audit.SUCCESS, user_id=user_out.id)
    return schemas.LoginOut(
        access_token=token,
        expires_in=int(absolute.total_seconds()),
        user=user_out,
        home_path=HOME_PATHS.get(user_out.role, DEFAULT_HOME_PATH),
    )


@api.get("/auth/me", response_model=schemas.MeOut)
def me(user: CurrentUser = Depends(get_current_user)):
    """내 정보"""
    return schemas.MeOut(
        id=user.id, login_id=user.login_id, name=user.name, role=user.role,
        department_id=user.department_id, patient_id=user.patient_id,
    )


@api.post("/auth/logout", response_model=schemas.LogoutOut)
def logout(request: Request, user: CurrentUser = Depends(get_current_user), db: Session = Depends(get_db)):
    """로그아웃: 세션을 끊는다. 이후 같은 토큰은 401."""
    now = utcnow()
    db.execute(
        update(UserSession)
        .where(UserSession.id == user.session_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now, updated_at=now)
    )
    db.commit()
    audit.write_audit(request, "LOGOUT", audit.SUCCESS, user_id=user.id, target_type="session",
                      target_id=user.session_id)
    return schemas.LogoutOut()


app.include_router(api) 
app.include_router(admin.router)  # A3~A6 관리 API 
