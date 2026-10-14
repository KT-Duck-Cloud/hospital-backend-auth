"""인증 서비스 A1·A2·A7 과 공통 토큰 검증(shared/auth.py) 테스트."""
from datetime import timedelta

import jwt
import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import ACCOUNTS, TEST_PASSWORD
from shared import config, permissions
from shared.models import AuditLog, User, UserSession, utcnow

LOGIN = "/api/v1/auth/login"
ME = "/api/v1/auth/me"
LOGOUT = "/api/v1/auth/logout"


def login(client, login_id, password=TEST_PASSWORD):
    return client.post(LOGIN, json={"login_id": login_id, "password": password})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def token_of(client, login_id):
    r = login(client, login_id)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def audit_rows(db_session):
    db_session.expire_all()
    return db_session.scalars(select(AuditLog).order_by(AuditLog.id)).all()


# ---------- 로그인 성공 ----------

EXPECTED_HOME = {"PATIENT": "/", "DOCTOR": "/manage", "MANAGER": "/manage", "ADMIN": "/manage", "DIRECTOR": "/manage"}


@pytest.mark.parametrize("login_id, role, dept, patient", ACCOUNTS)
def test_login_success_for_each_role(client, db_session, login_id, role, dept, patient):
    r = login(client, login_id)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["home_path"] == EXPECTED_HOME.get(role, "/workspace")
    assert body["expires_in"] == (14400 if role in ("ADMIN", "DIRECTOR") else 28800)
    assert body["user"]["role"] == role and body["user"]["department_id"] == dept
    assert body["user"]["patient_id"] == patient

    claims = jwt.decode(body["access_token"], config.JWT_SECRET, algorithms=["HS256"], issuer=config.JWT_ISSUER)
    assert claims["sub"] == str(body["user"]["id"]) and claims["role"] == role
    assert claims["department_id"] == dept and claims["patient_id"] == patient
    assert claims["exp"] - claims["iat"] == body["expires_in"]

    session = db_session.get(UserSession, claims["jti"])  # jti = sessions.id
    assert session is not None and session.revoked_at is None
    idle = timedelta(minutes=15 if role in ("ADMIN", "DIRECTOR") else 30)
    assert session.idle_expires_at - session.last_seen_at == idle

    me = client.get(ME, headers=bearer(body["access_token"]))
    assert me.status_code == 200 and me.json()["login_id"] == login_id and me.json()["role"] == role


# ---------- 로그인 실패 ----------

def test_wrong_password_and_unknown_id_look_the_same(client, monkeypatch):
    import app.main as auth_main

    calls = []
    real_checkpw = auth_main.bcrypt.checkpw
    monkeypatch.setattr(auth_main.bcrypt, "checkpw", lambda p, h: calls.append(1) or real_checkpw(p, h))

    wrong = login(client, "nurse_im01", "wrong-password")
    unknown = login(client, "no_such_user", "wrong-password")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["code"] == unknown.json()["code"] == "UNAUTHORIZED"
    assert wrong.json()["message"] == unknown.json()["message"]
    # 없는 아이디도 bcrypt 확인을 똑같이 한 번 한다 (응답 시간을 같게)
    assert len(calls) == 2


def test_login_body_rejects_extra_fields(client):
    r = client.post(LOGIN, json={"login_id": "nurse_im01", "password": TEST_PASSWORD, "role": "DIRECTOR"})
    assert r.status_code == 422


def test_password_over_72_bytes_fails(client):
    assert login(client, "nurse_im01", TEST_PASSWORD + "x" * 80).status_code == 401


def test_inactive_account_cannot_login(client, db_session):
    user = db_session.scalar(select(User).where(User.login_id == "dev01"))
    user.is_active = False
    db_session.commit()
    r = login(client, "dev01")
    assert r.status_code == 401 and r.json()["message"] == login(client, "dev01", "x").json()["message"]


# ---------- 잠금 (DEV2) ----------

def test_five_failures_lock_even_correct_password(client, db_session):
    for _ in range(5):
        assert login(client, "nurse_im01", "wrong").status_code == 401
    assert login(client, "nurse_im01").status_code == 401  # 맞는 비밀번호도 401

    user = db_session.scalar(select(User).where(User.login_id == "nurse_im01"))
    locked_until = user.locked_until
    assert locked_until is not None
    assert timedelta(minutes=14) < locked_until - utcnow() <= timedelta(minutes=15)

    # 잠긴 동안 더 시도해도 잠금 시간이 늘어나지 않는다
    for _ in range(3):
        login(client, "nurse_im01", "wrong")
    db_session.expire_all()
    assert db_session.get(User, user.id).locked_until == locked_until

    # 잠금이 끝나면 다시 로그인된다
    user = db_session.get(User, user.id)
    user.locked_until = utcnow() - timedelta(seconds=1)
    db_session.commit()
    assert login(client, "nurse_im01").status_code == 200
    db_session.expire_all()
    user = db_session.get(User, user.id)
    assert user.failed_login_count == 0 and user.locked_until is None and user.last_login_at is not None

    actions = [(a.action, a.result) for a in audit_rows(db_session)]
    assert ("LOGIN_LOCKED", "DENIED") in actions and ("LOGIN", "SUCCESS") in actions


def test_failures_older_than_15_minutes_do_not_count(client, db_session):
    for _ in range(4):
        login(client, "head_im01", "wrong")
    user = db_session.scalar(select(User).where(User.login_id == "head_im01"))
    assert user.failed_login_count == 4
    user.first_failed_at = utcnow() - timedelta(minutes=16)
    db_session.commit()

    assert login(client, "head_im01", "wrong").status_code == 401  # 새로 1회부터
    db_session.expire_all()
    user = db_session.get(User, user.id)
    assert user.failed_login_count == 1 and user.locked_until is None
    assert login(client, "head_im01").status_code == 200


# ---------- IP 요청 제한 ----------

def test_ip_rate_limit(client):
    for _ in range(20):
        login(client, "tester01", "wrong")
    r = login(client, "tester01")
    assert r.status_code == 429 and r.json()["code"] == "TOO_MANY_REQUESTS"
    assert int(r.headers["Retry-After"]) >= 1


# ---------- 토큰 검증 ----------

def test_no_token_is_401(client):
    for headers in ({}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer "}):
        r = client.get(ME, headers=headers)
        assert r.status_code == 401 and r.json()["code"] == "UNAUTHORIZED"


def test_forged_tokens_are_401(client):
    token = token_of(client, "nurse_im01")
    claims = jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"], issuer=config.JWT_ISSUER)

    other_key = jwt.encode(claims, "x" * 48, algorithm="HS256")
    escalated = jwt.encode({**claims, "role": "DIRECTOR"}, "x" * 48, algorithm="HS256")
    none_alg = jwt.encode(claims, None, algorithm="none")
    wrong_issuer = jwt.encode({**claims, "iss": "evil"}, config.JWT_SECRET, algorithm="HS256")
    head, payload, sig = token.split(".")
    tampered = f"{head}.{payload[:-2]}xx.{sig}"

    for bad in (other_key, escalated, none_alg, wrong_issuer, tampered, "garbage"):
        assert client.get(ME, headers=bearer(bad)).status_code == 401


def test_role_in_token_must_match_db(client, db_session):
    token = token_of(client, "nurse_im01")
    user = db_session.scalar(select(User).where(User.login_id == "nurse_im01"))
    user.role = "TESTER"  # 세션을 끊지 않고 역할만 바뀐 경우도 막는다
    db_session.commit()
    assert client.get(ME, headers=bearer(token)).status_code == 401


def test_expired_token_is_401(client):
    token = token_of(client, "nurse_im01")
    claims = jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"], issuer=config.JWT_ISSUER)
    now = claims["iat"]
    expired = jwt.encode({**claims, "iat": now - 7200, "exp": now - 60}, config.JWT_SECRET, algorithm="HS256")
    assert client.get(ME, headers=bearer(expired)).status_code == 401


def test_logout_then_same_token_is_401(client, db_session):
    token = token_of(client, "patient01")
    r = client.post(LOGOUT, headers=bearer(token))
    assert r.status_code == 200
    assert client.get(ME, headers=bearer(token)).status_code == 401
    assert client.post(LOGOUT, headers=bearer(token)).status_code == 401
    assert ("LOGOUT", "SUCCESS") in [(a.action, a.result) for a in audit_rows(db_session)]


def test_idle_timeout_is_401(client, db_session):
    token = token_of(client, "nurse_im01")
    jti = jwt.decode(token, options={"verify_signature": False})["jti"]
    session = db_session.get(UserSession, jti)
    session.idle_expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()
    assert client.get(ME, headers=bearer(token)).status_code == 401


def test_absolute_timeout_is_401(client, db_session):
    token = token_of(client, "director01")
    jti = jwt.decode(token, options={"verify_signature": False})["jti"]
    session = db_session.get(UserSession, jti)
    session.absolute_expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()
    assert client.get(ME, headers=bearer(token)).status_code == 401


def test_last_seen_updates_at_most_once_a_minute(client, db_session):
    token = token_of(client, "nurse_im01")
    jti = jwt.decode(token, options={"verify_signature": False})["jti"]
    first = db_session.get(UserSession, jti).last_seen_at

    client.get(ME, headers=bearer(token))
    db_session.expire_all()
    assert db_session.get(UserSession, jti).last_seen_at == first  # 1분 안: 갱신 안 함

    session = db_session.get(UserSession, jti)
    session.last_seen_at = first - timedelta(minutes=2)
    session.idle_expires_at = first + timedelta(minutes=5)
    db_session.commit()
    client.get(ME, headers=bearer(token))
    db_session.expire_all()
    session = db_session.get(UserSession, jti)
    assert session.last_seen_at > first - timedelta(minutes=2)
    assert session.idle_expires_at - session.last_seen_at == timedelta(minutes=30)  # 유휴 만료 연장


def test_deactivated_or_revoked_user_is_401(client, db_session):
    from shared.auth import revoke_user_sessions

    token1 = token_of(client, "tester01")
    token2 = token_of(client, "tester01")
    user = db_session.scalar(select(User).where(User.login_id == "tester01"))
    assert revoke_user_sessions(db_session, user.id) == 2
    db_session.commit()
    assert client.get(ME, headers=bearer(token1)).status_code == 401
    assert client.get(ME, headers=bearer(token2)).status_code == 401

    token3 = token_of(client, "tester01")
    user = db_session.get(User, user.id)
    user.is_active = False
    db_session.commit()
    assert client.get(ME, headers=bearer(token3)).status_code == 401


# ---------- READ_ONLY_MODE ----------

def test_login_is_503_in_read_only_mode(client, monkeypatch):
    monkeypatch.setattr(config, "READ_ONLY_MODE", True)
    r = login(client, "nurse_im01")
    assert r.status_code == 503 and r.json()["code"] == "WRITE_DISABLED"


# ---------- 권한 표·require_roles ----------

@pytest.fixture()
def guarded_client(client, monkeypatch):
    """권한 검사를 거는 작은 시험용 앱 (같은 DB·같은 키)"""
    from shared.auth import CurrentUser, enforce_permissions, require_roles
    from shared.errors import install_error_handlers

    monkeypatch.setitem(permissions.PERMISSIONS, ("GET", "/api/v1/test/nurse"), permissions.LOGGED_IN)
    monkeypatch.setitem(permissions.PERMISSIONS, ("GET", "/api/v1/test/director"),
                        frozenset({permissions.DIRECTOR}))
    test_app = FastAPI()
    test_app.state.service_name = "reservation"
    install_error_handlers(test_app)
    router = APIRouter(prefix="/api/v1", dependencies=[Depends(enforce_permissions)])

    @router.get("/test/nurse")
    def nurse_only(user: CurrentUser = Depends(require_roles("NURSE"))):
        return {"id": user.id}

    @router.get("/test/director")
    def director_only():
        return {"ok": True}

    @router.get("/test/unlisted")
    def unlisted():
        return {"ok": True}

    test_app.include_router(router)
    with TestClient(test_app) as c:
        yield c


def test_require_roles_403_and_audit(client, guarded_client, db_session):
    nurse = token_of(client, "nurse_im01")
    tester = token_of(client, "tester01")
    assert guarded_client.get("/api/v1/test/nurse", headers=bearer(nurse)).status_code == 200
    r = guarded_client.get("/api/v1/test/nurse", headers=bearer(tester))
    assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN"
    assert guarded_client.get("/api/v1/test/nurse").status_code == 401

    denied = [a for a in audit_rows(db_session) if a.result == "DENIED" and a.action == "ACCESS_DENIED"]
    assert len(denied) == 1
    assert denied[0].service == "reservation" and denied[0].target_id == "GET /api/v1/test/nurse"


def test_permission_table_roles_and_default_deny(client, guarded_client):
    director = token_of(client, "director01")
    nurse = token_of(client, "nurse_im01")
    assert guarded_client.get("/api/v1/test/director", headers=bearer(director)).status_code == 200
    assert guarded_client.get("/api/v1/test/director", headers=bearer(nurse)).status_code == 403
    # 표에 없는 API 는 누구든 403
    assert guarded_client.get("/api/v1/test/unlisted", headers=bearer(director)).status_code == 403


def test_require_roles_rejects_unknown_role():
    from shared.auth import require_roles

    with pytest.raises(ValueError):
        require_roles("SUPERUSER")


# ---------- 로그에 비밀번호·토큰이 남지 않는지 ----------

def test_no_password_or_token_in_audit_or_stdout(client, db_session, capsys):
    token = token_of(client, "admin01")
    login(client, "admin01", "wrong-" + TEST_PASSWORD)
    login(client, "nobody", TEST_PASSWORD)
    client.get(ME, headers=bearer(token))
    client.post(LOGOUT, headers=bearer(token))

    rows = audit_rows(db_session)
    assert {(a.action, a.result) for a in rows} >= {("LOGIN", "SUCCESS"), ("LOGIN", "FAIL"), ("LOGOUT", "SUCCESS")}
    dump = " ".join(str(getattr(a, c.name)) for a in rows for c in AuditLog.__table__.columns)
    out = capsys.readouterr()
    for secret in (TEST_PASSWORD, token, token.split(".")[2]):
        assert secret not in dump
        assert secret not in out.out and secret not in out.err


def test_health_endpoints_unchanged(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["service"] == "auth"
    assert client.get("/readyz").status_code == 200
