"""관리 API: A3 계정 목록, A4 계정 만들기, A5 역할·부서·활성 변경, A6 감사 로그 조회.

- 권한은 shared/permissions.py (A3: ADMIN·DIRECTOR·TESTER, A4·A5·A6: ADMIN·DIRECTOR)
- DIRECTOR 역할을 주거나 DIRECTOR 계정을 바꾸는 것은 DIRECTOR 만 한다 (ADMIN 의 권한 올리기 방지).
- 자기 계정은 A5 로 바꾸지 않는다 (스스로 잠기거나 권한을 올리지 않도록).
- A5 에서 역할·부서·활성 중 하나라도 바뀌면 그 사용자의 세션을 모두 끊는다 (이전 토큰 401).
- 감사 로그는 조회만 한다. 수정·삭제 API 는 없다.
"""
from typing import Annotated

import bcrypt
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import schemas
from shared import audit, config
from shared.auth import CurrentUser, enforce_permissions, get_current_user, revoke_user_sessions
from shared.db import get_db
from shared.errors import bad_request, conflict, forbidden, not_found
from shared.models import AuditLog, User, utcnow
from shared.permissions import DEPT_HEAD, DIRECTOR, DOCTOR, MANAGER, NURSE, PATIENT
from shared.timeutil import kst_day_range_utc

router = APIRouter(prefix="/api/v1/admin", dependencies=[Depends(enforce_permissions)])

# 부서가 꼭 있어야 하는 역할 (자기 부서 범위로 일하는 직원)
DEPARTMENT_REQUIRED = frozenset({NURSE, DOCTOR, MANAGER, DEPT_HEAD})
BCRYPT_MAX_BYTES = 72


def _deny(request: Request, actor: CurrentUser, target_id) -> None:
    audit.write_audit(request, "ACCESS_DENIED", audit.DENIED, user_id=actor.id, target_type="user", target_id=target_id)
    raise forbidden()


def _check_account_shape(db: Session, role: str, department_id: int | None, patient_id: int | None,
                         exclude_user_id: int | None = None) -> None:
    """역할에 맞는 소속인지: PATIENT 는 환자 연결·부서 없음, 부서 직원은 부서 필수, 그 밖에는 환자 연결 없음."""
    if role == PATIENT:
        if patient_id is None or department_id is not None:
            raise bad_request("PATIENT 계정은 patient_id 가 필요하고 department_id 는 없어야 합니다")
    elif patient_id is not None:
        raise bad_request("patient_id 는 PATIENT 계정에만 씁니다")
    if role in DEPARTMENT_REQUIRED and department_id is None:
        raise bad_request(f"{role} 계정은 department_id 가 필요합니다")
    # departments·patients 는 예약 서비스 표다. 인증 서비스는 존재 여부만 읽는다.
    if department_id is not None and db.scalar(
        text("SELECT id FROM departments WHERE id = :id"), {"id": department_id}
    ) is None:
        raise bad_request("부서를 찾을 수 없습니다")
    if patient_id is not None and db.scalar(
        text("SELECT id FROM patients WHERE id = :id"), {"id": patient_id}
    ) is None:
        raise bad_request("환자를 찾을 수 없습니다")
    if patient_id is not None and db.scalar(
        select(User.id).where(User.patient_id == patient_id, User.id != (exclude_user_id or 0))
    ) is not None:
        raise conflict("이미 계정이 있는 환자입니다")  # DB 의 UNIQUE(users.patient_id) 와 같은 규칙


# ---------- A3 계정 목록 ----------

@router.get("/users", response_model=schemas.AdminUserPage)
def list_users(filters: Annotated[schemas.AdminUserFilter, Query()], db: Session = Depends(get_db)):
    """직원 계정 목록 (환자 계정 제외). 역할·부서·활성·아이디/이름 일부로 거른다."""
    conditions = [User.role != PATIENT]
    if filters.role:
        conditions.append(User.role == filters.role)
    if filters.department_id is not None:
        conditions.append(User.department_id == filters.department_id)
    if filters.is_active is not None:
        conditions.append(User.is_active.is_(filters.is_active))
    if filters.q:
        conditions.append(User.login_id.contains(filters.q, autoescape=True)
                          | User.name.contains(filters.q, autoescape=True))
    total = db.scalar(select(func.count()).select_from(User).where(*conditions))
    items = db.scalars(
        select(User).where(*conditions).order_by(User.id)
        .offset((filters.page - 1) * filters.size).limit(filters.size)
    ).all()
    return {"items": items, "page": filters.page, "size": filters.size, "total": total}


# ---------- A4 계정 만들기 ----------

@router.post("/users", response_model=schemas.AdminUserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: schemas.AdminUserCreate, request: Request,
    actor: CurrentUser = Depends(get_current_user), db: Session = Depends(get_db),
):
    """계정 만들기. 비밀번호는 bcrypt 해시만 저장한다. 같은 아이디면 409."""
    if body.role == DIRECTOR and actor.role != DIRECTOR:
        _deny(request, actor, body.login_id)
    password = body.password.encode("utf-8")
    if len(password) > BCRYPT_MAX_BYTES:
        raise bad_request(f"비밀번호는 {BCRYPT_MAX_BYTES}바이트 이하여야 합니다")
    _check_account_shape(db, body.role, body.department_id, body.patient_id)

    now = utcnow()
    user = User(
        login_id=body.login_id, name=body.name, role=body.role,
        department_id=body.department_id, patient_id=body.patient_id, is_active=True,
        password_hash=bcrypt.hashpw(password, bcrypt.gensalt(rounds=config.BCRYPT_ROUNDS)).decode("ascii"),
        failed_login_count=0, created_at=now, updated_at=now,
    )
    db.add(user)
    try:
        db.flush()
        audit.add_audit(db, request, "USER_CREATE", audit.SUCCESS, user_id=actor.id,
                        target_type="user", target_id=user.id)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise conflict("이미 있는 아이디이거나, 이미 계정이 있는 환자입니다") from None
    db.refresh(user)
    return user


# ---------- A5 역할·부서·활성 변경 ----------

@router.patch("/users/{user_id}", response_model=schemas.AdminUserUpdateOut)
def update_user(
    user_id: int, body: schemas.AdminUserUpdate, request: Request,
    actor: CurrentUser = Depends(get_current_user), db: Session = Depends(get_db),
):
    """보낸 칸만 바꾼다. 하나라도 바뀌면 그 사용자의 세션을 모두 끊는다 (변경과 같은 트랜잭션)."""
    sent = body.model_fields_set
    if not sent:
        raise bad_request("바꿀 칸(role, department_id, is_active)이 없습니다")
    if ("role" in sent and body.role is None) or ("is_active" in sent and body.is_active is None):
        raise bad_request("role, is_active 는 null 로 바꿀 수 없습니다")
    if user_id == actor.id:
        raise bad_request("자기 계정은 바꿀 수 없습니다")

    user = db.scalar(select(User).where(User.id == user_id).with_for_update())
    if user is None:
        raise not_found("계정을 찾을 수 없습니다")
    new_role = body.role if "role" in sent else user.role
    if actor.role != DIRECTOR and DIRECTOR in (user.role, new_role):
        _deny(request, actor, user_id)
    new_department = body.department_id if "department_id" in sent else user.department_id
    new_active = body.is_active if "is_active" in sent else user.is_active
    _check_account_shape(db, new_role, new_department, user.patient_id, exclude_user_id=user.id)

    changed = (new_role, new_department, new_active) != (user.role, user.department_id, user.is_active)
    revoked = 0
    if changed:
        user.role, user.department_id, user.is_active = new_role, new_department, new_active
        user.updated_at = utcnow()
        revoked = revoke_user_sessions(db, user.id)
        audit.add_audit(db, request, "USER_UPDATE", audit.SUCCESS, user_id=actor.id,
                        target_type="user", target_id=user.id)
        db.commit()
        db.refresh(user)
    out = schemas.AdminUserOut.model_validate(user)
    return schemas.AdminUserUpdateOut(**out.model_dump(), revoked_sessions=revoked)


# ---------- A6 감사 로그 조회 ----------

@router.get("/audit-logs", response_model=schemas.AuditLogPage)
def list_audit_logs(
    filters: Annotated[schemas.AuditLogFilter, Query()], request: Request,
    actor: CurrentUser = Depends(get_current_user), db: Session = Depends(get_db),
):
    """감사 로그 조회 (최신순). 날짜는 KST. 조회 자체도 감사 로그에 남긴다."""
    conditions = []
    if filters.date_from:
        conditions.append(AuditLog.created_at >= kst_day_range_utc(filters.date_from)[0])
    if filters.date_to:
        conditions.append(AuditLog.created_at < kst_day_range_utc(filters.date_to)[1])
    if filters.user_id is not None:
        conditions.append(AuditLog.user_id == filters.user_id)
    if filters.action:
        conditions.append(AuditLog.action == filters.action)
    if filters.result:
        conditions.append(AuditLog.result == filters.result)
    if filters.service:
        conditions.append(AuditLog.service == filters.service)
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*conditions))
    items = db.scalars(
        select(AuditLog).where(*conditions).order_by(AuditLog.id.desc())
        .offset((filters.page - 1) * filters.size).limit(filters.size)
    ).all()
    audit.write_audit(request, "AUDIT_LOG_VIEW", audit.SUCCESS, user_id=actor.id)
    return {"items": items, "page": filters.page, "size": filters.size, "total": total} 
