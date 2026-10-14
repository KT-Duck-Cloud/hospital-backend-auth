"""인증 API 요청/응답 모양. 정해진 칸 외에는 받지 않는다 (extra=forbid → 422)."""
from datetime import date
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from shared.timeutil import UtcDateTime

LoginId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=50)]
# bcrypt 는 72바이트까지만 쓴다. 글자 수 제한은 넉넉히 두고, 바이트 초과는 로그인 실패로 처리한다.
Password = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    login_id: LoginId
    password: Password


class UserOut(BaseModel):
    id: int
    name: str
    role: str
    department_id: int | None
    patient_id: int | None


class MeOut(UserOut):
    login_id: str


class LoginOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int          # 최대 시간(초): 일반 28800, ADMIN·DIRECTOR 14400
    user: UserOut
    home_path: str


class LogoutOut(BaseModel):
    status: str = "logged_out"


# ---------- 관리 API (A3~A6) ----------

Role = Literal["PATIENT", "NURSE", "DOCTOR", "MANAGER", "ADMIN", "DEPT_HEAD", "DIRECTOR", "DEVELOPER", "TESTER"]
StaffRole = Literal["NURSE", "DOCTOR", "MANAGER", "ADMIN", "DEPT_HEAD", "DIRECTOR", "DEVELOPER", "TESTER"]
Id = Annotated[int, Field(ge=1, le=2**63 - 1)]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=50)]
NewLoginId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=50,
                                              pattern=r"^[A-Za-z0-9_.-]+$")]
# 처음 비밀번호: 10자 이상, bcrypt 한도(72바이트)는 서버에서 바이트로 다시 확인
NewPassword = Annotated[str, StringConstraints(min_length=10, max_length=72)]
MAX_PAGE_SIZE = 100


class AdminUserFilter(BaseModel):
    """GET /api/v1/admin/users: 직원 계정만 (환자 계정 제외)"""
    model_config = ConfigDict(extra="forbid")

    role: StaffRole | None = None
    department_id: Id | None = None
    is_active: bool | None = None
    q: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=50)] | None = None
    page: int = Field(1, ge=1, le=100_000)
    size: int = Field(20, ge=1, le=MAX_PAGE_SIZE)


class AdminUserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    login_id: NewLoginId
    name: Name
    role: Role
    department_id: Id | None = None
    patient_id: Id | None = None   # PATIENT 계정만
    password: NewPassword


class AdminUserUpdate(BaseModel):
    """PATCH: 역할·부서·활성만. 보낸 칸만 바꾼다 (department_id 를 null 로 보내면 부서를 비운다)."""
    model_config = ConfigDict(extra="forbid")

    role: Role | None = None
    department_id: Id | None = None
    is_active: bool | None = None


class AdminUserOut(BaseModel):
    """비밀번호 해시는 내보내지 않는다."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    login_id: str
    name: str
    role: str
    department_id: int | None
    patient_id: int | None
    is_active: bool
    locked_until: UtcDateTime | None
    last_login_at: UtcDateTime | None
    created_at: UtcDateTime
    updated_at: UtcDateTime


class AdminUserPage(BaseModel):
    items: list[AdminUserOut]
    page: int
    size: int
    total: int


class AdminUserUpdateOut(AdminUserOut):
    revoked_sessions: int   # 바뀌어서 끊은 세션 수


class AuditLogFilter(BaseModel):
    """GET /api/v1/admin/audit-logs: 날짜는 KST 날짜"""
    model_config = ConfigDict(extra="forbid")

    date_from: date | None = None
    date_to: date | None = None
    user_id: Id | None = None
    action: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=50)] | None = None
    result: Literal["SUCCESS", "DENIED", "FAIL"] | None = None
    service: Literal["auth", "reservation", "stats"] | None = None
    page: int = Field(1, ge=1, le=100_000)
    size: int = Field(50, ge=1, le=MAX_PAGE_SIZE)

    @model_validator(mode="after")
    def check_range(self):
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValueError("date_from 은 date_to 보다 늦을 수 없습니다")
        return self


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None
    service: str
    action: str
    target_type: str | None
    target_id: str | None
    request_id: str | None
    client_ip: str | None
    result: str
    created_at: UtcDateTime


class AuditLogPage(BaseModel):
    items: list[AuditLogOut]
    page: int
    size: int
    total: int
