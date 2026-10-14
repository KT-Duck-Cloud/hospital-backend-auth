"""관리 API A3~A6 테스트: 계정 목록·만들기·변경(세션 끊기)·감사 로그 조회"""
from datetime import timedelta

import pytest
from sqlalchemy import select, text

from conftest import TEST_PASSWORD
from shared.models import AuditLog, User, utcnow

USERS = "/api/v1/admin/users"
AUDIT = "/api/v1/admin/audit-logs"
ME = "/api/v1/auth/me"
NEW_PASSWORD = "Fresh-Pass-" + TEST_PASSWORD[:6]


@pytest.fixture()
def admin_client(client):
    """departments·patients 는 예약 서비스 표라 인증 테스트 DB 에는 없다. 존재 확인용으로만 만든다."""
    from shared.db import engine

    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE departments (id INTEGER PRIMARY KEY, code TEXT, name TEXT)"))
        conn.execute(text("INSERT INTO departments (id, code, name) VALUES "
                          "(1, 'IM', '내과'), (2, 'OS', '정형외과'), (3, 'PD', '소아과'), (4, 'ADM', '원무과')"))
        conn.execute(text("CREATE TABLE patients (id INTEGER PRIMARY KEY)"))
        conn.execute(text("INSERT INTO patients (id) VALUES (1), (2)"))
    yield client
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE departments"))
        conn.execute(text("DROP TABLE patients"))


def login(client, login_id, password=TEST_PASSWORD):
    return client.post("/api/v1/auth/login", json={"login_id": login_id, "password": password})


def h(client, login_id):
    r = login(client, login_id)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def user_id(db_session, login_id):
    db_session.expire_all()
    return db_session.scalar(select(User.id).where(User.login_id == login_id))


def audit_rows(db_session, action=None):
    db_session.expire_all()
    rows = db_session.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    return [a for a in rows if action is None or a.action == action]


# ---------- A3 ----------

def test_list_users_roles_and_filters(admin_client):
    c = admin_client
    for login_id in ("admin01", "director01", "tester01"):
        r = c.get(USERS, headers=h(c, login_id))
        assert r.status_code == 200
    for login_id in ("patient01", "nurse_im01", "doctor_im01", "office01", "head_im01", "dev01"):
        assert c.get(USERS, headers=h(c, login_id)).status_code == 403

    headers = h(c, "admin01")
    page = c.get(USERS, headers=headers).json()
    assert "patient01" not in [u["login_id"] for u in page["items"]]  # 직원만
    assert page["total"] == 8 and "password_hash" not in page["items"][0]
    assert [u["login_id"] for u in c.get(USERS, params={"role": "NURSE"}, headers=headers).json()["items"]] == [
        "nurse_im01"]
    assert c.get(USERS, params={"department_id": 1}, headers=headers).json()["total"] == 3  # 간호사·의사·부서장
    assert [u["login_id"] for u in c.get(USERS, params={"q": "dev"}, headers=headers).json()["items"]] == ["dev01"]
    assert c.get(USERS, params={"role": "PATIENT"}, headers=headers).status_code == 422
    assert c.get(USERS, params={"is_active": "false"}, headers=headers).json()["total"] == 0


# ---------- A4 ----------

def new_user(c, headers, **overrides):
    data = {"login_id": "nurse_pd01", "name": "소아과간호사", "role": "NURSE", "department_id": 3,
            "password": NEW_PASSWORD}
    data.update(overrides)
    return c.post(USERS, json=data, headers=headers)


def test_create_user_and_login(admin_client, db_session):
    c = admin_client
    r = new_user(c, h(c, "admin01"))
    assert r.status_code == 201
    body = r.json()
    assert body["role"] == "NURSE" and body["department_id"] == 3 and body["is_active"] is True
    assert "password" not in r.text and "password_hash" not in body
    assert login(c, "nurse_pd01", NEW_PASSWORD).status_code == 200  # 만든 계정으로 로그인
    stored = db_session.scalar(select(User.password_hash).where(User.login_id == "nurse_pd01"))
    assert stored.startswith("$2") and NEW_PASSWORD not in stored
    assert audit_rows(db_session, "USER_CREATE")[-1].target_id == str(body["id"])

    assert new_user(c, h(c, "admin01")).status_code == 409  # 같은 아이디


@pytest.mark.parametrize("overrides", [
    {"role": "NURSE", "department_id": None},                    # 부서 필수 역할
    {"role": "PATIENT", "department_id": None},                  # PATIENT 는 patient_id 필수
    {"role": "PATIENT", "patient_id": 2},                        # PATIENT 는 부서 없음
    {"role": "DEVELOPER", "department_id": None, "patient_id": 2},  # 직원에 환자 연결 금지
    {"department_id": 99},                                       # 없는 부서
    {"role": "PATIENT", "department_id": None, "patient_id": 99},  # 없는 환자
])
def test_create_user_shape_rules_400(admin_client, overrides):
    c = admin_client
    r = new_user(c, h(c, "director01"), **overrides)
    assert r.status_code == 400 and r.json()["code"] == "BAD_REQUEST"


def test_create_user_input_and_escalation(admin_client, db_session):
    c = admin_client
    admin = h(c, "admin01")
    assert new_user(c, admin, password="short").status_code == 422
    assert new_user(c, admin, login_id="has space").status_code == 422
    assert new_user(c, admin, is_active=False).status_code == 422          # 정해진 칸만
    assert new_user(c, admin, password_hash="$2b$...").status_code == 422
    # 이미 계정이 있는 환자(patient01 → 1)에 또 연결하면 409
    r = new_user(c, admin, login_id="patient_dup", role="PATIENT", department_id=None, patient_id=1)
    assert r.status_code == 409
    # ADMIN 은 DIRECTOR 를 만들 수 없다 (권한 올리기 방지), DIRECTOR 는 된다
    r = new_user(c, admin, login_id="boss2", role="DIRECTOR", department_id=None)
    assert r.status_code == 403
    assert audit_rows(db_session, "ACCESS_DENIED")[-1].target_id == "boss2"
    assert new_user(c, h(c, "director01"), login_id="boss2", role="DIRECTOR", department_id=None).status_code == 201
    # TESTER 는 목록만 (만들기 403)
    assert new_user(c, h(c, "tester01"), login_id="t2").status_code == 403


# ---------- A5 ----------

def test_role_change_revokes_sessions(admin_client, db_session):
    c = admin_client
    nurse = h(c, "nurse_im01")
    nurse2 = h(c, "nurse_im01")
    nid = user_id(db_session, "nurse_im01")
    r = c.patch(f"{USERS}/{nid}", json={"role": "DEPT_HEAD"}, headers=h(c, "admin01"))
    assert r.status_code == 200
    assert r.json()["role"] == "DEPT_HEAD" and r.json()["revoked_sessions"] == 2
    assert c.get(ME, headers=nurse).status_code == 401 and c.get(ME, headers=nurse2).status_code == 401
    assert c.get(ME, headers=h(c, "nurse_im01")).json()["role"] == "DEPT_HEAD"  # 다시 로그인하면 새 역할
    assert audit_rows(db_session, "USER_UPDATE")[-1].target_id == str(nid)


def test_department_and_active_changes_revoke(admin_client, db_session):
    c = admin_client
    admin = h(c, "admin01")
    nid = user_id(db_session, "office01")
    token = h(c, "office01")
    r = c.patch(f"{USERS}/{nid}", json={"department_id": 3}, headers=admin)
    assert r.status_code == 200 and r.json()["department_id"] == 3 and r.json()["revoked_sessions"] == 1
    assert c.get(ME, headers=token).status_code == 401

    token = h(c, "office01")
    r = c.patch(f"{USERS}/{nid}", json={"is_active": False}, headers=admin)
    assert r.status_code == 200 and r.json()["is_active"] is False
    assert c.get(ME, headers=token).status_code == 401
    assert login(c, "office01").status_code == 401  # 비활성은 로그인 불가


def test_no_change_keeps_sessions(admin_client, db_session):
    c = admin_client
    token = h(c, "dev01")
    did = user_id(db_session, "dev01")
    r = c.patch(f"{USERS}/{did}", json={"role": "DEVELOPER"}, headers=h(c, "admin01"))
    assert r.status_code == 200 and r.json()["revoked_sessions"] == 0
    assert c.get(ME, headers=token).status_code == 200


def test_update_rules(admin_client, db_session):
    c = admin_client
    admin = h(c, "admin01")
    admin_id = user_id(db_session, "admin01")
    director_id = user_id(db_session, "director01")
    dev_id = user_id(db_session, "dev01")
    nurse_id = user_id(db_session, "nurse_im01")

    assert c.patch(f"{USERS}/{admin_id}", json={"is_active": False}, headers=admin).status_code == 400  # 자기 계정
    assert c.patch(f"{USERS}/{director_id}", json={"is_active": False}, headers=admin).status_code == 403
    assert c.patch(f"{USERS}/{dev_id}", json={"role": "DIRECTOR"}, headers=admin).status_code == 403
    assert c.patch(f"{USERS}/{dev_id}", json={}, headers=admin).status_code == 400
    assert c.patch(f"{USERS}/{dev_id}", json={"role": None}, headers=admin).status_code == 400
    assert c.patch(f"{USERS}/{dev_id}", json={"password": "x" * 12}, headers=admin).status_code == 422
    assert c.patch(f"{USERS}/{nurse_id}", json={"department_id": None}, headers=admin).status_code == 400
    assert c.patch(f"{USERS}/{nurse_id}", json={"role": "PATIENT"}, headers=admin).status_code == 400
    assert c.patch(f"{USERS}/99999", json={"is_active": False}, headers=admin).status_code == 404
    assert c.patch(f"{USERS}/{dev_id}", json={"is_active": False}, headers=h(c, "tester01")).status_code == 403
    # DIRECTOR 는 DIRECTOR 역할을 줄 수 있다
    r = c.patch(f"{USERS}/{dev_id}", json={"role": "DIRECTOR"}, headers=h(c, "director01"))
    assert r.status_code == 200 and r.json()["role"] == "DIRECTOR"


# ---------- A6 ----------

def test_audit_logs_view_and_filters(admin_client, db_session):
    c = admin_client
    login(c, "nurse_im01", "wrong")  # LOGIN FAIL
    admin = h(c, "admin01")
    for login_id in ("tester01", "nurse_im01", "dev01", "head_im01"):
        assert c.get(AUDIT, headers=h(c, login_id)).status_code == 403
    assert c.get(AUDIT, headers=h(c, "director01")).status_code == 200

    page = c.get(AUDIT, headers=admin).json()
    ids = [i["id"] for i in page["items"]]
    assert ids == sorted(ids, reverse=True) and page["total"] >= 3  # 최신순
    fails = c.get(AUDIT, params={"action": "LOGIN", "result": "FAIL"}, headers=admin).json()
    assert fails["total"] == 1 and fails["items"][0]["user_id"] == user_id(db_session, "nurse_im01")
    nid = user_id(db_session, "nurse_im01")
    assert all(i["user_id"] == nid for i in c.get(AUDIT, params={"user_id": nid}, headers=admin).json()["items"])
    assert c.get(AUDIT, params={"service": "reservation"}, headers=admin).json()["total"] == 0
    today = (utcnow() + timedelta(hours=9)).date()
    assert c.get(AUDIT, params={"date_from": str(today), "date_to": str(today)}, headers=admin).json()["total"] >= 3
    tomorrow = today + timedelta(days=1)
    assert c.get(AUDIT, params={"date_from": str(tomorrow)}, headers=admin).json()["total"] == 0
    assert c.get(AUDIT, params={"date_from": str(tomorrow), "date_to": str(today)}, headers=admin).status_code == 422
    assert any(a.action == "AUDIT_LOG_VIEW" for a in audit_rows(db_session))


def test_audit_logs_cannot_be_changed(admin_client):
    c = admin_client
    admin = h(c, "admin01")
    for method in ("post", "put", "patch", "delete"):
        assert getattr(c, method)(AUDIT, headers=admin).status_code == 405
        assert getattr(c, method)(f"{AUDIT}/1", headers=admin).status_code == 404
