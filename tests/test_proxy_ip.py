"""인그레스 뒤의 실제 클라이언트 IP (uvicorn --proxy-headers --forwarded-allow-ips).

uvicorn 이 --proxy-headers 일 때 앱 앞에 붙이는 ProxyHeadersMiddleware 를 그대로 써서,
'보낸 쪽 주소'(TestClient client)와 X-Forwarded-For 를 바꿔 가며 감사 로그 client_ip 와 로그인 IP 제한을 확인한다.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from conftest import TEST_PASSWORD
from shared.models import AuditLog

LOGIN = "/api/v1/auth/login"
INGRESS = "10.42.0.15"        # 믿는 프록시 (인그레스 컨트롤러 Pod)
TRUSTED = "10.42.0.0/24"      # FORWARDED_ALLOW_IPS 예
OUTSIDER = "192.0.2.50"       # 믿지 않는 곳 (NodePort 로 바로 온 요청 등)
REAL = "203.0.113.7"          # 실제 클라이언트


@pytest.fixture()
def via(client):
    """via(보낸 쪽 IP, 믿는 프록시 목록) → 그 주소에서 온 것처럼 요청하는 TestClient"""
    from app.main import app

    clients = []

    def make(source_ip: str, forwarded_allow_ips: str = TRUSTED) -> TestClient:
        c = TestClient(ProxyHeadersMiddleware(app, trusted_hosts=forwarded_allow_ips), client=(source_ip, 40000))
        clients.append(c)
        return c

    yield make
    for c in clients:
        c.close()


def fail_login(c, xff=None, login_id="nurse_im01"):
    headers = {"X-Forwarded-For": xff} if xff else {}
    return c.post(LOGIN, json={"login_id": login_id, "password": "wrong"}, headers=headers)


def last_audit_ip(db_session, action="LOGIN"):
    db_session.expire_all()
    row = db_session.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id.desc())).first()
    return row.client_ip


def test_trusted_proxy_uses_forwarded_client_ip(via, db_session):
    c = via(INGRESS)
    assert fail_login(c, REAL).status_code == 401
    assert last_audit_ip(db_session) == REAL
    r = c.post(LOGIN, json={"login_id": "dev01", "password": TEST_PASSWORD}, headers={"X-Forwarded-For": REAL})
    assert r.status_code == 200 and last_audit_ip(db_session) == REAL  # 성공 로그도


def test_spoofed_left_entries_are_ignored(via, db_session):
    """클라이언트가 X-Forwarded-For 를 미리 채워 보내도, 믿는 프록시 바로 앞의 주소만 쓴다."""
    c = via(INGRESS)
    fail_login(c, f"198.51.100.66, {REAL}")
    assert last_audit_ip(db_session) == REAL


def test_untrusted_source_header_is_ignored(via, db_session):
    fail_login(via(OUTSIDER), REAL)
    assert last_audit_ip(db_session) == OUTSIDER


def test_default_setting_trusts_no_proxy(via, db_session):
    """기본값 127.0.0.1: 인그레스 주소에서 와도 X-Forwarded-For 를 믿지 않는다."""
    fail_login(via(INGRESS, forwarded_allow_ips="127.0.0.1"), REAL)
    assert last_audit_ip(db_session) == INGRESS


def test_rate_limit_counts_real_client_ip(via):
    c = via(INGRESS)
    for _ in range(20):
        assert fail_login(c, REAL, login_id="nobody").status_code == 401
    assert fail_login(c, REAL, login_id="nobody").status_code == 429
    # 같은 인그레스를 지나도 다른 사용자(IP)는 막히지 않는다
    assert fail_login(c, "203.0.113.8", login_id="nobody").status_code == 401


def test_untrusted_source_cannot_dodge_rate_limit_by_rotating_header(via):
    c = via(OUTSIDER)
    for i in range(20):
        assert fail_login(c, f"198.51.100.{i}", login_id="nobody").status_code == 401
    assert fail_login(c, "198.51.100.99", login_id="nobody").status_code == 429
