"""/metrics (Prometheus 형식): 인증 없이 열려 있고, 토큰·비밀번호·DB 주소가 지표에 들어가지 않는다."""
import os

from conftest import TEST_PASSWORD


def test_metrics_is_prometheus_text_without_secrets(client):
    r = client.post("/api/v1/auth/login", json={"login_id": "nobody", "password": TEST_PASSWORD})
    client.get("/healthz")
    m = client.get("/metrics")
    assert m.status_code == 200
    assert "text/plain" in m.headers["content-type"]
    assert "http_requests_total" in m.text
    for hidden in (TEST_PASSWORD, os.environ["JWT_SECRET"], os.environ["DB_URL"], "nobody", "Bearer"):
        assert hidden not in m.text
    assert r.status_code in (400, 401, 422)
