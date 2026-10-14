"""인증 서비스 로그: 모든 줄이 JSON, request_id 로 요청을 찾을 수 있고 비밀번호·토큰이 없다."""
import json

from conftest import TEST_PASSWORD

LOGIN = "/api/v1/auth/login"


def test_login_logs_are_json_and_have_no_password_or_token(client, capsys):
    capsys.readouterr()
    r = client.post(LOGIN, json={"login_id": "admin01", "password": TEST_PASSWORD},
                    headers={"X-Request-ID": "auth-log-1"})
    assert r.status_code == 200
    token = r.json()["access_token"]
    client.post(LOGIN, json={"login_id": "admin01", "password": "wrong-" + TEST_PASSWORD},
                headers={"X-Request-ID": "auth-log-2"})
    client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}", "X-Request-ID": "auth-log-3"})

    out = capsys.readouterr().out
    lines = [json.loads(ln) for ln in out.splitlines() if ln.strip()]  # 모든 줄이 JSON
    by_id = {ln["request_id"]: ln for ln in lines if ln["logger"] == "access"}
    assert by_id["auth-log-1"]["status"] == 200 and by_id["auth-log-1"]["service"] == "auth"
    assert by_id["auth-log-2"]["status"] == 401
    assert by_id["auth-log-3"]["path"] == "/api/v1/auth/me"
    for secret in (TEST_PASSWORD, token, token.split(".")[2]):
        assert secret not in out


def test_redact_masks_tokens_and_db_urls():
    from shared.logs import redact

    jwt_like = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
    text = redact(f"Bearer {jwt_like} mysql+pymysql://app_runtime:pw123@db:3306/hospital password=hunter2")
    for secret in (jwt_like, "pw123", "hunter2", "app_runtime"):
        assert secret not in text
    assert text.count("[REDACTED]") >= 3
