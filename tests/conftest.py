"""테스트용 설정: 저장소 루트를 import 경로에 넣고, 임시 SQLite DB 와 테스트용 키를 쓴다.

비밀번호·서명 키는 실행할 때마다 무작위로 만든다 (파일에 고정값을 두지 않는다).
"""
import os
import secrets
import sys
import tempfile
from pathlib import Path

# 서비스 폴더 = tests/ 의 부모 (app/ 이 있는 곳). 저장소 루트 = shared/ 가 있는 가장 가까운 폴더.
# reservation-app(services/<이름>/tests) 과 서비스별 저장소(tests/) 두 구조에서 모두 동작한다.
SERVICE_DIR = Path(__file__).resolve().parents[1]
ROOT = next(p for p in [SERVICE_DIR, *SERVICE_DIR.parents] if (p / "shared").is_dir())
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SERVICE_DIR))

_db = Path(tempfile.mkdtemp()) / "auth-test.db"
os.environ["DB_URL"] = f"sqlite:///{_db}"
for _name in ("DB_USERNAME", "DB_PASSWORD"):  # SQLite 는 계정을 쓰지 않는다 (밖의 값이 섞이지 않게)
    os.environ.pop(_name, None)
os.environ["JWT_SECRET"] = secrets.token_urlsafe(48)
os.environ["BCRYPT_ROUNDS"] = "4"  # 테스트 속도용 (운영 12)
os.environ.pop("READ_ONLY_MODE", None)

import bcrypt  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

TEST_PASSWORD = secrets.token_urlsafe(16)

# (login_id, role, department_id, patient_id)
ACCOUNTS = [
    ("patient01", "PATIENT", None, 1),
    ("nurse_im01", "NURSE", 1, None),
    ("doctor_im01", "DOCTOR", 1, None),
    ("office01", "MANAGER", 4, None),
    ("admin01", "ADMIN", None, None),
    ("head_im01", "DEPT_HEAD", 1, None),
    ("director01", "DIRECTOR", None, None),
    ("dev01", "DEVELOPER", None, None),
    ("tester01", "TESTER", None, None),
]


@pytest.fixture()
def db_session():
    from shared.db import SessionLocal

    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def client():
    from shared import models
    from shared.db import Base, SessionLocal, engine
    from app.main import app, login_limiter

    # 앱은 표를 만들지 않는다. 테스트에서만 모델로 임시 DB 에 만든다.
    Base.metadata.create_all(engine)
    password_hash = bcrypt.hashpw(TEST_PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()
    with SessionLocal() as s:
        for login_id, role, dept, patient in ACCOUNTS:
            s.add(models.User(login_id=login_id, password_hash=password_hash, name=f"테스트 {login_id}",
                              role=role, department_id=dept, patient_id=patient))
        s.commit()
    login_limiter.reset()
    with TestClient(app) as c:
        yield c
    Base.metadata.drop_all(engine)
