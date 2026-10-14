# hospital-backend-auth

병원 예약 시스템의 인증 서비스 (로그인, 세션, 관리자 계정 관리). FastAPI 서비스이며 `shared/` 는 세 백엔드 저장소(auth · reservation · stats)에 같은 내용으로 들어 있다.

## 구조

```
app/            서비스 코드 (uvicorn app.main:app)
shared/         공통 코드 (DB, 인증, 로그, 설정 등)
tests/          pytest (임시 SQLite DB 로 돈다)
Dockerfile      이 폴더 하나로 빌드한다
```

## 테스트

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest tests
```

## 이미지 빌드 · 실행

```powershell
docker build --build-arg APP_VERSION=$(git rev-parse --short HEAD) -t hospital-backend-auth:dev .
docker run --rm -p 8001:8000 -e DATABASE_URL=... -e JWT_SECRET=... hospital-backend-auth:dev
```

DB 와 다른 서비스를 함께 띄우는 로컬 개발 환경은 `hospital-gitops` 의 `docker-compose.yml` 을 쓴다.

## 샘플 계정 넣기

```powershell
.venv\Scripts\python scripts\seed_users.py
```

샘플 계정 비밀번호는 환경변수 `SEED_PASSWORD` 로만 받는다. DB 접속 정보는 `DATABASE_URL`, 없으면 이 폴더 `.env` 의 `APP_RUNTIME_PASSWORD` 와 `DB_HOST`(기본 127.0.0.1) · `DB_PORT`(기본 3306) 를 쓴다.

## 환경변수

값(비밀번호·키)은 코드나 이미지에 넣지 않고 실행할 때 주입한다.

| 이름 | 필수 | 설명 |
|---|---|---|
| `DATABASE_URL` | 필수 | `mysql+pymysql://사용자:비밀번호@호스트:3306/hospital?charset=utf8mb4` |
| `JWT_SECRET` | 필수 | JWT 서명 키 (세 서비스 같은 값, 32바이트 이상) |
| `JWT_ISSUER` | | 토큰 발급자 (기본 `hospital-reservation`) |
| `DB_SSL_CA` | | DB TLS CA 인증서 경로 (없으면 암호화만, 검증 안 함) |
| `DB_POOL_SIZE` · `DB_MAX_OVERFLOW` · `DB_POOL_TIMEOUT` · `DB_POOL_RECYCLE` | | DB 연결 풀 (기본 5 · 5 · 5초 · 1800초) |
| `READ_ONLY_MODE` | | `true` 면 쓰기 요청을 503 으로 막음 |
| `SITE_NAME` | | 사이트 이름 (hospital / krdr / aws) |
| `APP_VERSION` | | 버전 표시 (이미지 빌드 때 `--build-arg APP_VERSION`) |
| `FORWARDED_ALLOW_IPS` | | 믿을 프록시 IP (기본 `127.0.0.1`) |
| `LOGIN_RATE_LIMIT_PER_MINUTE` | | 로그인 시도 제한 (IP 당 분당 횟수) |
| `BCRYPT_ROUNDS` | | bcrypt 비용 (기본 12, 테스트에서만 낮춤) |

## 코드 원본

이 저장소의 코드는 `reservation-app` 에서 `scripts/sync_to_repos.ps1` 로 복사한다.
README.md · .gitignore · .gitattributes · .github/ 는 이 저장소에서 직접 관리한다 (복사 대상 아님).
