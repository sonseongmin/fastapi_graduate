# app/auth.py뀨

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from app import models, schemas, database

SECRET_KEY = "your-secret-key"  # TODO: 환경변수로 교체 권장
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

router = APIRouter(prefix="/api", tags=["Auth"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ✅ HTTPBearer로 변경 (Swagger 연동 잘됨)
security = HTTPBearer()

# 비밀번호 검증 함수
def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

# ✅ JWT 토큰 생성 함수
def create_access_token(data: dict, expires_delta: timedelta = None):
    # 한국 시간 기준으로 만료 시간 설정
    now_kst = datetime.utcnow() + timedelta(hours=9)
    expire = now_kst + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ✅ 로그인 엔드포인트
@router.post("/login", response_model=schemas.TokenResponse)
def login(login_req: schemas.LoginRequest, db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.username == login_req.username).first()
    if not user or not verify_password(login_req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user.username})
    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "bearer",
            "name": user.name,
            "username": user.username,
            "email": user.email,
        },
        media_type="application/json; charset=utf-8"  # <- 이게 핵심
    )
# ✅ 현재 유저 반환 (보호된 라우트에서 사용)
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(database.get_db)
):
    token = credentials.credentials  # Bearer <token> 중 토큰만 추출
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception

    return user