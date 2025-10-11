from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app import models, schemas
from passlib.context import CryptContext
import random, string 
router = APIRouter(prefix="/auth", tags=["Auth Extras"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 1. ID 중복 확인 (아이디 중복 체크)
@router.get("/check-username")
def check_username(username: str, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.username == username).first()
    return {"available": existing_user is None}

# 2. 비밀번호 재설정 (비밀번호 찾기 - 간단 버전)
def generate_temp_password(length: int = 8) -> str:
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

@router.post("/reset-password")
def reset_password(
    request: schemas.PasswordResetRequest,
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.username == request.username).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.name != request.name:
        raise HTTPException(status_code=403, detail="Name does not match")

    if user.email != request.email:
        raise HTTPException(status_code=403, detail="Email does not match")

    temp_password = generate_temp_password()
    user.password_hash = pwd_context.hash(temp_password)
    db.commit()

    return {"new_password": temp_password}

# 3. 아이디 찾기 (이메일로 사용자명 조회)
@router.get("/find-username")
def find_username(email: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="No user with that email")
    return {"username": user.username}

# 4. 본인인증
@router.post("/verify-identity")
def verify_identity(request: schemas.PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == request.username).first()

    if not user or user.name != request.name or user.email != request.email:
        raise HTTPException(status_code=403, detail="Invalid credentials")

    return {"message": "Verified"}
# 비밀번호 재설정
@router.post("/update-password")
def update_password(request: schemas.UpdatePasswordRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == request.username).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password_hash = pwd_context.hash(request.new_password)
    db.commit()

    return {"message": "Password updated successfully"}
