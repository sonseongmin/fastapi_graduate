from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app import models, schemas
from passlib.context import CryptContext

router = APIRouter(prefix="/auth", tags=["Auth Extras"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 1. ID 중복 확인 (아이디 중복 체크)
@router.get("/check-username")
def check_username(username: str, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.username == username).first()
    return {"available": existing_user is None}

# 2. 비밀번호 재설정 (비밀번호 찾기 - 간단 버전)
@router.post("/reset-password")
def reset_password(request: schemas.PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password_hash = pwd_context.hash(request.new_password)
    db.commit()
    return {"message": "Password updated successfully"}

# 3. 아이디 찾기 (이메일로 사용자명 조회)
@router.get("/find-username")
def find_username(email: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="No user with that email")
    return {"username": user.username}
