from pydantic import BaseModel, EmailStr
from datetime import datetime, date
from enum import Enum
from typing import List, Optional, Union, Any


# 회원가입 시 사용되는 요청 데이터 모델
class UserCreate(BaseModel):
    username: str
    name: str
    email: EmailStr
    password: str


# 사용자 정보를 조회할 때 사용하는 모델
class UserOut(BaseModel):
    id: int
    username: str
    name: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


# 운동 종류 Enum (운동 기록 등에서 사용)
class ExerciseType(str, Enum):
    squat = "squat"
    pushup = "pushup"
    pullup = "pullup"
    jumping_jack = "jumping_jack"


# 운동 기록 등록 시 사용하는 요청 데이터 모델
class WorkoutCreate(BaseModel):
    exercise_type: ExerciseType
    rep_count: int
    avg_accuracy: Optional[float] = None   # ← float/None 로 완화 (분석 결과와 맞춤)
    started_at: Optional[datetime] = None    # ✅ 추가
    ended_at: Optional[datetime] = None      # ✅ 추가

# 운동 기록을 조회할 때 사용하는 모델
class WorkoutOut(WorkoutCreate):
    id: int

    class Config:
        from_attributes = True


# 로그인 요청 시 사용하는 모델
class LoginRequest(BaseModel):
    username: str
    password: str


# 로그인 성공 시 반환되는 토큰 응답 모델
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    name: str
    username: str
    email: str


# 인바디 데이터 등록 시 사용하는 요청 데이터 모델
class InbodyCreate(BaseModel):
    weight: float
    muscle_mass: float
    body_fat: float
    height: float
    sex: str
    birth_date: date
    recorded_at: datetime


# 인바디 데이터를 조회할 때 사용하는 모델
class InbodyOut(InbodyCreate):
    id: int

    class Config:
        from_attributes = True


# 아이디 비밀번호 찾기
class PasswordResetRequest(BaseModel):
    username: str
    name: str
    email: EmailStr


# 비밀번호 재설정 기능
class UpdatePasswordRequest(BaseModel):
    username: str
    new_password: str

# ----- 분석 응답 모델 (동기 /analyze 응답) -----
class AnalyzeResponse(BaseModel):
    # AI 분석 결과 필드 (AI 쪽에서 문자열로 줄 가능 있으니 exercise_type은 str로 수용)
    exercise_type: str
    rep_count: int
    avg_accuracy: Optional[float] = None
    calories: Optional[int] = None


    # 백엔드에서 DB 저장 후 반환
    workout_id: int

class AnalyzeJobResponse(BaseModel):
    job_id: str
    status: str
