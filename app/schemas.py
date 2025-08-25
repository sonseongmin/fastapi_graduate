from pydantic import BaseModel, EmailStr
from datetime import datetime, date
from enum import Enum


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
    lunge = "lunge"
    pushup = "pushup"
    plank = "plank"
    situp = "situp"
    pullup = "pullup"
    jumping_jack = "jumping_jack"


# 운동 기록 등록 시 사용하는 요청 데이터 모델
class WorkoutCreate(BaseModel):
    exercise_type: ExerciseType
    started_at: datetime
    ended_at: datetime
    rep_count: int
    avg_accuracy: int


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
    new_password: str


# AI 서버에서 분석결과 받아오기
class AnalyzeResponse(BaseModel):
    exercise_name: str
    count_total: int
    count_incorrect: int
    feedback: str
    elapsed_time: float

    class Config:
        from_attributes = True