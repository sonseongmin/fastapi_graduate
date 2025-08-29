from fastapi import FastAPI, Depends, HTTPException, Security, Request
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.openapi.utils import get_openapi

from fastapi import Path
import uuid
from fastapi import UploadFile, File
from app import models, schemas, database, auth
from app.auth import security, get_current_user

from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth_extra 

# FastAPI 앱 초기화
app = FastAPI()

import time
import os
import shutil
import httpx
import json
from fastapi import Form

def analyze_video(file_path: str, exercise: str) -> dict:
    """
    AI 서버에 POST 요청 보내서 분석 결과 가져오기
    """
    start_time = time.time()
    ai_url = "http://3.39.194.20:8001/analyze"  # AI 서버 주소

    files = {"file": open(file_path, "rb")}
    data = {"exercise": exercise}

    with httpx.Client() as client:
        response = client.post(ai_url, files=files, data=data)
        result = response.json()

    result["elapsed_time"] = round(time.time() - start_time, 2)
    return result

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 또는 ["http://localhost:3000", "http://127.0.0.1:8000"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 라우터 등록 (로그인 포함)
app.include_router(auth.router)
app.include_router(auth_extra.router)

# 업로드 라우터 등록
from app.routers import upload
app.include_router(upload.router, prefix="/api/v1/exercise")

# DB 테이블 생성
models.Base.metadata.create_all(bind=database.engine)

# 비밀번호 해싱
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# 회원가입 API
@app.post("/users", response_model=schemas.UserOut)
def create_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    existing_user = db.query(models.User).filter(
        (models.User.email == user.email) | (models.User.username == user.username)
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email or username already registered")

    hashed_password = hash_password(user.password)
    new_user = models.User(
        username=user.username,
        name=user.name,
        email=user.email,
        password_hash=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# /me API (토큰 확인용)
@app.get("/me", response_model=schemas.UserOut)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user

# 디버그용: 토큰 안에 뭐 들어있는지 보기
@app.get("/debug-token")
def debug_token(request: Request, current_user: models.User = Depends(get_current_user)):
    return {
        "token_verified": True,
        "user_id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "raw_authorization_header": request.headers.get("authorization")
    }

from fastapi.openapi.utils import get_openapi

# Swagger 보안 스키마 커스터마이징
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="BodyLog API",
        version="1.0.0",
        description="API with JWT authentication",
        routes=app.routes,
    )
    # 보안 스키마 정의
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    # 모든 경로에 기본 보안 스키마 할당 (전역적용)
    openapi_schema["security"] = [{"BearerAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi


# 운동 기록 저장
@app.post("/workouts", response_model=schemas.WorkoutOut)
def create_workout(
    workout: schemas.WorkoutCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user)
):
    new_workout = models.Workout(
        user_id=current_user.id,
        exercise_type=workout.exercise_type,
        started_at=workout.started_at,
        ended_at=workout.ended_at,
        rep_count=workout.rep_count,
        avg_accuracy=workout.avg_accuracy
    )
    db.add(new_workout)
    db.commit()
    db.refresh(new_workout)
    return new_workout


# 운동 기록 조회
@app.get("/workouts", response_model=list[schemas.WorkoutOut], dependencies=[Depends(get_current_user)])
def get_workouts(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user)
):
    return db.query(models.Workout).filter(models.Workout.user_id == current_user.id).all()

# 운동 결과 반환 API
@app.get("/workouts/{workout_id}/result")
def get_workout_result(
    workout_id: int = Path(..., description="Workout ID"),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 운동 가져오기
    workout = db.query(models.Workout).filter_by(id=workout_id, user_id=current_user.id).first()
    if not workout:
        raise HTTPException(status_code=404, detail="Workout not found")

    # 시간 계산
    duration_seconds = int((workout.ended_at - workout.started_at).total_seconds())

    # 피드백 조회
    feedbacks = db.query(models.Feedback).filter_by(workout_id=workout_id).all()
    feedback_list = [
        {"rep_number": f.rep_number, "text": f.feedback_text} for f in feedbacks
    ]

    return {
        "workout_id": workout.id,
        "exercise_type": workout.exercise_type.value,
        "duration_seconds": duration_seconds,
        "rep_count": workout.rep_count,
        "avg_accuracy": workout.avg_accuracy,
        "feedback": feedback_list
    }


# 분석 결과 저장용 임시 딕셔너리 (메모리 상 저장 → 실제로는 DB 또는 큐에 저장해야 함)
analysis_results = {}
# 운동 영상 업로드 및 분석 요청
@app.post("/api/v1/exercise/upload")
async def upload_exercise_video(
    file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user)
):
    # 실제 파일 저장/분석 로직은 생략
    result_id = str(uuid.uuid4())  # 고유 ID 생성
    analysis_results[result_id] = {"status": "processing", "result": None}

    # 예: AI 분석 비동기 요청 → 완료 시 상태를 바꾸는 로직 필요
    return {"result_id": result_id}



from app.schemas import AnalyzeResponse
# AI로부터 운동 분석 결과 받기
@app.post("/api/v1/exercise/analyze", response_model=AnalyzeResponse)
async def analyze_exercise(
    file: UploadFile = File(...),
    exercise: str = Form(...),
    current_user: models.User = Depends(get_current_user)
):
    # 1. 파일 저장
    UPLOAD_DIR = "media"
    category_dir = os.path.join(UPLOAD_DIR, category)
    os.makedirs(category_dir, exist_ok=True)

    unique_filename = f"{uuid.uuid4()}_{file.filename}"
    file_path = os.path.join(category_dir, unique_filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 2. AI 분석
    result = analyze_video(file_path, exercise)

    # 3. 결과 반환
    return result


# 운동 분석 결과 조회
@app.get("/api/v1/exercise/result/{result_id}")
def get_analysis_result(
    result_id: str,
    current_user: models.User = Depends(get_current_user)
):
    if result_id not in analysis_results:
        raise HTTPException(status_code=404, detail="Result not found")

    return {
        "result_id": result_id,
        "status": analysis_results[result_id]["status"],
        "result": analysis_results[result_id]["result"]
    }


# 인바디 데이터 등록

@app.post("/api/v1/inbody", response_model=schemas.InbodyOut)
def create_inbody(
    inbody: schemas.InbodyCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user)
):
    new_data = models.Inbody(
        user_id=current_user.id,
        weight=inbody.weight,
        muscle_mass=inbody.muscle_mass,
        body_fat=inbody.body_fat,
        height=inbody.height,
        sex=inbody.sex,
        birth_date=inbody.birth_date,
        recorded_at=inbody.recorded_at
    )
    db.add(new_data)
    db.commit()
    db.refresh(new_data)
    return new_data



# 최신 인바디 데이터 조회

@app.get("/api/v1/inbody", response_model=schemas.InbodyOut)
def get_latest_inbody(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user)
):
    latest = db.query(models.Inbody)\
        .filter(models.Inbody.user_id == current_user.id)\
        .order_by(models.Inbody.recorded_at.desc())\
        .first()

    if not latest:
        raise HTTPException(status_code=404, detail="No inbody data found")

    return latest

# 운동 추천 받기

@app.get("/api/v1/recommendation")
def get_recommendation(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 간단한 예시 추천: 최근 인바디 기반
    latest = db.query(models.Inbody)\
        .filter(models.Inbody.user_id == current_user.id)\
        .order_by(models.Inbody.recorded_at.desc())\
        .first()

    if not latest:
        return {"recommendation": "최근 인바디 정보가 없습니다. 먼저 인바디를 등록해주세요."}

    # 간단한 조건 예시
    if latest.body_fat > 25:
        return {"recommendation": "유산소 위주의 운동을 추천합니다. (예: 러닝 30분)"}
    else:
        return {"recommendation": "근육 강화 운동을 추천합니다. (예: 스쿼트 3세트)"}
