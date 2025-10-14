import asyncio
import uuid
import io
import httpx
from fastapi import (
    FastAPI, Depends, HTTPException, File, UploadFile, Request, APIRouter, Path, status
)
from app.routers import workout_routes
from sqlalchemy.orm import Session
from datetime import datetime
from app import models, schemas, database, auth
from passlib.context import CryptContext
from app.auth import get_current_user
from app.schemas import AnalyzeResponse
from app.routers import auth_extra
from fastapi.responses import JSONResponse

# FastAPI 앱 초기화
app = FastAPI()
router = APIRouter()

import time
import os ,io
import shutil
import httpx
import json
from fastapi import Form
import logging
logger = logging.getLogger("uvicorn.error")
JOB_STATUS= {}
app.include_router(workout_routes.router)
def analyze_video(file_path: str, category: str) -> dict:
    """
    AI 서버에 POST 요청 보내서 분석 결과 가져오기
    """
    start_time = time.time()
    ai_url = "http://bodylog-ai:8001/analyze"  # AI 서버 주소

    files = {"file": open(file_path, "rb")}
    data = {"exercise": category}

    with httpx.Client(timeout=600.0) as client:
        response = client.post(ai_url, files=files, data=data)
        response.raise_for_status()
        result = response.json()

    result["elapsed_time"] = round(time.time() - start_time, 2)
    return result

# NEW ─ 디스크에 저장하지 않고, 메모리 바이트로 AI 서버에 분석 요청
def analyze_video_bytes(file_bytes: bytes, filename: str, content_type: str | None = None) -> dict:
    start_time = time.time()
    ai_url = "http://bodylog-ai:8001/analyze"

    files = {"file": (filename, file_bytes, content_type or "application/octet-stream")}

    timeout_config = httpx.Timeout(
    connect=600.0,  # 연결 수립
    read=600.0,    # 응답 읽기
    write=600.0,   # 파일 전송
    pool=600.0      # 커넥션 풀 대기
    )

    with httpx.Client(timeout=timeout_config) as client:
        print("[DEBUG] AI 요청 시작", flush=True)
        resp = client.post(ai_url, files=files)
        print(f"[DEBUG] AI 응답 수신: {resp.status_code}", flush=True)
        resp.raise_for_status()
        return resp.json()

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://13.125.219.3"],  # 또는 ["http://localhost:3000", "http://127.0.0.1:8000"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# --- 상태 조회 API
@router.get("/api/v1/exercise/status/{job_id}")
async def get_job_status(job_id: str):
    job = JOB_STATUS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Invalid job_id")
    return job

# 라우터 등록 (로그인 포함)
app.include_router(auth.router)
app.include_router(auth_extra.router)

# 업로드 라우터 등록
#from app.routers import upload
#app.include_router(upload.router, prefix="/api/v1/exercise")

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
@app.get("/api/me", response_model=schemas.UserOut)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user

# 디버그용: 토큰 안에 뭐 들어있는지 보기
@app.get("/api/debug-token")
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
@app.post("/api/v1/workouts", response_model=schemas.WorkoutOut)
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
@app.get("/api/v1/workouts", response_model=list[schemas.WorkoutOut], dependencies=[Depends(get_current_user)])
def get_workouts(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user)
):
    return db.query(models.Workout).filter(models.Workout.user_id == current_user.id).all()

# 운동 결과 반환 API
@app.get("/api/v1/workouts/{workout_id}/result")
def get_workout_result(
    workout_id: int = Path(..., description="Workout ID"),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 운동 가져오기
    workout = db.query(models.Workout).filter_by(id=workout_id, user_id=current_user.id).first()
    if not workout:
        raise HTTPException(status_code=404, detail="Workout not found")

    # exercise_type이 Enum일 경우 .value, 문자열 컬럼이면 그대로 접근
    exercise_type_value = workout.exercise_type.value if hasattr(workout.exercise_type, "value") else workout.exercise_type

    return {
        "workout_id": workout.id,
        "exercise_type": exercise_type_value,
        "avg_accuracy": workout.avg_accuracy
    }


# --- DB 저장
def persist_analysis_to_db(result: dict, user_id: int) -> int:
    session = database.SessionLocal()
    try:
        exercise_type_val = result.get("exercise_type")
        try:
            exercise_type_val = models.ExerciseType(exercise_type_val)
        except Exception:
            pass

        workout = models.Workout(
            user_id=user_id,
            exercise_type=exercise_type_val,
            rep_count=int(result.get("rep_count") or result.get("count") or 0),
            avg_accuracy=result.get("avg_accuracy"),
        )
        session.add(workout)
        session.flush()
        session.commit()
        return workout.id
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

from app.schemas import AnalyzeResponse

# --- 분석 요청 (비동기 job_id 반환)
@router.post("/api/v1/exercise/analyze", status_code=status.HTTP_200_OK)
async def analyze_exercise(
    file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user)
):
    filename_lower = file.filename.lower()
    is_video_mime = (file.content_type or "").startswith("video/")
    is_video_ext = filename_lower.endswith((".mp4", ".mov", ".mkv", ".avi", ".webm"))
    if not (is_video_mime or is_video_ext):
        raise HTTPException(status_code=400, detail="영상 파일만 업로드 가능합니다.")

    file_bytes = await file.read()
    await file.close()

    try:
        # 🔹 AI 분석 동기 실행
        result = await asyncio.to_thread(analyze_video_bytes, file_bytes, file.filename, file.content_type)
        workout_id = await asyncio.to_thread(persist_analysis_to_db, result, current_user.id)

        exercise_type = result.get("exercise_type", "unknown")
        rep_count = result.get("rep_count") or result.get("count") or 0
        calories = calculate_calories(exercise_type, int(rep_count))
        avg_accuracy = result.get("avg_accuracy") or result.get("acc") or 90

        final_result = {
            "exercise_type": exercise_type,
            "rep_count": rep_count,
            "calories": calories,
            "avg_accuracy": avg_accuracy,
            "workout_id": workout_id
        }

        # 🔹 최종 결과 반환
        return JSONResponse(content=final_result, status_code=200)

    except Exception as e:
        logger.exception(f"[AI ERROR] analyze_exercise failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

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
    

# --- 칼로리 계산
def calculate_calories(exercise_type: str, count: int, user_weight: float = 70.0) -> float:
    kcal_per_rep = {"pushup": 0.29, "pullup": 1.0, "squat": 0.32, "jumpingjack": 0.2}
    base_kcal = kcal_per_rep.get(exercise_type.lower(), 0)
    kcal = base_kcal * count * (user_weight / 70.0)
    return round(kcal, 2)

# --- 백그라운드 분석 태스크
async def process_analysis_task(job_id: str, file_bytes: bytes, filename: str, content_type: str, user_id: int):
    try:
        JOB_STATUS[job_id]["status"] = "processing"
        result = await asyncio.to_thread(analyze_video_bytes, file_bytes, filename, content_type)
        workout_id = await asyncio.to_thread(persist_analysis_to_db, result, user_id)

        exercise_type = result.get("exercise_type")
        rep_count = result.get("rep_count") or result.get("count") or 0
        calories = calculate_calories(exercise_type, int(rep_count))

        result["workout_id"] = workout_id
        result["calories"] = calories

        JOB_STATUS[job_id].update({"status": "done", "result": result})
    except Exception as e:
        logger.exception(f"[AI ERROR] process_analysis_task failed: {e}") 
        JOB_STATUS[job_id].update({"status": "error", "error": str(e)})

app.include_router(auth.router)

try:
    from app.routers.auth_extra import router as auth_extra_router
    app.include_router(auth_extra_router)
except ImportError:
    pass

# ✅ 로컬 router는 꼭 마지막에 등록!
app.include_router(router)

#커밋용