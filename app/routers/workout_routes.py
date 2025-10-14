from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import models, database
from app.auth import get_current_user

router = APIRouter(prefix="/api/v1/workouts", tags=["Workout"])

@router.get("/latest")
def get_latest_workout(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    ✅ 로그인된 사용자의 가장 최근 운동 데이터를 반환
    """
    workout = (
        db.query(models.Workout)
        .filter(models.Workout.user_id == current_user.id)
        .order_by(models.Workout.id.desc())
        .first()
    )

    if not workout:
        raise HTTPException(status_code=404, detail="No workout data found")

    # 칼로리 계산 (exercise_type에 따라 가중치 변경 가능)
    kcal_per_rep = {"pushup": 0.29, "pullup": 1.0, "squat": 0.32, "jumpjack": 0.2}
    base_kcal = kcal_per_rep.get(workout.exercise_type.lower(), 0)
    calories = round(base_kcal * (workout.rep_count or 0), 2)

    return {
        "id": workout.id,
        "exercise_type": workout.exercise_type,
        "rep_count": workout.rep_count,
        "calories": calories,
        "avg_accuracy": workout.avg_accuracy,
        "created_at": (
            workout.created_at.isoformat()
            if hasattr(workout, "created_at") and workout.created_at
            else None
        ),
    }
