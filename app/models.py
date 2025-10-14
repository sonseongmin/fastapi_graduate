from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, Float, Date
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import enum

Base = declarative_base()

# 운동 종류 enum
class ExerciseType(enum.Enum):
    squat = "squat"
    lunge = "lunge"
    pushup = "pushup"
    plank = "plank"
    situp = "situp"
    pullup = "pullup"
    jumping_jack = "jumping_jack"

# 사용자 테이블
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)  # 사용자 ID (아이디)
    email = Column(String, unique=True, index=True)
    name = Column(String)
    password = Column(String)  # 해시된 비밀번호
    created_at = Column(DateTime, default=datetime.utcnow)
    password_hash = Column(String)
    workouts = relationship("Workout", back_populates="user")
    inbodies = relationship("Inbody", back_populates="user")



# 운동 기록 테이블
class Workout(Base):
    __tablename__ = "workouts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    exercise_type = Column(Enum(ExerciseType))
    started_at = Column(DateTime)
    ended_at = Column(DateTime)
    rep_count = Column(Integer)
    avg_accuracy = Column(Integer)
    calories = Column(Float)  # 예: 93 = 93%

    user = relationship("User", back_populates="workouts")
    reps = relationship("Rep", back_populates="workout")
    feedbacks = relationship("Feedback", back_populates="workout")


# 반복 데이터 테이블
class Rep(Base):
    __tablename__ = "reps"

    id = Column(Integer, primary_key=True, index=True)
    workout_id = Column(Integer, ForeignKey("workouts.id"))
    rep_number = Column(Integer)
    accuracy = Column(Integer)  # 정수 퍼센트 (예: 87)
    timestamp = Column(DateTime, default=datetime.utcnow)

    workout = relationship("Workout", back_populates="reps")


# 피드백 메시지 테이블
class Feedback(Base):
    __tablename__ = "feedbacks"

    id = Column(Integer, primary_key=True, index=True)
    workout_id = Column(Integer, ForeignKey("workouts.id"))
    rep_number = Column(Integer, nullable=True)
    feedback_text = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    workout = relationship("Workout", back_populates="feedbacks")


# 인바디 테이블
class Inbody(Base):
    __tablename__ = "inbodies"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))

    weight = Column(Float)
    muscle_mass = Column(Float)
    body_fat = Column(Float)

    height = Column(Float)
    sex = Column(String(10))
    birth_date = Column(Date)
    recorded_at = Column(DateTime)

    user = relationship("User", back_populates="inbodies")
