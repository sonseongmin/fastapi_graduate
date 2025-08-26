from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# SQLite 경로 (파일형 DB)
SQLALCHEMY_DATABASE_URL = "sqlite:///./data/dev.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()