from fastapi import APIRouter, UploadFile, File, Form
import os
import shutil
import uuid

router = APIRouter()

UPLOAD_DIR = "media"
os.makedirs(UPLOAD_DIR, exist_ok=True)  # media 폴더 없으면 생성

@router.post("/upload")
def upload_video(
    category: str = Form(...),   # 프론트에서 넘어오는 운동 카테고리
    file: UploadFile = File(...),
):
    # 1. 카테고리별 폴더 생성
    category_dir = os.path.join(UPLOAD_DIR, category)
    os.makedirs(category_dir, exist_ok=True)

    # 2. 중복 방지를 위한 UUID 파일명 생성
    unique_filename = f"{uuid.uuid4()}_{file.filename}"
    file_path = os.path.join(category_dir, unique_filename)

    # 3. 파일 저장
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 4. 업로드 경로 로그 출력 (확인용)
    print(f"[UPLOAD] File saved to: {os.path.abspath(file_path)}")

    return {
        "filename": unique_filename,
        "category": category,
        "message": "Upload success!",
        "path": file_path
    }
