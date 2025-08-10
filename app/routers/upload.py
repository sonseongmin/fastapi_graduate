from fastapi import APIRouter, UploadFile, File
import os
import shutil

router = APIRouter()

UPLOAD_DIR = "media"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@router.post("/upload")
def upload_video(file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return {"filename": file.filename, "message": "Upload success!"}
