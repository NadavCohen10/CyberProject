from fastapi import FastAPI, UploadFile, File
import os
import shutil
import uuid
from redis import Redis
from rq import Queue

app = FastAPI(title="Malware Detection API", version="1.0")

# Connect to Redis (this will run in a separate Docker container later)
redis_conn = Redis(host='redis', port=6379)
q = Queue(connection=redis_conn)

UPLOAD_DIR = "/app/temp_uploads" 
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/")
def read_root():
    return {"status": "Online", "service": "Malware Detection System"}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    task_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{task_id}_{file.filename}")
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # Send task to the Worker via Redis
    # 'process_file' is the function the worker will run
    job = q.enqueue("worker.process_file", file_path, job_id=task_id)
    
    return {
        "task_id": task_id,
        "status": "Queued",
        "message": "Analysis started in background"
    }