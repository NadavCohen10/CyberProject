from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import shutil
import uuid
import json
from redis import Redis
from rq import Queue

app = FastAPI(title="Malware Detection API", version="1.0")

# 1. Connect to Redis using the service name 'redis'
redis_conn = Redis(host='redis', port=6379)
q = Queue(connection=redis_conn)

# 2. Unified path matching the Docker Volume
UPLOAD_DIR = "/app/temp_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory="/app/static"), name="static")

@app.get("/")
def read_root():
    return FileResponse("/app/static/index.html")

@app.post("/upload", tags=["Scanning"])
async def upload_file(file: UploadFile = File(...)):
    task_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{task_id}_{file.filename}")
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # Send task to the Worker
    q.enqueue("worker.process_file", file_path, job_id=task_id)
    
    return {
        "task_id": task_id,
        "status": "Queued",
        "message": "Analysis started. Use /results/{task_id} to check status."
    }

@app.get("/results/{task_id}", tags=["Scanning"])
async def get_results(task_id: str):
    """
    Checks if a result JSON file exists for the given task_id.
    """
    # Look for any .json file starting with the task_id
    for filename in os.listdir(UPLOAD_DIR):
        if filename.startswith(task_id) and filename.endswith(".json"):
            json_path = os.path.join(UPLOAD_DIR, filename)
            with open(json_path, "r") as f:
                return json.load(f)
    
    return {
        "task_id": task_id,
        "status": "Processing", 
        "message": "The worker is still analyzing the file. Try again in a few seconds."
    }

@app.get("/stats")
async def serve_stats_ui():
    return FileResponse("/app/static/stats.html")

@app.get("/api/all-stats")
async def get_all_stats():
    """Aggregates all results from the shared folder for the stats dashboard."""
    all_data = []
    for filename in os.listdir(UPLOAD_DIR):
        if filename.endswith(".json"):
            try:
                with open(os.path.join(UPLOAD_DIR, filename), "r") as f:
                    all_data.append(json.load(f))
            except:
                continue
    return all_data