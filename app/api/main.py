"""API server for queueing file scans and retrieving results.

This FastAPI application accepts file uploads, enqueues an RQ job for
asynchronous analysis by a worker process, and exposes endpoints to fetch
individual task results and aggregated stats.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import shutil
import uuid
import json
from redis import Redis
from rq import Queue

# Create FastAPI app instance
app = FastAPI(title="Malware Detection API", version="1.0")

# 1. Connect to Redis using the service name 'redis' (as defined in docker-compose)
#    The RQ Queue is then used to enqueue jobs that will be processed by the worker
redis_conn = Redis(host='redis', port=6379)
q = Queue(connection=redis_conn)

# 2. Paths updated to match internal Docker structure
UPLOAD_DIR = "/app/temp_uploads"
STATIC_DIR = "/app/api/static"
# Ensure the upload directory exists at startup
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Mount static files so they are available under /static URL path
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def read_root():
    """Serve the main UI page (index.html) for the web interface."""
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.post("/upload", tags=["Scanning"])
async def upload_file(file: UploadFile = File(...)):
    """Accept an uploaded file, save it to disk, and enqueue it for analysis.

    A UUID is used as a task identifier and prefixed to the filename so the
    worker and the API can correlate results.
    """
    task_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{task_id}_{file.filename}")

    # Persist the uploaded file to the uploads directory
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Enqueue the worker task using the function path 'worker.worker.process_file'
    # The job_id is set to the task_id for easier lookup and correlation
    q.enqueue("worker.worker.process_file", file_path, job_id=task_id)

    return {
        "task_id": task_id,
        "status": "Queued",
        "message": "Analysis started. Use /results/{task_id} to check status."
    }


@app.get("/results/{task_id}", tags=["Scanning"])
async def get_results(task_id: str):
    """Return the JSON result file for a specific task_id when available.

    The worker writes a JSON file with the same prefix when processing completes.
    This endpoint checks the uploads directory for that file and returns it if found.
    """
    for filename in os.listdir(UPLOAD_DIR):
        if filename.startswith(task_id) and filename.endswith(".json"):
            json_path = os.path.join(UPLOAD_DIR, filename)
            with open(json_path, "r") as f:
                return json.load(f)

    # If no JSON result found, indicate the job is still processing
    return {
        "task_id": task_id,
        "status": "Processing", 
        "message": "The worker is still analyzing the file. Try again in a few seconds."
    }


@app.get("/stats")
async def serve_stats_ui():
    """Serve the HTML page that displays aggregated statistics."""
    return FileResponse(os.path.join(STATIC_DIR, "stats.html"))


@app.get("/api/all-stats")
async def get_all_stats():
    """Return a list of all JSON result payloads found in the uploads directory.

    The endpoint is useful for debugging or building a simple dashboard that
    aggregates recent scan outputs. Non-readable files are skipped silently.
    """
    all_data = []
    for filename in os.listdir(UPLOAD_DIR):
        if filename.endswith(".json"):
            try:
                with open(os.path.join(UPLOAD_DIR, filename), "r") as f:
                    all_data.append(json.load(f))
            except:
                # Skip any files that can't be read or parsed
                continue
    return all_data