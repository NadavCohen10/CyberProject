# MacBreaker — Simple Overview

**Short description:**
MacBreaker helps you quickly identify whether a macOS binary looks malicious. It provides a short, explainable verdict plus a small set of supporting signals so you can triage samples fast.

---

## Authors

- Project: MacBreaker
- Maintainers / Contributors: Nadav Cohen, Ofek Bar Shalom

---

## Files Included

| Filename | Description |
|---|---|
| `app/api/static/index.html` | Web UI for uploading binaries and viewing results |
| `app/api/static/stats.html` | Simple analytics page (processing time vs file size) |
| `app/api/main.py` | FastAPI server and API endpoints |
| `app/worker/worker.py` | Background analyzer that extracts features and runs the model |
| `ml_pipeline/extract_features.py` | Script to build a CSV dataset from raw samples |
| `ml_pipeline/train_model.py` | Train the RandomForest model used for detection |
| `data/dataset.csv` | Example dataset used to train the model |
| `temp_uploads/` | Uploads and analysis JSON reports (runtime output) |
| `docker-compose.yml` | Launches the web server, Redis, and worker (recommended) |
| `tests/stress_test.py` | Simple script to send multiple upload requests for testing |

---

## What it does

- Accepts binary files and performs a fast static inspection.
- Runs a machine-learning model that outputs **MALWARE** or **BENIGN**, along with human-friendly indicators (number of imports, suspicious functions, entropy, signature presence, etc.).
- Stores a small JSON report per analysis so you can review results later.

---

## How to try it

1. Recommended (isolated and easiest):

```bash
docker-compose up --build
# Open http://localhost:8000 in your browser and upload a binary
```

2. Minimal API test (useful for quick checks):

```bash
curl -F "file=@/path/to/your/sample" http://localhost:8000/upload
# You'll get a task_id — check results with:
curl http://localhost:8000/results/<task_id>
```

---

## Typical output (example)

A JSON result contains:
- `task_id`, `filename`, `status` (Processing/Completed)
- `prediction`: `MALWARE` or `BENIGN`
- small set of supporting measurements

This is designed so you can quickly sort, triage, or annotate results in your own workflows.

---

## Configuration & Notes

- The project uses **Redis** as a job queue for background analysis (default port **6379**).
- The server listens on port **8000** by default.
- The model file is expected at `app/models/malware_model.pkl` (if present the worker will use it).

---

## Safety & Legal Disclaimer

This code is provided for **research and educational use only**. Do **not** analyze unknown samples on production machines, use VMs, containers, or isolated lab systems. Do not use this project to attack or analyze systems you do not own or have permission to test.


