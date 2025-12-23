import joblib
import lief
import numpy as np
import os
import json
import time

# 1. Unified Paths for the Docker Environment
# These match the WORKDIR and Volumes in docker-compose.yml
MODEL_PATH = "/app/malware_model.pkl"
UPLOAD_DIR = "/app/temp_uploads"

# 2. Load the pre-trained Machine Learning model at startup
print(f"[*] Loading model from {MODEL_PATH}...")
model = joblib.load(MODEL_PATH)

def process_file(filepath):
    """
    Analyzes a binary file using LIEF and the ML model.
    Measures processing time to satisfy performance testing requirements.
    """
    start_time = time.time() # Start performance measurement
    task_id = os.path.basename(filepath).split('_')[0]
    
    print(f"[*] Starting analysis for task: {task_id}")
    
    # Initialize the result object with basic info
    result = {
        "task_id": task_id,
        "filename": os.path.basename(filepath).split('_', 1)[-1],
        "status": "Processing"
    }
    
    try:
        # 3. Parse the binary using LIEF
        binary = lief.parse(filepath)
        
        if not binary:
            print(f"[!] LIEF failed to parse {filepath}")
            result.update({"status": "Failed", "error": "Invalid binary format"})
        else:
            if isinstance(binary, list): 
                binary = binary[0]

            # 4. Feature Extraction (The 6 core features)
            size = os.path.getsize(filepath)
            n_sections = len(binary.sections)
            n_imports = len(binary.imported_functions) if hasattr(binary, 'imported_functions') else 0
            n_exports = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0
            has_sig = 1 if getattr(binary, 'has_signature', False) else 0
            entropy = np.mean([s.entropy for s in binary.sections]) if binary.sections else 0

            features = np.array([size, n_sections, n_imports, n_exports, has_sig, entropy]).reshape(1, -1)
            
            # 5. Perform Prediction
            prediction = int(model.predict(features)[0])
            confidence = float(model.predict_proba(features)[0][prediction])

            # 6. Calculate Duration
            end_time = time.time()
            duration = round(end_time - start_time, 4)

            # 7. Finalize Result Object
            result.update({
                "prediction": "MALWARE" if prediction == 1 else "SAFE",
                "confidence": f"{confidence * 100:.2f}%",
                "status": "Completed",
                "processing_time_sec": duration, # Added for Performance Testing
                "details": {
                    "size_bytes": size,
                    "sections": n_sections,
                    "entropy": round(entropy, 2)
                }
            })
            print(f"[+] Analysis Complete for {task_id} in {duration}s: {result['prediction']}")

    except Exception as e:
        print(f"[!] Critical error during analysis: {str(e)}")
        result.update({"status": "Error", "error": str(e)})

    # 8. Persistence: Save the JSON result to the shared Docker volume
    try:
        result_path = filepath + ".json"
        with open(result_path, "w") as f:
            json.dump(result, f)
        
        # Ensure correct permissions so the Web API can read the file
        os.chmod(result_path, 0o666) 
    except Exception as save_error:
        print(f"[!] Could not save result JSON: {save_error}")

    return result