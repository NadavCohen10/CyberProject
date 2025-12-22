import joblib
import lief
import numpy as np
import os
import json
import time

# 1. Unified Paths for Docker Environment
# These paths match the Workdir and Volumes defined in your Dockerfile and Compose
MODEL_PATH = "/app/malware_model.pkl"
UPLOAD_DIR = "/app/temp_uploads"

# 2. Load the pre-trained Machine Learning model
# This happens once when the worker container starts
print(f"[*] Loading model from {MODEL_PATH}...")
model = joblib.load(MODEL_PATH)

def process_file(filepath):
    """
    Function called by the Redis Queue (RQ) to analyze a file.
    It extracts features using LIEF and predicts if it's Malware or Safe.
    """
    print(f"[*] Starting analysis for: {filepath}")
    
    try:
        # 3. Parse the binary using LIEF
        binary = lief.parse(filepath)
        if not binary:
            return {"error": "Invalid binary format or corrupted file"}
        
        # Handle cases where multiple binaries are in one file (Fat Binaries)
        if isinstance(binary, list):
            binary = binary[0]

        # 4. Feature Extraction (Matching the 6 features from training)
        # Size of the file in bytes
        size = os.path.getsize(filepath)
        
        # Number of sections in the binary
        n_sections = len(binary.sections)
        
        # Number of imported and exported functions
        n_imports = len(binary.imported_functions) if hasattr(binary, 'imported_functions') else 0
        n_exports = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0
        
        # Binary signature check (1 if signed, 0 if not)
        has_sig = 1 if getattr(binary, 'has_signature', False) else 0
        
        # Average entropy of sections (higher entropy often suggests packing/encryption)
        entropy = np.mean([s.entropy for s in binary.sections]) if binary.sections else 0

        # Prepare features for the Random Forest model
        features = np.array([size, n_sections, n_imports, n_exports, has_sig, entropy]).reshape(1, -1)
        
        # 5. Perform Prediction
        prediction = int(model.predict(features)[0])
        confidence = float(model.predict_proba(features)[0][prediction])

        # 6. Prepare Result Object
        result = {
            "task_id": os.path.basename(filepath).split('_')[0],
            "filename": os.path.basename(filepath).split('_', 1)[-1],
            "prediction": "MALWARE" if prediction == 1 else "SAFE",
            "confidence": f"{confidence * 100:.2f}%",
            "status": "Completed",
            "details": {
                "size_bytes": size,
                "sections": n_sections,
                "entropy": round(entropy, 2)
            }
        }

        # 7. Save Result to JSON File
        # This allows the API to read the result later even if the worker is busy
        result_path = filepath + ".json"
        with open(result_path, "w") as f:
            json.dump(result, f)

        print(f"[+] Analysis Complete for {filepath}: {result['prediction']} ({result['confidence']})")
        return result

    except Exception as e:
        error_msg = f"Error during analysis: {str(e)}"
        print(f"[!] {error_msg}")
        return {"error": error_msg}