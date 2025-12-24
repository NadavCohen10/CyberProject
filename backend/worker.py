import joblib
import lief
import numpy as np
import os
import json
import time

# 1. Unified Paths for the Docker Environment
MODEL_PATH = "/app/malware_model.pkl"
UPLOAD_DIR = "/app/temp_uploads"

# --- Suspicious imports list (MUST match extract_features.py & scan_file.py) ---
SUSPICIOUS_IMPORTS = [
    'ptrace', 'openssl', 'socket', 'connect', 'bind', 'listen', 
    'system', 'execve', 'chmod', 'wget', 'curl', 'kill', 'keylogger'
]

# 2. Load the pre-trained Machine Learning model at startup
print(f"[*] Attempting to load model from {MODEL_PATH}...")
try:
    model = joblib.load(MODEL_PATH)
    print(f"[*] Successfully loaded model from {MODEL_PATH}")
except Exception as e:
    print(f"[!] FATAL: Could not load model: {e}")
    # In a worker, we might want to exit if model is missing
    model = None 

def process_file(filepath):
    """
    Analyzes a binary file using LIEF and the ML model.
    Matches the exact logic used in train_model.py (97.5% accuracy).
    """
    if model is None:
        return {"status": "Error", "error": "Model not loaded"}

    start_time = time.time() 
    task_id = os.path.basename(filepath).split('_')[0]
    
    print(f"[*] Starting analysis for task: {task_id}")
    
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

            # --- 4. Feature Extraction (Updated to match Training) ---
            
            # Feature 1: Size
            size = os.path.getsize(filepath)
            
            # Feature 2: Sections
            if not hasattr(binary, 'sections'):
                raise ValueError("Binary has no sections")
            n_sections = len(binary.sections)

            # Feature 3 & 4: Imports & Suspicious Count
            n_imports = 0
            suspicious_count = 0
            
            if hasattr(binary, 'imported_functions'):
                 n_imports = len(binary.imported_functions)
                 for func in binary.imported_functions:
                     try:
                         if any(s in func.name.lower() for s in SUSPICIOUS_IMPORTS):
                             suspicious_count += 1
                     except:
                         continue
            elif hasattr(binary, 'libraries'):
                 n_imports = len(binary.libraries)

            # Feature 5: Exports
            n_exports = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0
            
            # Feature 6: Signature (THE CRITICAL FIX)
            has_sig = 0
            try:
                if binary.has_code_signature:
                    has_sig = 1
                elif binary.code_signature_dir:
                    has_sig = 1
            except:
                has_sig = 0

            # Feature 7: Entropy
            entropy = 0
            if binary.sections:
                entropy = np.mean([s.entropy for s in binary.sections])

            # Ensure feature order matches training CSV: 
            # [size, n_sections, n_imports, num_suspicious_imports, n_exports, has_sig, entropy]
            features = np.array([size, n_sections, n_imports, suspicious_count, n_exports, has_sig, entropy]).reshape(1, -1)
            
            # 5. Perform Prediction
            prediction = int(model.predict(features)[0])
            probability = model.predict_proba(features)[0][1] # Probability of being malware (class 1)

            # 6. Calculate Duration
            end_time = time.time()
            duration = round(end_time - start_time, 4)

            # 7. Finalize Result Object
            result.update({
                "prediction": "MALWARE" if prediction == 1 else "SAFE",
                "confidence": f"{probability * 100:.2f}%" if prediction == 1 else f"{(1 - probability) * 100:.2f}%",
                "raw_probability": probability,
                "status": "Completed",
                "processing_time_sec": duration,
                "details": {
                    "size_bytes": size,
                    "sections": n_sections,
                    "imports": n_imports,
                    "suspicious_imports": suspicious_count,
                    "exports": n_exports,
                    "has_signature": bool(has_sig),
                    "entropy": round(entropy, 2)
                }
            })
            print(f"[+] Analysis Complete for {task_id}: {result['prediction']}")

    except Exception as e:
        print(f"[!] Critical error during analysis: {str(e)}")
        result.update({"status": "Error", "error": str(e)})

    # 8. Persistence: Save the JSON result to the shared Docker volume
    try:
        result_path = filepath + ".json"
        with open(result_path, "w") as f:
            json.dump(result, f)
        os.chmod(result_path, 0o666) 
    except Exception as save_error:
        print(f"[!] Could not save result JSON: {save_error}")

    return result