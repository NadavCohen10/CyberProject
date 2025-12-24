import joblib
import lief
import numpy as np
import os
import json
import time
import pandas as pd

MODEL_PATH = "/app/models/malware_model.pkl"
UPLOAD_DIR = "/app/temp_uploads"

SUSPICIOUS_IMPORTS = [
    'ptrace', 'openssl', 'socket', 'connect', 'bind', 'listen', 
    'system', 'execve', 'chmod', 'wget', 'curl', 'kill', 'keylogger'
]

print(f"[*] Attempting to load model from {MODEL_PATH}...")
try:
    model = joblib.load(MODEL_PATH)
    print(f"[*] Successfully loaded model from {MODEL_PATH}")
except Exception as e:
    print(f"[!] FATAL: Could not load model: {e}")
    model = None 

def process_file(filepath):
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
        binary = lief.parse(filepath)
        
        if not binary:
            result.update({"status": "Failed", "error": "Invalid binary format"})
        else:
            if isinstance(binary, list): 
                binary = binary[0]

            size = os.path.getsize(filepath)
            
            if not hasattr(binary, 'sections'):
                raise ValueError("Binary has no sections")
            n_sections = len(binary.sections)

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

            n_exports = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0
            
            has_sig = 0
            try:
                if binary.has_code_signature or binary.code_signature_dir:
                    has_sig = 1
            except:
                has_sig = 0

            entropy = 0
            if binary.sections:
                entropy = np.mean([s.entropy for s in binary.sections])

            # Use the exact names from your logs to satisfy the RandomForest requirement
            feature_columns = [
                "file_size", 
                "num_sections", 
                "num_imported_functions", 
                "num_suspicious_imports", 
                "num_exported_functions", 
                "has_signature", 
                "avg_section_entropy"
            ]
            
            features_raw = np.array([[size, n_sections, n_imports, suspicious_count, n_exports, has_sig, entropy]])
            features_df = pd.DataFrame(features_raw, columns=feature_columns)
            
            prediction = int(model.predict(features_df)[0])
            probability = model.predict_proba(features_df)[0][1] 

            end_time = time.time()
            duration = round(end_time - start_time, 4)

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

    try:
        result_path = filepath + ".json"
        with open(result_path, "w") as f:
            json.dump(result, f)
        os.chmod(result_path, 0o666) 
    except Exception as save_error:
        print(f"[!] Could not save result JSON: {save_error}")

    return result