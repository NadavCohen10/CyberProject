"""Worker process for analyzing uploaded binaries.

This module loads a pre-trained classifier on import and exposes a single
function `process_file` which accepts a file path, extracts a compact set of
static features (file size, sections, imports, signature, entropy), runs the
model, and writes a JSON result alongside the input file.
"""

import joblib
import lief
import numpy as np
import os
import json
import time
import pandas as pd

# Path inside the container where the trained model is expected to live
MODEL_PATH = "/app/models/malware_model.pkl"
# Directory used by the service to save incoming uploads
UPLOAD_DIR = "/app/temp_uploads"

# List of keywords used to flag suspicious imported functions
SUSPICIOUS_IMPORTS = [
    'ptrace', 'openssl', 'socket', 'connect', 'bind', 'listen', 
    'system', 'execve', 'chmod', 'wget', 'curl', 'kill', 'keylogger'
]

# Attempt to load the persisted model on module import. This makes model load
# errors immediately visible in logs when the worker container starts.
print(f"[*] Attempting to load model from {MODEL_PATH}...")
try:
    model = joblib.load(MODEL_PATH)
    print(f"[*] Successfully loaded model from {MODEL_PATH}")
except Exception as e:
    # If the model can't be loaded, keep `model` as None and let callers
    # handle the error gracefully when trying to process files.
    print(f"[!] FATAL: Could not load model: {e}")
    model = None 


def process_file(filepath: str) -> dict:
    """Process a single file and return a dictionary with analysis results.

    The returned dictionary contains keys like `task_id`, `filename`, `status`,
    `prediction`, `confidence`, `details` (feature breakdown), and timing.
    """
    # If the model failed to load, return a clear error payload
    if model is None:
        return {"status": "Error", "error": "Model not loaded"}

    start_time = time.time() 
    # Task identifiers are encoded in the filename (prefix before first underscore)
    task_id = os.path.basename(filepath).split('_')[0]
    
    print(f"[*] Starting analysis for task: {task_id}")
    
    result = {
        "task_id": task_id,
        "filename": os.path.basename(filepath).split('_', 1)[-1],
        "status": "Processing"
    }
    
    try:
        # Parse the binary using LIEF. It supports Mach-O/PE/ELF formats.
        binary = lief.parse(filepath)
        
        if not binary:
            # If LIEF returns falsy, consider it an invalid binary
            result.update({"status": "Failed", "error": "Invalid binary format"})
        else:
            # LIEF may return a list for fat/multi-arch binaries—pick the first
            if isinstance(binary, list): 
                binary = binary[0]

            # File metadata
            size = os.path.getsize(filepath)
            
            # Basic sanity check: binary must expose sections
            if not hasattr(binary, 'sections'):
                raise ValueError("Binary has no sections")
            n_sections = len(binary.sections)

            # Compute import counts and suspicious import hits
            n_imports = 0
            suspicious_count = 0
            
            if hasattr(binary, 'imported_functions'):
                 n_imports = len(binary.imported_functions)
                 for func in binary.imported_functions:
                     try:
                         # Use a defensive lowercasing in case func.name isn't a str
                         if any(s in func.name.lower() for s in SUSPICIOUS_IMPORTS):
                             suspicious_count += 1
                     except:
                         # Ignore malformed import entries
                         continue
            elif hasattr(binary, 'libraries'):
                 # Fallback for binaries where imports are represented as libraries
                 n_imports = len(binary.libraries)

            # Exported functions count (if available)
            n_exports = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0
            
            # Detect code signature presence; be robust to attribute differences
            has_sig = 0
            try:
                if binary.has_code_signature or binary.code_signature_dir:
                    has_sig = 1
            except:
                has_sig = 0

            # Average section entropy as an indicator of packing/obfuscation
            entropy = 0
            if binary.sections:
                entropy = np.mean([s.entropy for s in binary.sections])

            # Feature column names expected by the model
            feature_columns = [
                "file_size", 
                "num_sections", 
                "num_imported_functions", 
                "num_suspicious_imports", 
                "num_exported_functions", 
                "has_signature", 
                "avg_section_entropy"
            ]
            
            # Build a single-row DataFrame for the scikit-learn model
            features_raw = np.array([[size, n_sections, n_imports, suspicious_count, n_exports, has_sig, entropy]])
            features_df = pd.DataFrame(features_raw, columns=feature_columns)
            
            # Run the classifier and obtain both predicted class and probability
            prediction = int(model.predict(features_df)[0])
            probability = model.predict_proba(features_df)[0][1] 

            end_time = time.time()
            duration = round(end_time - start_time, 4)

            # Populate the result payload with human-readable outputs
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
        # Capture any unexpected error and include it in the result payload
        print(f"[!] Critical error during analysis: {str(e)}")
        result.update({"status": "Error", "error": str(e)})

    try:
        # Save the JSON result next to the file so other services can pick it up
        result_path = filepath + ".json"
        with open(result_path, "w") as f:
            json.dump(result, f)
        # Make the file world-writable (the service expects permissive perms)
        os.chmod(result_path, 0o666) 
    except Exception as save_error:
        print(f"[!] Could not save result JSON: {save_error}")

    return result