# usage example : python3 tests/scan_file.py data/samples/benign/aa
# usage example : python3 tests/scan_file.py data/samples/malware/CallMe/CallMe

import os
import lief
import joblib
import numpy as np
import sys
import warnings

warnings.filterwarnings("ignore")

# --- Dynamic Path Configuration ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
MODEL_PATH = os.path.join(BASE_DIR, "app/models", "malware_model.pkl")

# --- Suspicious Functions List ---
SUSPICIOUS_IMPORTS = [
    'ptrace', 'openssl', 'socket', 'connect', 'bind', 'listen', 
    'system', 'execve', 'chmod', 'wget', 'curl', 'kill', 'keylogger'
]

def extract_features_for_prediction(filepath):
    try:
        binary = lief.parse(filepath)
        if binary is None: return None
        if isinstance(binary, list): binary = binary[0]
        if not hasattr(binary, 'sections'): return None

        # 1. File Size
        size = os.path.getsize(filepath)
        
        # 2. Number of Sections
        n_sections = len(binary.sections)
        
        # 3 + 4. Imported Functions & Suspicious Count
        n_imports = 0
        suspicious_count = 0

        if hasattr(binary, 'imported_functions'):
             n_imports = len(binary.imported_functions)
             for func in binary.imported_functions:
                 if any(s in func.name.lower() for s in SUSPICIOUS_IMPORTS):
                     suspicious_count += 1
        elif hasattr(binary, 'libraries'):
             n_imports = len(binary.libraries)
        
        # 5. Exported Functions Count
        n_exports = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0
            
        # 6. Signature Presence (THE FIX)
        has_sig = 0
        try:
            if binary.has_code_signature:
                has_sig = 1
            elif binary.code_signature_dir:
                has_sig = 1
        except:
            has_sig = 0
        
        # 7. Average Entropy
        entropy = 0
        if binary.sections:
            entropy = np.mean([s.entropy for s in binary.sections])

        # Return data [size, sections, imports, suspicious, exports, signature, entropy]
        return [size, n_sections, n_imports, suspicious_count, n_exports, has_sig, entropy]

    except Exception as e:
        print(f"Error extraction: {e}")
        return None

def scan(filepath):
    print(f"\nScanning: {os.path.basename(filepath)}...")
    
    if not os.path.exists(filepath):
        print("Error: File not found.")
        return

    try:
        model = joblib.load(MODEL_PATH)
    except:
        print(f"Error: Model file not found at {MODEL_PATH}.")
        return

    features = extract_features_for_prediction(filepath)
    
    if features is None:
        print("Skipped: Not a valid Mach-O binary.")
        return

    features_array = np.array(features).reshape(1, -1)
    prediction = model.predict(features_array)[0]
    probability = model.predict_proba(features_array)[0][1] * 100 

    print("-" * 30)
    if prediction == 1:
        print(f"RESULT: MALWARE DETECTED! ({probability:.2f}% confidence)")
    else:
        print(f"RESULT: File is Safe. ({100-probability:.2f}% confidence)")
    print("-" * 30)
    
    print(f"Stats:")
    print(f" - Size: {features[0]}")
    print(f" - Sections: {features[1]}")
    print(f" - Imports: {features[2]} (Suspicious: {features[3]})")
    print(f" - Signed: {'Yes' if features[5]==1 else 'No'}")
    print(f" - Entropy: {features[6]:.2f}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        scan(target_file)
    else:
        print("Usage: python3 scan_file.py <path_to_file>")