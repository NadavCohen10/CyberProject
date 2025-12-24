# usage example : python3 tests/scan_file.py data/samples/benign/aa
# usage example : python3 tests/scan_file.py data/samples/malware/CallMe/CallMe
# Small utility to perform a static scan on a Mach-O binary by extracting
# simple features and using a pre-trained model to classify it as benign
# or malware. This file is intended for quick local testing in the repo.

import os
import lief
import joblib
import numpy as np
import sys
import warnings

warnings.filterwarnings("ignore")  # reduce noisy warnings during parsing

# --- Dynamic Path Configuration ---
# Compute project root relative to this test script and point to saved model
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
MODEL_PATH = os.path.join(BASE_DIR, "app/models", "malware_model.pkl")

# --- Suspicious Functions List ---
# Keywords used to flag potentially dangerous imported functions
SUSPICIOUS_IMPORTS = [
    'ptrace', 'openssl', 'socket', 'connect', 'bind', 'listen', 
    'system', 'execve', 'chmod', 'wget', 'curl', 'kill', 'keylogger'
]


def extract_features_for_prediction(filepath):
    """Extract a small set of static features from a Mach-O binary.

    Returns a list with the following items in order:
      [size, n_sections, n_imports, suspicious_count, n_exports, has_sig, entropy]

    Returns None if the file cannot be parsed as a valid Mach-O binary.
    """
    try:
        # Parse binary with lief. It can return None or a list for certain inputs.
        binary = lief.parse(filepath)
        if binary is None: return None
        if isinstance(binary, list): binary = binary[0]
        # Ensure basic structure exists
        if not hasattr(binary, 'sections'): return None

        # 1. File Size
        size = os.path.getsize(filepath)
        
        # 2. Number of Sections
        n_sections = len(binary.sections)
        
        # 3 + 4. Number of imported functions and count of suspicious imports
        n_imports = 0
        suspicious_count = 0

        if hasattr(binary, 'imported_functions'):
             n_imports = len(binary.imported_functions)
             # Check each imported function name for suspicious keywords
             for func in binary.imported_functions:
                 if any(s in func.name.lower() for s in SUSPICIOUS_IMPORTS):
                     suspicious_count += 1
        elif hasattr(binary, 'libraries'):
             # Fallback for binaries where imports are represented as libraries
             n_imports = len(binary.libraries)
        
        # 5. Exported Functions Count
        n_exports = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0
            
        # 6. Signature Presence
        has_sig = 0
        try:
            # Different lief versions expose signature info differently
            if binary.has_code_signature:
                has_sig = 1
            elif binary.code_signature_dir:
                has_sig = 1
        except:
            # If any attribute access fails, assume no signature
            has_sig = 0
        
        # 7. Average Entropy
        entropy = 0
        if binary.sections:
            entropy = np.mean([s.entropy for s in binary.sections])

        # Return the feature vector in the expected order
        return [size, n_sections, n_imports, suspicious_count, n_exports, has_sig, entropy]

    except Exception as e:
        # Any parsing error is surfaced for the user and the file skipped
        print(f"Error extraction: {e}")
        return None


def scan(filepath):
    """Run the end-to-end scan for a single file path and print results."""
    print(f"\nScanning: {os.path.basename(filepath)}...")
    
    # Basic existence check
    if not os.path.exists(filepath):
        print("Error: File not found.")
        return

    # Load the trained classifier from the repository model path
    try:
        model = joblib.load(MODEL_PATH)
    except:
        print(f"Error: Model file not found at {MODEL_PATH}.")
        return

    # Extract features for prediction
    features = extract_features_for_prediction(filepath)
    
    if features is None:
        # skip files that aren't valid Mach-O binaries
        print("Skipped: Not a valid Mach-O binary.")
        return

    # Prepare array shape expected by scikit-learn model and predict
    features_array = np.array(features).reshape(1, -1)
    prediction = model.predict(features_array)[0]
    probability = model.predict_proba(features_array)[0][1] * 100 

    # formatted output with result and feature summary
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
    # Allow running this script directly with a target file argument
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        scan(target_file)
    else:
        print("Usage: python3 scan_file.py <path_to_file>")