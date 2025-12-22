# usage example : python3 scan_file.py dataset/benign/ls
# usage example : python3 scan_file.py "dataset/malware/sample_name"

import os
import lief
import joblib
import numpy as np
import sys

# --- Dynamic Path Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "backend", "malware_model.pkl")

def extract_features_for_prediction(filepath):
    """Matches the exact feature extraction used during training"""
    try:
        binary = lief.parse(filepath)
        if binary is None: return None
        if isinstance(binary, list): binary = binary[0]
        if not hasattr(binary, 'sections'): return None

        # 1. File Size
        size = os.path.getsize(filepath)
        
        # 2. Number of Sections
        n_sections = len(binary.sections)
        
        # 3. Imported Functions Count
        n_imports = 0
        if hasattr(binary, 'imported_functions'):
             n_imports = len(binary.imported_functions)
        elif hasattr(binary, 'libraries'):
             n_imports = len(binary.libraries)
        
        # 4. Exported Functions Count
        n_exports = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0
            
        # 5. Signature Presence (1 if signed, 0 if not)
        has_sig = 1 if getattr(binary, 'has_signature', False) else 0
        
        # 6. Average Entropy
        entropy = 0
        if binary.sections:
            entropy = np.mean([s.entropy for s in binary.sections])

        # Return data in the exact order the model expects
        return [size, n_sections, n_imports, n_exports, has_sig, entropy]

    except Exception as e:
        print(f"Error extraction: {e}")
        return None

def scan(filepath):
    print(f"\n🔍 Scanning: {os.path.basename(filepath)}...")
    
    if not os.path.exists(filepath):
        print("❌ Error: File not found.")
        return

    # 1. Load the trained model
    try:
        model = joblib.load(MODEL_PATH)
    except:
        print(f"❌ Error: Model file not found at {MODEL_PATH}. Run train_model.py first.")
        return

    # 2. Extract Features
    features = extract_features_for_prediction(filepath)
    
    if features is None:
        print("⚠️  Skipped: Not a valid Mach-O binary.")
        return

    # 3. Convert to 2D array for the model
    features_array = np.array(features).reshape(1, -1)

    # 4. Perform Prediction
    prediction = model.predict(features_array)[0]
    # Get the probability of being malware
    probability = model.predict_proba(features_array)[0][1] * 100 

    # 5. Output Results
    print("-" * 30)
    if prediction == 1:
        print(f"🚨 RESULT: MALWARE DETECTED! ({probability:.2f}% confidence)")
    else:
        print(f"✅ RESULT: File is Safe. ({100-probability:.2f}% confidence)")
    print("-" * 30)
    print(f"Stats: Size={features[0]}, Sections={features[1]}, Imports={features[2]}, Entropy={features[5]:.2f}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        scan(target_file)
    else:
        print("Usage: python3 scan_file.py <path_to_file>")