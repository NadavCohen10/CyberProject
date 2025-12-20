import os
import lief
import joblib
import numpy as np
import sys

# נתיבים
BASE_DIR = os.path.expanduser("~/Desktop/CyberProject")
MODEL_PATH = os.path.join(BASE_DIR, "backend/malware_model.pkl")

# בדיוק אותה פונקציה כמו באימון (בלי ה-label וה-filename)
def extract_features_for_prediction(filepath):
    try:
        binary = lief.parse(filepath)
        if binary is None: return None
        if isinstance(binary, list): binary = binary[0]
        if not hasattr(binary, 'sections'): return None

        # 1. File Size
        size = os.path.getsize(filepath)
        
        # 2. Sections
        n_sections = len(binary.sections)
        
        # 3. Imports
        n_imports = 0
        if hasattr(binary, 'imported_functions'):
             n_imports = len(binary.imported_functions)
        elif hasattr(binary, 'libraries'):
             n_imports = len(binary.libraries)
        
        # 4. Exports
        n_exports = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0
            
        # 5. Signature
        has_sig = 1 if getattr(binary, 'has_signature', False) else 0
        
        # 6. Entropy
        entropy = 0
        if binary.sections:
            entropy = np.mean([s.entropy for s in binary.sections])

        # החזרת הנתונים בדיוק בסדר שהמודל למד
        return [size, n_sections, n_imports, n_exports, has_sig, entropy]

    except Exception as e:
        print(f"Error extraction: {e}")
        return None

def scan(filepath):
    print(f"\n🔍 Scanning: {os.path.basename(filepath)}...")
    
    if not os.path.exists(filepath):
        print("❌ Error: File not found.")
        return

    # 1. טעינת המודל
    try:
        model = joblib.load(MODEL_PATH)
    except:
        print("❌ Error: Model file not found. Run train_model.py first.")
        return

    # 2. חילוץ פיצ'רים
    features = extract_features_for_prediction(filepath)
    
    if features is None:
        print("⚠️  Skipped: Not a valid Mach-O binary.")
        return

    # 3. המרה לפורמט שהמודל מבין (מערך דו-ממדי)
    features_array = np.array(features).reshape(1, -1)

    # 4. ביצוע התחזית
    prediction = model.predict(features_array)[0]
    probability = model.predict_proba(features_array)[0][1] * 100 # סיכוי שזה נוזקה

    # 5. הדפסת התוצאה
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