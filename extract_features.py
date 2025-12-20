import os
import lief
import numpy as np
import csv
import gc

# --- הגדרות ---
BASE_DIR = os.path.expanduser("~/Desktop/CyberProject")
MALWARE_DIR = os.path.join(BASE_DIR, "dataset/malware")
BENIGN_DIR = os.path.join(BASE_DIR, "dataset/benign")
OUTPUT_CSV = os.path.join(BASE_DIR, "dataset.csv")

# חתימות תקינות של קבצי Mach-O
VALID_MAGICS = [
    b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
    b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', 
    b'\xca\xfe\xba\xbe'
]

CSV_HEADERS = [
    "filename", "file_size", "num_sections", "num_imported_functions", 
    "num_exported_functions", "has_signature", "avg_section_entropy", "label"
]

# השתקת לוגים
try:
    lief.logging.set_level(lief.logging.LEVEL.ERROR)
except:
    pass

def is_potential_macho(filepath):
    """סינון ראשוני מהיר לפי Magic Bytes"""
    try:
        if os.path.getsize(filepath) == 0: return False
        with open(filepath, 'rb') as f:
            header = f.read(4)
            return header in VALID_MAGICS
    except:
        return False

def extract_features(filepath, label):
    # 1. בדיקת חתימה
    if not is_potential_macho(filepath):
        return None

    try:
        # 2. טעינה עם LIEF
        binary = lief.parse(filepath)
        
        if binary is None: return None
            
        # טיפול ב-Fat Binary
        if isinstance(binary, list):
            binary = binary[0]

        if not hasattr(binary, 'sections'): return None

        # --- תיקון הקריסה: שימוש בשיטות בטוחות יותר ---
        
        # גודל
        size = os.path.getsize(filepath)
        
        # מספר סקשנים
        n_sections = len(binary.sections)
        
        # *** התיקון הגדול: ספירה ישירה של פונקציות מיובאות ***
        n_imports = 0
        if hasattr(binary, 'imported_functions'):
             n_imports = len(binary.imported_functions)
        elif hasattr(binary, 'libraries'):
             # fallback למקרה קיצון: ספירת ספריות בלבד
             n_imports = len(binary.libraries)
        
        # פונקציות מיוצאות
        n_exports = 0
        if hasattr(binary, 'exported_functions'):
            n_exports = len(binary.exported_functions)
            
        # *** תיקון has_signature: שימוש ב-getattr למניעת קריסה ***
        has_sig = 1 if getattr(binary, 'has_signature', False) else 0
        
        # אנטרופיה
        entropy = 0
        if binary.sections:
            entropy = np.mean([s.entropy for s in binary.sections])

        return [
            os.path.basename(filepath),
            size, n_sections, n_imports, n_exports, has_sig, entropy, label
        ]

    except Exception:
        # במקרה של קובץ ממש דפוק, נדלג
        return None

def process_and_save(root_folder, label, writer):
    print(f"\n--- Scanning: {root_folder} (Label: {label}) ---")
    
    count = 0
    scanned = 0
    
    for root, dirs, files in os.walk(root_folder):
        for file in files:
            # סינון סיומות רעש נפוצות
            if file.lower().endswith(('.txt', '.html', '.xml', '.png', '.plist', '.json', '.h', '.c')):
                continue

            file_path = os.path.join(root, file)
            scanned += 1
            
            features = extract_features(file_path, label)
            
            if features:
                writer.writerow(features)
                count += 1
                # הדפסה כל 5 קבצים כדי שתרגיש את ההתקדמות
                if count % 5 == 0:
                    print(f"✅ Success: {count} extracted...", end='\r')
            
            if scanned % 1000 == 0:
                gc.collect()

    print(f"\nFinished {root_folder}. Total Success: {count}")

if __name__ == "__main__":
    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        
        process_and_save(MALWARE_DIR, 1, writer)
        gc.collect()
        process_and_save(BENIGN_DIR, 0, writer)
        
    print(f"\nDone! CSV saved to {OUTPUT_CSV}")