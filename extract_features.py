import os
import lief
import numpy as np
import csv
import gc
import struct

# --- הגדרות ---
BASE_DIR = os.path.expanduser("~/Desktop/CyberProject")
MALWARE_DIR = os.path.join(BASE_DIR, "dataset/malware")
BENIGN_DIR = os.path.join(BASE_DIR, "dataset/benign")
OUTPUT_CSV = os.path.join(BASE_DIR, "dataset.csv")

# הגבלת גודל: 50MB
MAX_FILE_SIZE = 50 * 1024 * 1024 

# חתימות של קבצי Mach-O (כדי לזהות אותם וודאית)
MACHO_SIGNATURES = {
    b'\xfe\xed\xfa\xce',  # MH_MAGIC (32-bit)
    b'\xfe\xed\xfa\xcf',  # MH_MAGIC_64 (64-bit)
    b'\xce\xfa\xed\xfe',  # MH_CIGAM (32-bit LE)
    b'\xcf\xfa\xed\xfe',  # MH_CIGAM_64 (64-bit LE)
    b'\xca\xfe\xba\xbe',  # FAT_MAGIC
}

CSV_HEADERS = [
    "filename", "file_size", "num_sections", "num_imported_functions", 
    "num_exported_functions", "has_signature", "avg_section_entropy", "label"
]

try:
    lief.logging.set_level(lief.logging.LEVEL.ERROR)
except:
    pass

def is_macho(filepath):
    """בדיקה מהירה האם הקובץ הוא Mach-O לפי הכותרת שלו"""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(4)
            return header in MACHO_SIGNATURES
    except:
        return False

def extract_features(filepath, label):
    try:
        # 1. בדיקת גודל
        fsize = os.path.getsize(filepath)
        if fsize > MAX_FILE_SIZE:
            return None # Skip silently

        # 2. בדיקת סוג קובץ (Magic Bytes)
        if not is_macho(filepath):
            return None # זה לא Mach-O (אולי זה DMG/PKG/TXT), דלג.

        # 3. ניתוח עם LIEF
        binary = lief.parse(filepath)
        if binary is None: return None
        
        # טיפול ב-Fat Binary (קבצים שמכילים גם Intel וגם ARM)
        if isinstance(binary, list): 
            binary = binary[0] # קח את הראשון
        
        if not isinstance(binary, lief.MachO.Binary):
            return None

        # 4. חילוץ נתונים
        return [
            os.path.basename(filepath), # הוספתי את שם הקובץ ל-CSV שנדע מה עבד
            fsize,
            len(binary.sections),
            sum(len(lib.entries) for lib in binary.libraries),
            len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0,
            1 if binary.has_signature else 0,
            np.mean([s.entropy for s in binary.sections]) if binary.sections else 0,
            label
        ]
    except Exception:
        return None

def process_and_save(root_folder, label, writer):
    print(f"\n--- Scanning: {root_folder} (Label: {label}) ---")
    
    total_files = 0
    processed_count = 0
    skipped_count = 0
    
    for root, dirs, files in os.walk(root_folder):
        for file in files:
            if file.startswith('.') or file.endswith('.zip') or file.endswith('.csv'): continue
            
            total_files += 1
            file_path = os.path.join(root, file)
            
            features = extract_features(file_path, label)
            
            if features:
                writer.writerow(features)
                processed_count += 1
                if processed_count % 10 == 0:
                    print(f"Extracted: {processed_count} files...", end='\r')
            else:
                skipped_count += 1
                
            if total_files % 100 == 0:
                gc.collect()

    print(f"\nFinished. Scanned: {total_files} | Success: {processed_count} | Skipped/Not-MachO: {skipped_count}")

if __name__ == "__main__":
    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        
        process_and_save(MALWARE_DIR, 1, writer)
        gc.collect()
        process_and_save(BENIGN_DIR, 0, writer)
        
    print(f"\nDone! CSV saved to {OUTPUT_CSV}")