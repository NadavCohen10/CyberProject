# extract features from Mach-O files in malware and benign datasets

import os
import lief
import numpy as np
import csv
import gc

# --- Settings ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
MALWARE_DIR = os.path.join(BASE_DIR, "data/samples/malware")
BENIGN_DIR = os.path.join(BASE_DIR, "data/samples/benign")
OUTPUT_CSV = os.path.join(BASE_DIR, "data/dataset.csv")

# Valid magic bytes
VALID_MAGICS = [
    b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
    b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', 
    b'\xca\xfe\xba\xbe'
]

# --- Suspicious Imports List ---
# These words are commonly found in malware (networking, command execution, encryption)
SUSPICIOUS_IMPORTS = [
    'ptrace', 'openssl', 'socket', 'connect', 'bind', 'listen', 
    'system', 'execve', 'chmod', 'wget', 'curl', 'kill', 'keylogger'
]

CSV_HEADERS = [
    "filename", "file_size", "num_sections", "num_imported_functions", 
    "num_suspicious_imports", "num_exported_functions", "has_signature", "avg_section_entropy", "label"
]

try:
    lief.logging.set_level(lief.logging.LEVEL.ERROR)
except:
    pass

def is_potential_macho(filepath):
    try:
        if os.path.getsize(filepath) == 0: return False
        with open(filepath, 'rb') as f:
            header = f.read(4)
            return header in VALID_MAGICS
    except:
        return False

def extract_features(filepath, label):
    if not is_potential_macho(filepath):
        return None

    try:
        binary = lief.parse(filepath)
        if binary is None: return None
        if isinstance(binary, list): binary = binary[0]
        if not hasattr(binary, 'sections'): return None

        # existing data
        size = os.path.getsize(filepath)
        n_sections = len(binary.sections)
        
        n_imports = 0
        suspicious_count = 0

        if hasattr(binary, 'imported_functions'):
             n_imports = len(binary.imported_functions)
             # count of suspicious functions
             for func in binary.imported_functions:
                 if any(s in func.name.lower() for s in SUSPICIOUS_IMPORTS):
                     suspicious_count += 1
                     
        elif hasattr(binary, 'libraries'):
             n_imports = len(binary.libraries)
        
        n_exports = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0
        has_sig = 0
        try:
            # specific check for Mach-O in LIEF
            if binary.has_code_signature:
                has_sig = 1
            # additional option in case the first doesn't work in older versions
            elif binary.code_signature_dir: 
                has_sig = 1
        except:
            has_sig = 0
        
        entropy = 0
        if binary.sections:
            entropy = np.mean([s.entropy for s in binary.sections])

        return [
            os.path.basename(filepath),
            size, n_sections, n_imports, suspicious_count, n_exports, has_sig, entropy, label
        ]

    except Exception:
        return None

def process_and_save(root_folder, label, writer):
    print(f"\n--- Scanning: {root_folder} (Label: {label}) ---")
    count = 0
    scanned = 0
    for root, dirs, files in os.walk(root_folder):
        for file in files:
            if file.lower().endswith(('.txt', '.html', '.xml', '.png', '.plist', '.json', '.h', '.c')):
                continue
            
            file_path = os.path.join(root, file)
            scanned += 1
            features = extract_features(file_path, label)
            
            if features:
                writer.writerow(features)
                count += 1
                if count % 50 == 0:
                    print(f"✅ Success: {count} extracted...", end='\r')
            
            if scanned % 1000 == 0: gc.collect()

    print(f"\nFinished {root_folder}. Total Success: {count}")

if __name__ == "__main__":
    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        process_and_save(MALWARE_DIR, 1, writer)
        gc.collect()
        process_and_save(BENIGN_DIR, 0, writer)
    print(f"\nDone! CSV saved to {OUTPUT_CSV}")