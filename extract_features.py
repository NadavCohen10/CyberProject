# extract features from Mach-O files in malware and benign datasets

import os
import lief
import numpy as np
import csv
import gc

# --- Dynamic Path Settings ---
# Automatically find the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define relative paths for datasets and output
MALWARE_DIR = os.path.join(BASE_DIR, "dataset", "malware")
BENIGN_DIR = os.path.join(BASE_DIR, "dataset", "benign")
OUTPUT_CSV = os.path.join(BASE_DIR, "dataset.csv")

# Valid Magic Bytes for Mach-O file identification
VALID_MAGICS = [
    b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
    b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', 
    b'\xca\xfe\xba\xbe'
]

CSV_HEADERS = [
    "filename", "file_size", "num_sections", "num_imported_functions", 
    "num_exported_functions", "has_signature", "avg_section_entropy", "label"
]

# Silence LIEF library logs
try:
    lief.logging.set_level(lief.logging.LEVEL.ERROR)
except:
    pass

def is_potential_macho(filepath):
    """Initial quick filter using Magic Bytes to identify Mach-O files"""
    try:
        if os.path.getsize(filepath) == 0: return False
        with open(filepath, 'rb') as f:
            header = f.read(4)
            return header in VALID_MAGICS
    except:
        return False

def extract_features(filepath, label):
    # 1. Quick Signature Check
    if not is_potential_macho(filepath):
        return None

    try:
        # 2. Parse binary with LIEF
        binary = lief.parse(filepath)
        
        if binary is None: return None
            
        # Handle Fat Binaries (Universal Binaries) by taking the first architecture
        if isinstance(binary, list):
            binary = binary[0]

        if not hasattr(binary, 'sections'): return None

        # --- Data Extraction ---
        
        # File size on disk
        size = os.path.getsize(filepath)
        
        # Total number of sections in the binary
        n_sections = len(binary.sections)
        
        # Count imported functions; fallback to library count if specific list is unavailable
        n_imports = 0
        if hasattr(binary, 'imported_functions'):
             n_imports = len(binary.imported_functions)
        elif hasattr(binary, 'libraries'):
             n_imports = len(binary.libraries)
        
        # Total number of exported functions
        n_exports = 0
        if hasattr(binary, 'exported_functions'):
            n_exports = len(binary.exported_functions)
            
        # Check for presence of a digital signature
        has_sig = 1 if getattr(binary, 'has_signature', False) else 0
        
        # Calculate average entropy across all sections (indicates compression/encryption)
        entropy = 0
        if binary.sections:
            entropy = np.mean([s.entropy for s in binary.sections])

        return [
            os.path.basename(filepath),
            size, n_sections, n_imports, n_exports, has_sig, entropy, label
        ]

    except Exception:
        # Skip files that cause parsing errors
        return None

def process_and_save(root_folder, label, writer):
    if not os.path.exists(root_folder):
        print(f"Warning: Folder not found, skipping: {root_folder}")
        return

    print(f"\n--- Scanning: {root_folder} (Label: {label}) ---")
    
    count = 0
    scanned = 0
    
    for root, dirs, files in os.walk(root_folder):
        for file in files:
            # Filter out common non-binary file types
            if file.lower().endswith(('.txt', '.html', '.xml', '.png', '.plist', '.json', '.h', '.c')):
                continue

            file_path = os.path.join(root, file)
            scanned += 1
            
            features = extract_features(file_path, label)
            
            if features:
                writer.writerow(features)
                count += 1
                # Progress indicator every 5 successful extractions
                if count % 5 == 0:
                    print(f"✅ Success: {count} extracted...", end='\r')
            
            # Run garbage collection every 1000 files to manage RAM usage
            if scanned % 1000 == 0:
                gc.collect()

    print(f"\nFinished {root_folder}. Total Success: {count}")

if __name__ == "__main__":
    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        
        # Process malware samples (Label: 1)
        process_and_save(MALWARE_DIR, 1, writer)
        gc.collect()
        
        # Process benign samples (Label: 0)
        process_and_save(BENIGN_DIR, 0, writer)
        
    print(f"\nDone! CSV saved to {OUTPUT_CSV}")