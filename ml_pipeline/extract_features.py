# extract features from Mach-O files in malware and benign datasets
# This script walks two sample directories (malware/benign), extracts a small
# set of static features from each Mach-O file, and writes a CSV dataset that
# can be consumed by the training pipeline.

import os
import lief
import numpy as np
import csv
import gc

# --- Settings ---
# Project-relative directories for samples and output dataset CSV
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
MALWARE_DIR = os.path.join(BASE_DIR, "data/samples/malware")
BENIGN_DIR = os.path.join(BASE_DIR, "data/samples/benign")
OUTPUT_CSV = os.path.join(BASE_DIR, "data/dataset.csv")

# Valid magic bytes used to quickly detect potential Mach-O files
VALID_MAGICS = [
    b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
    b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', 
    b'\xca\xfe\xba\xbe'
]

# --- Suspicious Imports List ---
# Keywords that increase suspicion when seen among imported function names
SUSPICIOUS_IMPORTS = [
    'ptrace', 'openssl', 'socket', 'connect', 'bind', 'listen', 
    'system', 'execve', 'chmod', 'wget', 'curl', 'kill', 'keylogger'
]

# CSV header order expected by downstream training scripts
CSV_HEADERS = [
    "filename", "file_size", "num_sections", "num_imported_functions", 
    "num_suspicious_imports", "num_exported_functions", "has_signature", "avg_section_entropy", "label"
]

# Reduce LIEF logging noise when parsing many files
try:
    lief.logging.set_level(lief.logging.LEVEL.ERROR)
except:
    pass


def is_potential_macho(filepath):
    """Quick heuristic to filter files by magic bytes and zero-length.

    Returns True for files that appear to be Mach-O by checking the first
    4 bytes against known Mach-O magic values.
    """
    try:
        # Skip empty files
        if os.path.getsize(filepath) == 0: return False
        with open(filepath, 'rb') as f:
            header = f.read(4)
            return header in VALID_MAGICS
    except:
        # Any IO/parsing error -> not a potential Mach-O
        return False


def extract_features(filepath, label):
    """Parse a Mach-O file and return a list of features or None on failure.

    Returned feature vector format:
    [basename, file_size, n_sections, n_imports, suspicious_count, n_exports, has_sig, entropy, label]
    """
    if not is_potential_macho(filepath):
        return None

    try:
        binary = lief.parse(filepath)
        if binary is None: return None
        # LIEF sometimes returns a list for fat/multi-arch binaries
        if isinstance(binary, list): binary = binary[0]
        if not hasattr(binary, 'sections'): return None

        # Basic file metadata
        size = os.path.getsize(filepath)
        n_sections = len(binary.sections)
        
        # Imported functions and number of suspicious ones
        n_imports = 0
        suspicious_count = 0

        if hasattr(binary, 'imported_functions'):
             n_imports = len(binary.imported_functions)
             # Count suspicious imported function names
             for func in binary.imported_functions:
                 if any(s in func.name.lower() for s in SUSPICIOUS_IMPORTS):
                     suspicious_count += 1
                     
        elif hasattr(binary, 'libraries'):
             # Fallback: count linked libraries if function list isn't available
             n_imports = len(binary.libraries)
        
        # Exported functions (if present)
        n_exports = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0

        # Code signature presence (robust against different LIEF versions)
        has_sig = 0
        try:
            if binary.has_code_signature:
                has_sig = 1
            elif binary.code_signature_dir: 
                has_sig = 1
        except:
            has_sig = 0
        
        # Average section entropy as a measure of randomness/packing
        entropy = 0
        if binary.sections:
            entropy = np.mean([s.entropy for s in binary.sections])

        return [
            os.path.basename(filepath),
            size, n_sections, n_imports, suspicious_count, n_exports, has_sig, entropy, label
        ]

    except Exception:
        # Any parsing/analysis error -> skip this file
        return None


def process_and_save(root_folder, label, writer):
    """Walk `root_folder`, extract features for each file, and write to CSV.

    Skips common non-binary extensions and periodically triggers garbage collection
    when scanning large directories to keep memory usage bounded.
    """
    print(f"\n--- Scanning: {root_folder} (Label: {label}) ---")
    count = 0
    scanned = 0
    for root, dirs, files in os.walk(root_folder):
        for file in files:
            # Skip obviously non-binary/resource files
            if file.lower().endswith(('.txt', '.html', '.xml', '.png', '.plist', '.json', '.h', '.c')):
                continue
            
            file_path = os.path.join(root, file)
            scanned += 1
            features = extract_features(file_path, label)
            
            if features:
                writer.writerow(features)
                count += 1
                # Print progress occasionally for long runs
                if count % 50 == 0:
                    print(f"Success: {count} extracted...", end='\r')
            
            # Periodic garbage collection to free resources in large scans
            if scanned % 1000 == 0: gc.collect()

    print(f"\nFinished {root_folder}. Total Success: {count}")


if __name__ == "__main__":
    # Open CSV and process malware first then benign samples
    with open(OUTPUT_CSV, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        process_and_save(MALWARE_DIR, 1, writer)
        gc.collect()
        process_and_save(BENIGN_DIR, 0, writer)
    print(f"\nDone! CSV saved to {OUTPUT_CSV}")