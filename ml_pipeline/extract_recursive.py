# extract all compressed files in a directory recursively using 7zip ( p7zip-full must be installed )
# for the malware dataset that comprises .dmg, .pkg, .zip, .tar.gz, .xip files

import os
import subprocess

# Get the directory where this script is located
SCRIPT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))


# Assumes the folder structure: CyberProject/data/samples/malware
MALWARE_DIR = os.path.join(SCRIPT_DIR, "data", "smapes", "malware")

def extract_archives(root_folder):
    print(f"--- Starting recursive extraction in: {root_folder} ---")
    count = 0
    
    for root, dirs, files in os.walk(root_folder):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Check if the file is a compressed archive
            if file.endswith(('.dmg', '.pkg', '.zip', '.tar.gz', '.xip')):
                print(f"Extracting: {file}...")
                
                try:
                    # Use 7zip for extraction (assumes p7zip-full is installed)
                    subprocess.run(
                        ["7z", "x", file_path, f"-o{root}", "-y"], 
                        stdout=subprocess.DEVNULL, # Hide standard output
                        stderr=subprocess.PIPE     # Capture errors
                    )
                    count += 1
                except Exception as e:
                    print(f"Failed to extract {file}: {e}")

    print(f"\nDone! Extracted {count} archives.")
    print("Run extract_features.py now!")

if __name__ == "__main__":
    extract_archives(MALWARE_DIR)