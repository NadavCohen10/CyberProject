# extract all compressed files in a directory recursively using 7zip ( p7zip-full must be installed )
# for the malware dataset that comprises .dmg, .pkg, .zip, .tar.gz, .xip files

import os
import subprocess

# הגדרת נתיב לתיקיית הנוזקות
MALWARE_DIR = os.path.expanduser("~/Desktop/CyberProject/dataset/malware")

def extract_archives(root_folder):
    print(f"--- Starting recursive extraction in: {root_folder} ---")
    count = 0
    
    for root, dirs, files in os.walk(root_folder):
        for file in files:
            file_path = os.path.join(root, file)
            
            # בדיקה אם זה קובץ מכווץ
            if file.endswith(('.dmg', '.pkg', '.zip', '.tar.gz', '.xip')):
                print(f"Extracting: {file}...")
                
                try:
                    # שימוש ב-7zip לחילוץ (מניח ש-p7zip-full מותקן)
                    # ה-flag -o מגדיר לחלץ לאותה תיקייה שבה הקובץ נמצא
                    # ה-flag -y מאשר דריסת קבצים אוטומטית אם צריך
                    subprocess.run(
                        ["7z", "x", file_path, f"-o{root}", "-y"], 
                        stdout=subprocess.DEVNULL, # הסתרת פלט רגיל
                        stderr=subprocess.PIPE     # תפיסת שגיאות
                    )
                    count += 1
                except Exception as e:
                    print(f"Failed to extract {file}: {e}")

    print(f"\nDone! Extracted {count} archives.")
    print("Run extract_features.py now!")

if __name__ == "__main__":
    extract_archives(MALWARE_DIR)