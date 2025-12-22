import os
import lief
import sys
import numpy as np

# --- Dynamic Path Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def debug_file(filepath):
    print(f"\n--- Debugging File: {filepath} ---")
    
    if not os.path.exists(filepath):
        print("❌ Error: File not found!")
        return

    # 1. Check Magic Bytes (Signature)
    try:
        with open(filepath, 'rb') as f:
            header = f.read(4)
            print(f"Hex Header: {header.hex()}")
            # Check against standard Mach-O signatures
            if header in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xcf\xfa\xed\xfe']:
                print("✅ Magic Bytes: Valid Mach-O signature detected.")
            else:
                print("⚠️  Magic Bytes: NOT a standard Mach-O header (might be text/dat/xml).")
    except Exception as e:
        print(f"Error reading header: {e}")

    # 2. Attempt Analysis with LIEF
    try:
        binary = lief.parse(filepath)
        print(f"LIEF Object Type: {type(binary)}")
        
        if binary is None:
            print("❌ LIEF failed to parse this file (returned None).")
            return

        # Handle Fat Binaries (Universal Binaries)
        if isinstance(binary, list):
            print(f"ℹ️  Fat Binary detected with {len(binary)} architectures.")
            binary = binary[0]
            
        if not hasattr(binary, 'sections'):
            print("❌ Object exists but has no sections (probably not a binary executable).")
            return

        # 3. Attempt Data Extraction
        print("✅ LIEF parsed successfully! Extracting info:")
        print(f"   - Sections: {len(binary.sections)}")
        print(f"   - Imports: {len(binary.libraries)}")
        # Calculate entropy of sections as a sanity check
        entropy = np.mean([s.entropy for s in binary.sections]) if binary.sections else 0
        print(f"   - Entropy: {entropy:.4f}")
        
    except Exception as e:
        print(f"❌ CRITICAL ERROR during LIEF parsing: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Use path provided in the terminal
        target = sys.argv[1]
    else:
        # Default fallback path relative to the project structure
        target = os.path.join(BASE_DIR, "dataset", "benign", "ls")
    
    debug_file(target)