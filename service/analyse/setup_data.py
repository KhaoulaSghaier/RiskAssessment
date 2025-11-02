"""
Script to download all required data files for the Risk Assessment tool
Run this before running Service.py for the first time
"""

import os
import gzip
import requests
from pathlib import Path

# Create data directory 
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

print("📁 Data directory created/verified")

def download_epss():
    """Download EPSS scores CSV with proper binary handling"""
    print("\n📥 Downloading EPSS scores (this may take a moment, it's ~50MB)...")
    

    urls = [
        "https://epss.cyentia.com/epss_scores-current.csv.gz",
        "https://www.first.org/epss/epss_scores-current.csv.gz"
    ]
    
    for url in urls:
        try:
            print(f"   Trying: {url}")
            response = requests.get(url, timeout=60, stream=True)
            response.raise_for_status()
            
            # Save the .gz file first
            gz_path = DATA_DIR / "epss_scores-current.csv.gz"
            with open(gz_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            print(f"   ✅ Downloaded .gz file ({gz_path.stat().st_size / 1024 / 1024:.1f} MB)")
            
            # Now extract it properly
            print("   📦 Extracting...")
            output_path = DATA_DIR / "epss_scores-current.csv"
            
            with gzip.open(gz_path, 'rb') as f_in:
                with open(output_path, 'wb') as f_out:
                    # Write in chunks to handle large file
                    while True:
                        chunk = f_in.read(8192)
                        if not chunk:
                            break
                        f_out.write(chunk)
            
            # Verify the CSV file
            file_size = output_path.stat().st_size
            print(f"   ✅ Extracted CSV file ({file_size / 1024 / 1024:.1f} MB)")
            
            # Quick validation - read first few lines
            with open(output_path, 'r', encoding='utf-8') as f:
                first_lines = [f.readline() for _ in range(3)]
                if 'cve' in first_lines[0].lower() or 'cve' in first_lines[1].lower():
                    print("   ✅ File format looks correct!")
                    print(f"   First lines: {first_lines[0][:50]}...")
                else:
                    print("   ⚠️  Warning: File format may be incorrect")
            
            return True
            
        except Exception as e:
            print(f"   ❌ Failed: {e}")
            continue
    
    print("❌ All EPSS download sources failed")
    return False

def download_mitre_attack():
    """Download MITRE ATT&CK enterprise data"""
    print("\n📥 Downloading MITRE ATT&CK data...")
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        output_path = DATA_DIR / "enterprise-attack.json"
        with open(output_path, 'wb') as f:
            f.write(response.content)
        
        file_size = output_path.stat().st_size / 1024
        print(f"✅ MITRE ATT&CK data saved ({file_size:.1f} KB)")
        return True
    except Exception as e:
        print(f"❌ Failed to download MITRE ATT&CK: {e}")
        return False

def check_manual_files():
    """Check for files that need to be downloaded manually"""
    print("\n📋 Checking for manually downloaded files...")
    
    manual_files = {
        "cwe.csv": "Download from: https://cwe.mitre.org/data/downloads.html (CSV format)",
        "capec.csv": "Download from: https://capec.mitre.org/data/downloads.html (CSV format)"
    }
    
    missing = []
    for filename, instruction in manual_files.items():
        filepath = DATA_DIR / filename
        if filepath.exists() and filepath.is_file():
            file_size = filepath.stat().st_size / 1024
            print(f"✅ {filename} found ({file_size:.1f} KB)")
        else:
            print(f"⚠️  {filename} missing")
            print(f"   {instruction}")
            missing.append(filename)
    
    return missing

def verify_epss_file():
    """Verify EPSS file is actually a CSV and not corrupted"""
    epss_path = DATA_DIR / "epss_scores-current.csv"
    
    if not epss_path.exists():
        return False, "File does not exist"
    
    if epss_path.is_dir():
        return False, "Path is a directory, not a file! Please delete it and re-run."
    
    if epss_path.stat().st_size < 1000:
        return False, "File is too small (corrupted)"
    
    try:
        with open(epss_path, 'r', encoding='utf-8') as f:
            first_line = f.readline()
            if 'cve' not in first_line.lower():
                return False, "File doesn't contain expected CSV header"
        return True, "File looks valid"
    except Exception as e:
        return False, f"Error reading file: {e}"

if __name__ == "__main__":
    print("=" * 60)
    print("Risk Assessment Tool - Data Setup")
    print("=" * 60)
    
    # Check if EPSS already exists and is corrupted
    epss_path = DATA_DIR / "epss_scores-current.csv"
    if epss_path.exists():
        if epss_path.is_dir():
            print("\n⚠️  WARNING: epss_scores-current.csv is a FOLDER, not a file!")
            print("   This needs to be deleted first.")
            response = input("   Delete it now? (y/n): ")
            if response.lower() == 'y':
                import shutil
                shutil.rmtree(epss_path)
                print("   ✅ Deleted corrupted folder")
            else:
                print("   ❌ Please delete it manually and re-run this script")
                exit(1)
    
    # Download automated files
    epss_ok = download_epss()
    mitre_ok = download_mitre_attack()
    
    # Verify EPSS
    if epss_ok:
        valid, message = verify_epss_file()
        print(f"\n🔍 EPSS Verification: {message}")
    
    # Check manual files
    missing = check_manual_files()
    
    print("\n" + "=" * 60)
    print("Setup Summary:")
    print("=" * 60)
    
    if epss_ok and mitre_ok:
        print("✅ Automated downloads completed successfully")
    else:
        print("⚠️  Some automated downloads failed")
    
    if missing:
        print(f"⚠️  {len(missing)} file(s) need manual download:")
        for f in missing:
            print(f"   - {f}")
        print("\nℹ️  The tool will not work until all files are present")
    else:
        print("✅ All required files are present")
    
    print("\n🚀 Once all files are ready, you can run Service.py")
    print("=" * 60)