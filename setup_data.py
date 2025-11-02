"""
Script to download all required data files for the Risk Assessment tool
Run this before running Service.py for the first time
"""

import os
import gzip
import requests
from pathlib import Path

# Create data directory if it doesn't exist
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

print("📁 Data directory created/verified")

def download_epss():
    """Download EPSS scores CSV with proper binary handling"""
    print("\n📥 Downloading EPSS scores (this may take a moment, it's ~50MB)...")
    
    # Try multiple sources
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
    


def download_and_convert_cwe():
    """Download CWE XML and convert to CSV"""
    
    print("📥 Downloading CWE data...")
    url = "http://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    
    try:
        # Download the ZIP file
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        print(f"✅ Downloaded ({len(response.content) / 1024 / 1024:.1f} MB)")
        
        # Extract XML from ZIP
        print("📦 Extracting ZIP...")
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            # Find the XML file (usually cwec_latest.xml or similar)
            xml_files = [f for f in z.namelist() if f.endswith('.xml')]
            if not xml_files:
                print("❌ No XML file found in ZIP")
                return False
            
            xml_filename = xml_files[0]
            print(f"   Found: {xml_filename}")
            
            with z.open(xml_filename) as xml_file:
                xml_content = xml_file.read()
        
        print("🔄 Parsing XML...")
        root = ET.fromstring(xml_content)
        
        # Find namespace
        namespace = {'cwe': 'http://cwe.mitre.org/cwe-7'}
        
        # Extract weaknesses
        weaknesses = root.findall('.//cwe:Weakness', namespace)
        print(f"   Found {len(weaknesses)} weaknesses")
        
        # Prepare CSV data
        csv_data = []
        headers = [
            'CWE-ID', 'Name', 'Abstraction', 'Structure', 'Status',
            'Description', 'Extended Description', 'Related Weaknesses',
            'Weakness Ordinalities', 'Applicable Platforms', 'Background Details',
            'Alternate Terms', 'Modes Of Introduction', 'Exploitation Factors',
            'Likelihood Of Exploit', 'Common Consequences', 'Detection Methods',
            'Potential Mitigations', 'Observed Examples', 'Functional Areas',
            'Affected Resources', 'Taxonomy Mappings', 'Related Attack Patterns',
            'Notes'
        ]
        
        for weakness in weaknesses:
            cwe_id = weakness.get('ID', '')
            name = weakness.get('Name', '')
            abstraction = weakness.get('Abstraction', '')
            structure = weakness.get('Structure', '')
            status = weakness.get('Status', '')
            
            # Description
            desc_elem = weakness.find('cwe:Description', namespace)
            description = desc_elem.text if desc_elem is not None else ''
            
            # Extended Description
            ext_desc_elem = weakness.find('cwe:Extended_Description', namespace)
            extended_description = ''
            if ext_desc_elem is not None:
                extended_description = ''.join(ext_desc_elem.itertext())
            
            # Common Consequences
            consequences = []
            for consequence in weakness.findall('.//cwe:Consequence', namespace):
                scope = consequence.find('cwe:Scope', namespace)
                impact = consequence.find('cwe:Impact', namespace)
                if scope is not None and impact is not None:
                    consequences.append(f"{scope.text}:{impact.text}")
            
            # Likelihood
            likelihood_elem = weakness.find('cwe:Likelihood_Of_Exploit', namespace)
            likelihood = likelihood_elem.text if likelihood_elem is not None else ''
            
            # Related Attack Patterns
            attack_patterns = []
            for pattern in weakness.findall('.//cwe:Related_Attack_Pattern', namespace):
                capec_id = pattern.get('CAPEC_ID', '')
                if capec_id:
                    attack_patterns.append(f"CAPEC-{capec_id}")
            
            csv_data.append({
                'CWE-ID': cwe_id,
                'Name': name,
                'Abstraction': abstraction,
                'Structure': structure,
                'Status': status,
                'Description': description.strip(),
                'Extended Description': extended_description.strip(),
                'Related Weaknesses': '',
                'Weakness Ordinalities': '',
                'Applicable Platforms': '',
                'Background Details': '',
                'Alternate Terms': '',
                'Modes Of Introduction': '',
                'Exploitation Factors': '',
                'Likelihood Of Exploit': likelihood,
                'Common Consequences': '::'.join(consequences),
                'Detection Methods': '',
                'Potential Mitigations': '',
                'Observed Examples': '',
                'Functional Areas': '',
                'Affected Resources': '',
                'Taxonomy Mappings': '',
                'Related Attack Patterns': ','.join(attack_patterns),
                'Notes': ''
            })
        
        # Write CSV
        output_path = DATA_DIR / "cwe.csv"
        print(f"💾 Writing CSV to {output_path}...")
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(csv_data)
        
        print(f"✅ CWE CSV created successfully!")
        print(f"   {len(csv_data)} records written")
        print(f"   File size: {output_path.stat().st_size / 1024:.1f} KB")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

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

    print("=" * 60)
    print("CWE Data Download and Conversion")
    print("=" * 60)
    
    success = download_and_convert_cwe()
    
    if success:
        print("\n✅ CWE data is ready!")
        print("   You can now run Service.py")
    else:
        print("\n❌ Failed to download/convert CWE data")
        print("   Try downloading manually from:")
        print("   https://cwe.mitre.org/data/downloads.html")