import gzip
import json
import re
from functools import lru_cache
from pathlib import Path

import datetime
import io
import pandas as pd
import requests

DIR_PATH = Path("data")
CAPEC_PATH = "capec.json"
EPSS_PATH = "epss_scores-current.csv"
CWE_PATH = "cwe.csv"
CAPEC_PATH = "capec.csv"
CVE_PATH = "cve"
CWE_PATH_LINK = "https://cwe.mitre.org/data/csv/1400.csv.zip"
# étape de récupération des informations
# epss
expertise_map = {"High": "Expert", "Medium": "Advanced", "Low": "Novice"}

# fonction
@lru_cache(maxsize=1)
def parse_nvd_json(year=None) -> pd.DataFrame:
    """
    Charge le JSON NVD et en extrait un DataFrame avec les métriques :
    - cve_id, description, publishedDate, lastModifiedDate
    - cvssV3.baseScore, cvssV3.vectorString
    - cwe_ids
    """
    if year is None:
        year = datetime.date.today().year
    #url = f"https://static.nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
    """url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    resp = requests.get(url)
    resp.raise_for_status()

    with gzip.open(io.BytesIO(resp.content), "rt", encoding="utf-8") as f:
        data = json.load(f)"""
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    resp = requests.get(url)
    resp.raise_for_status()

    # No gzip decompression - API returns plain JSON
    data = resp.json()

    records = []
    for item in data["vulnerabilities"]:
        meta = item["cve"]
        cve_id = meta["id"]

        # Description textuelle
        desc = item["cve"]["descriptions"]
        desc = next((d["value"] for d in desc if d["lang"] == "en"), "")

        # CVSSv3 si disponible
        metrics = item.get("impact", {}).get("baseMetricV3", {})
        cvss3 = metrics.get("cvssV3", {})
        base_score = cvss3.get("baseScore")
        vector_string = cvss3.get("vectorString")

        # Liste de CWE associées
        nodes = item["cve"].get("problemtype", {}).get("problemtype_data", [])
        cwes = []
        for n in nodes:
            for desc in n.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwes.append(val)

        if cvss3:
            attack =  {
                "attack_vector": cvss3.get("attackVector"),
                "attack_complexity": cvss3.get("attackComplexity"),
                "privilege_required": cvss3.get("privilegesRequired"),
                "user_interaction": cvss3.get("userInteraction"),
                "cvss_score": cvss3.get("baseScore"),
                "cvss_version": "3.x"
            }

        # 2) Fallback sur CVSS v2
        cvss2 = metrics.get("baseMetricV2", {}).get("cvssV2", {})
        if cvss2:
            attack = {
                "attack_vector": cvss2.get("accessVector"),
                "attack_complexity": cvss2.get("accessComplexity"),
                "privilege_required": cvss2.get("authentication"),
                "user_interaction": None,
                "cvss_score": cvss2.get("baseScore"),
                "cvss_version": "2.0"
            }
        else:
        # 3) Aucune métrique dispo
            attack =  {
            "attack_vector": "NETWORK",
            "attack_complexity": 'Low',
            "privilege_required": None,
            "user_interaction": None,
            "cvss_score": None,
            "cvss_version": None
            }
        records.append({
            "id": cve_id,
            "name": "none",
            "description": desc,
            "publishedDate": item.get("publishedDate"),
            "lastModified": item.get("lastModifiedDate"),
            "cvss3_score": base_score,
            "cvss3_vector": vector_string,
            "cwe_ids": cwes,
            "attack_vector": attack.get("attack_vector"),
            "attack_complexity": attack.get("attack_complexity"),
            "privilege_required": attack.get("privilege_required"),
            "user_interaction": attack.get("user_interaction"),
            "cvss_score": attack.get("cvss_score"),
            "cvss_version": attack.get("cvss_version"),

        })

    return pd.DataFrame(records)


def enrich_with_epss(nvd_df: pd.DataFrame, epss_df: pd.DataFrame) -> pd.DataFrame:
    return (
        nvd_df
        .merge(epss_df[["cve","epss"]], left_on="cve_id", right_on="cve", how="left")
        .drop(columns=["cve"])
    )

def parse_cwe(filepath):
    #wget https://cwe.mitre.org/data/csv/1400.csv.zip
    """Version améliorée qui gère dynamiquement le nombre de colonnes"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Étape 1: Analyse précise du fichier
    lines = []
    current_line = []
    in_quotes = False
    field = []

    for char in content:
        if char == '"':
            in_quotes = not in_quotes
        elif char == ',' and not in_quotes:
            current_line.append(''.join(field).strip())
            field = []
        elif char == '\n' and not in_quotes:
            current_line.append(''.join(field).strip())
            lines.append(current_line)
            current_line = []
            field = []
        else:
            field.append(char)

    # Étape 2: Trouver la ligne d'en-tête
    header = next((line for line in lines if 'CWE-ID' in line or 'Name' in line), None)
    if not header:
        raise ValueError("En-tête CWE introuvable dans le fichier")

    # Étape 3: Ajustement dynamique des colonnes
    max_cols = max(len(line) for line in lines)
    if len(header) < max_cols:
        header += [f'Extra_{i}' for i in range(len(header), max_cols)]

    # Étape 4: Filtrer les lignes de données
    data = [line for line in lines if line and line[0].isdigit()]

    # Étape 5: Création du DataFrame avec ajustement automatique
    return pd.DataFrame(data, columns=header[:max_cols])

def load_capec_correctly(filepath):
    # Étape 1: Lecture brute et nettoyage
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Étape 2: Reconstruction manuelle des lignes
    corrected_lines = []
    current_line = []
    in_quotes = False
    field_buffer = []

    for char in content:
        if char == '"':
            in_quotes = not in_quotes
        elif char == ',' and not in_quotes:
            current_line.append(''.join(field_buffer))
            field_buffer = []
        elif char == '\n' and not in_quotes:
            current_line.append(''.join(field_buffer))
            corrected_lines.append(current_line)
            current_line = []
            field_buffer = []
        else:
            field_buffer.append(char)

    # Étape 3: Trouver la ligne d'en-tête
    header = None
    data_lines = []
    for line in corrected_lines:
        if line[0].strip() == "'ID":
            header = line
        elif line[0].strip().isdigit():
            data_lines.append(line)

    # Étape 4: Création du DataFrame
    if header and data_lines:
        # Nettoyage des noms de colonnes
        clean_header = [col.strip("'\" ") for col in header]

        # Ajustement du nombre de colonnes
        max_cols = max(len(line) for line in data_lines)
        if len(clean_header) < max_cols:
            clean_header += [f'extra_{i}' for i in range(len(clean_header), max_cols)]

        return pd.DataFrame(data_lines, columns=clean_header)
    else:
        raise ValueError("Format de fichier CAPEC invalide")


cve_temp = None
@lru_cache(maxsize=1)
def load_data():
    global cve_temp

    epss_df = pd.read_csv(DIR_PATH / EPSS_PATH,skiprows=1, dtype= {'cve':str, 'epss':float, 'percentile':float}, low_memory=False)
    #epss_df = pd.read_csv(EPSS_PATH,skiprows=1, dtype= {'cve':str, 'epss':float, 'percentile':float}, low_memory=False)

    cve_df = parse_nvd_json(2025)
    #json_path = download_cve(datetime.date(2025,7,6))
    #nvd_df = parse_nvd_json(json_path)

    # cwe
    cwe_df = parse_cwe(DIR_PATH / CWE_PATH)


    if 'Extra_23' in cwe_df.columns:
        cwe_df = cwe_df.drop(columns=['Extra_23'])

    # Nettoyage des champs textuels
    text_cols = ['Description', 'Extended Description', 'Background Details']
    cwe_df[text_cols] = cwe_df[text_cols].apply(
        lambda x: x.str.replace('^::|::$', '', regex=True)
    )

    # capec
    #capec_df = pd.read_csv(DIR_PATH / CAPEC_PATH, header=None)
    capec_df = load_capec_correctly(DIR_PATH / CAPEC_PATH)
    if 'extra_20' in capec_df.columns:
        capec_df = capec_df.drop(columns=['extra_20'])

    # Nettoyage des champs textuels
    text_columns = ['Description', 'Execution Flow', 'Mitigations', 'Example Instances']
    capec_df[text_columns] = capec_df[text_columns].apply(
        lambda x: x.str.replace('^::|::$', '', regex=True)
    )

    #with open(DIR_PATH / "enterprise-attack.json", "r", encoding="utf-8") as f:
    #    mitre_data = json.load(f)
    #return cve_df,cwe_df,capec_df,mitre_data,epss_df






get_all_data = load_data()
def get_cve():
    return get_all_data[0]

def get_cwe():
    return get_all_data[1]

def get_capec():
    return get_all_data[2]

def get_mitre():
    return get_all_data[3]
def get_epss():
    return get_all_data[4]

techniques = None # mitre
techniques_capec = None # capec
techniques_cwe = None # cwe
techniques_cve = None # cve

@lru_cache(maxsize=1)
def set_techniques():
    global  techniques
    technique = []
    for obj in get_mitre()['objects']:
        if obj['type'] == 'attack-pattern':
            technique.append({
                'id': obj['external_references'][0]['external_id'],
                'name': obj['name'],
                'description': obj.get('description', ''),
                'tactic': [x['phase_name'] for x in obj.get('kill_chain_phases', [])]

            })
    techniques = pd.DataFrame(technique)
    return techniques

def set_capec():
    global  techniques_capec
    save =[]
    for _, row in get_capec().iterrows():
        for _, row in get_capec().iterrows():
            save.append({
        "id": row["ID"],
        "name": row["Name"],
        "description": str(row.get("Description", "")),
        "likelihood_of_attack": row.get("Likelihood Of Attack",None),
        "typical_severity": row.get("Typical Severity",None),
        "capec_consequences": row.get("Consequences",None),
        "attack_prerequisites": str(row.get("Prerequisites", ""))

            })
    techniques_capec = pd.DataFrame(save)

def set_cwe():
    global techniques_cwe
    techniques_cwe =  pd.DataFrame([{
        "id": row["CWE-ID"],
        "name": row["Name"],
        "description": str(row["Description"])
    } for _, row in get_cwe().iterrows()])

techniques_epss = None
def set_epss():
    global techniques_epss  # ← c’est bien techniques_epss
    epss_df = get_all_data[4]  # c’est le 5e élément de load_data()
    # si besoin, remets l’index cve en colonne
    if epss_df.index.name == 'cve':
        epss_df = epss_df.reset_index()

    techniques_epss = pd.DataFrame([{
        "id":          row["cve"],
        "epss":        row["epss"],
        "percentile":  row["percentile"]
    } for _, row in epss_df.iterrows()])


def get_all_epss():
    if techniques_epss is None:
        set_epss()
    return techniques_epss
def get_all_capec():
    if techniques_capec is None:
        set_capec()
    return techniques_capec

def get_all_cwe():
    if techniques_cwe is None:
        set_cwe()
    return techniques_cwe


def get_cve_description():
    return get_cve()['description']


def get_mitre_techniques():
    global techniques
    if techniques is None:
        set_techniques()
    return techniques

def get_technique_by_id(technique_id):
    technique_df = get_mitre_techniques()
    return technique_df[technique_df['id'] == technique_id].iloc[0].to_dict()


def get_all_mitre_description():
    return get_mitre_techniques()['description']

def get_all_capec_description():
    return get_all_capec()['description']

def get_all_cwe_description():
    return get_all_cwe()['description']

def extract_cve_cvss_fields(id_cve):
    """
    "cvss3_score": base_score,
    "cvss3_vector": vector_string,
    "cwe_ids": cwes,
    "attack_vector": attack.get("attack_vector"),
    "attack_complexity": attack.get("attack_complexity"),
    "privilege_required": attack.get("privilege_required"),
    "user_interaction": attack.get("user_interaction"),
    """
    cve_item = get_cve()[get_cve()['id'] ==  id_cve]

    return str(cve_item['attack_vector'].iloc[0]),str(cve_item['attack_complexity'].iloc[0]),str(cve_item['privilege_required'].iloc[0]),str(cve_item['user_interaction'].iloc[0])


def get_epss_score(id_cve):
    epss_df = get_all_epss()
    result  = epss_df[epss_df["id"] == id_cve]
    return float(result['epss'].iloc[0]),float(result['percentile'].iloc[0])


def parse_consequence(consequence_not_parsed):
    result = {}
    parts = [p for p in consequence_not_parsed.split("::SCOPE:") if p]
    for part in parts:
        scope, rest = part.split(":", 1)
        impacts = re.findall(r"TECHNICAL IMPACT:([^:]+)", rest)
        impacts = [imp.strip() for imp in impacts if imp.strip()]
        result[scope] = impacts
    return result


def get_capec_from_id(id_capec,name_capec):

    capec_df = get_all_capec()
    mask = ((capec_df["id"] == id_capec) & (capec_df['name'] == name_capec))
    res = capec_df.loc[mask]
    row = res.iloc[0]
    return row['likelihood_of_attack'],row['typical_severity'],parse_consequence(row['capec_consequences']), row['attack_prerequisites']

def parse_mitre_description(description):
    description = description.lower()

    # attack_vector
    if any(term in description for term in ["network", "remote", "rpc", "tcp", "internet"]):
        attack_vector = "NETWORK"
    elif any(term in description for term in ["local", "memory", "process", "window", "ewm", "injection"]):
        attack_vector = "Local"
    else:
        attack_vector = "NONE"

    # required_privileges
    if "elevated privileges" in description or "admin" in description or "root" in description:
        required_privileges = "High"
    elif "user" in description or "low privileges" in description:
        required_privileges = "Low"
    else:
        required_privileges = "none"

    # damage_potential (basic logic)
    if "access to memory" in description or "bypass" in description or "evade" in description:
        damage_potential = "High"
    elif "modification" in description:
        damage_potential = "Medium"
    else:
        damage_potential = "Low"

    # detectability
    if "evade detection" in description or "masked" in description or "avoid" in description:
        detectability = "Low"
    elif "monitor" in description or "logging" in description:
        detectability = "High"
    else:
        detectability = "Medium"

    return attack_vector, required_privileges, damage_potential, detectability


"""def parse_cwe_info(cwe_id):
    print(cwe_id)
    cwe_df = get_cwe()[get_cwe()['CWE-ID'] == cwe_id]
    row = cwe_df.iloc[0]
    operation_impact = 5
    consequences = str(row.get('Common Consequences', '')).lower()
    if 'high' in consequences or 'critical' in consequences:
        operation_impact = 8
    elif 'low' in consequences:
        operation_impact = 3
    
    necessary_material = 3
    factors = row['Exploitation Factors']
    if any('none' in f.lower() for f in factors):
        necessary_material = 1
    if any('specialized' in f.lower() for f in factors):
        necessary_material = 7
    return necessary_material,operation_impact"""

def extract_necessary_material(row):
    """
    Extract exploitation difficulty from multiple sources
    Score: 0-10 (0=impossible, 10=trivial)
    """
    score = 5  # Default: medium difficulty
    
    # Source 1: Exploitation Factors (if exists)
    exploit_factors = str(row.get('Exploitation Factors', '')).lower()
    if exploit_factors and exploit_factors != 'nan':
        if 'none' in exploit_factors or 'trivial' in exploit_factors:
            score = 9  # Very easy
        elif 'specialized' in exploit_factors or 'difficult' in exploit_factors:
            score = 3  # Hard
        elif 'standard' in exploit_factors:
            score = 6  # Moderate
    
    # Source 2: Description keywords (fallback)
    else:
        description = str(row.get('Description', '')).lower()
        # Easy to exploit indicators
        if any(word in description for word in ['trivial', 'simple', 'basic', 'common']):
            score = 8
        # Hard to exploit indicators
        elif any(word in description for word in ['complex', 'sophisticated', 'advanced', 'race condition']):
            score = 3
        # Moderate indicators
        elif any(word in description for word in ['improper', 'insufficient', 'missing']):
            score = 6
    
    return score


def extract_operation_impact(row):
    """
    Extract operational impact from Common Consequences
    Score: 0-10 (0=negligible, 10=catastrophic)
    
    Maps CWE Scope + Impact to numerical severity
    """
    consequences = str(row.get('Common Consequences', '')).lower()
    
    if not consequences or consequences == 'nan':
        # Fallback to description analysis
        return analyze_impact_from_description(row)
    
    # Impact severity mapping (OTA-focused)
    impact_scores = {
        # Critical impacts (OTA-relevant)
        'execute unauthorized code': 10,
        'execute code': 10,
        'gain privileges': 9,
        'bypass protection': 8,
        'modify files': 8,
        'modify memory': 8,
        'modify data': 8,
        
        # High impacts
        'read data': 7,
        'read files': 7,
        'read memory': 6,
        'denial of service': 6,
        'dos': 6,
        
        # Medium impacts
        'varies by context': 5,
        'other': 5,
        
        # Low impacts
        'read application data': 4,
        'hide activities': 3,
    }
    
    # Find highest severity impact mentioned
    max_score = 5  # Default
    for impact_phrase, score in impact_scores.items():
        if impact_phrase in consequences:
            max_score = max(max_score, score)
    
    # Scope multipliers (certain scopes are more critical for OTA)
    critical_scopes = ['integrity', 'access control'] #, 'confidentiality']
    for scope in critical_scopes:
        if scope in consequences:
            max_score = min(10, max_score + 1)  # Boost score
    
    return max_score


def analyze_impact_from_description(row):
    """
    Fallback: Analyze impact from description text
    """
    description = str(row.get('Description', '') + ' ' + row.get('Extended Description', '')).lower()
    
    # Critical keywords for OTA
    if any(word in description for word in ['execute', 'arbitrary code', 'remote code execution', 'privilege']):
        return 10
    elif any(word in description for word in ['memory corruption', 'overflow', 'injection']):
        return 8
    elif any(word in description for word in ['authentication', 'authorization', 'access control']):
        return 7
    elif any(word in description for word in ['information disclosure', 'leak', 'exposure']):
        return 6
    elif any(word in description for word in ['denial of service', 'crash', 'hang']):
        return 5
    else:
        return 5  # Default


def extract_detection_difficulty(row):
    """
    Extract detection difficulty
    Score: 0-10 (0=easy to detect, 10=hard to detect)
    
    For DREAD "Discoverability"
    """
    detection = str(row.get('Detection Methods', '')).lower()
    description = str(row.get('Description', '')).lower()
    
    # If detection methods are well-documented → easier to find
    if detection and detection != 'nan' and len(detection) > 50:
        if 'automated' in detection or 'scanner' in detection:
            return 3  # Easy to detect
        elif 'manual' in detection or 'code review' in detection:
            return 6  # Moderate
        else:
            return 5
    
    # Fallback: analyze from description
    if 'obvious' in description or 'easily detected' in description:
        return 2
    elif 'subtle' in description or 'difficult to detect' in description:
        return 8
    elif 'race condition' in description or 'timing' in description:
        return 9  # Very hard to detect
    else:
        return 5  # Default: moderate


def extract_exploit_likelihood(row):
    """
    Extract likelihood of exploitation
    Score: 0-10 (0=unlikely, 10=very likely)
    """
    likelihood = str(row.get('Likelihood Of Exploit', '')).lower()
    
    # Mapping from CWE qualitative values
    likelihood_map = {
        'very high': 10,
        'high': 8,
        'medium': 5,
        'low': 3,
        'very low': 1,
    }
    
    for key, value in likelihood_map.items():
        if key in likelihood:
            return value
    
    # Fallback: use CWE Top 25 rankings
    cwe_id = str(row.get('CWE-ID', ''))
    top_25_cwes = {
        '787': 10,  # Out-of-bounds Write
        '79': 9,    # XSS
        '89': 8,    # SQL Injection
        '20': 8,    # Improper Input Validation
        '125': 7,   # Out-of-bounds Read
        '78': 7,    # OS Command Injection
        '416': 7,   # Use After Free
        '22': 7,    # Path Traversal
        '352': 6,   # CSRF
        '434': 6,   # Unrestricted Upload
        '862': 6,   # Missing Authorization
        '476': 6,   # NULL Pointer Dereference
        '287': 8,   # Improper Authentication
        '190': 6,   # Integer Overflow
        '502': 7,   # Deserialization
        '77': 7,    # Command Injection
        '119': 8,   # Buffer Overflow
        '798': 7,   # Hardcoded Credentials
        '918': 6,   # SSRF
        '306': 6,   # Missing Authentication
    }
    
    if cwe_id in top_25_cwes:
        return top_25_cwes[cwe_id]
    
    return 5  # Default: medium likelihood


"""def adjust_for_ota_context(cwe_id, necessary_material, operation_impact, detection_difficulty, exploit_likelihood):
    
    Adjust scores for OTA update context in automotive
    
    OTA-critical CWEs get boosted scores
    
    # OTA-critical CWEs (authentication, crypto, updates)
    ota_critical_cwes = {
        '347': {'operation_impact': +2, 'exploit_likelihood': +1},  # Improper Crypto Signature
        '345': {'operation_impact': +2, 'exploit_likelihood': +1},  # Insufficient Verification
        '287': {'operation_impact': +2, 'exploit_likelihood': +1},  # Improper Authentication
        '295': {'operation_impact': +1, 'exploit_likelihood': +1},  # Improper Certificate Validation
        '326': {'operation_impact': +1},  # Inadequate Encryption
        '502': {'operation_impact': +3, 'exploit_likelihood': +2},  # Deserialization of Untrusted Data
        '20': {'operation_impact': +1},   # Improper Input Validation
        '798': {'operation_impact': +2, 'exploit_likelihood': +2},  # Hardcoded Credentials
        '494': {'operation_impact': +2},  # Download of Code Without Integrity Check
        '829': {'operation_impact': +1},  # Inclusion of Functionality from Untrusted Control Sphere
    }
    
    cwe_id_str = str(cwe_id)
    if cwe_id_str in ota_critical_cwes:
        adjustments = ota_critical_cwes[cwe_id_str]
        operation_impact = min(10, operation_impact + adjustments.get('operation_impact', 0))
        exploit_likelihood = min(10, exploit_likelihood + adjustments.get('exploit_likelihood', 0))
        print(f"   🚗 OTA context boost applied for CWE-{cwe_id}")
    
    return necessary_material, operation_impact, detection_difficulty, exploit_likelihood"""


def parse_cwe_info(cwe_id):
    """
    MAIN FUNCTION - Replace the old parse_cwe_info() with this
    
    Enhanced CWE parser that extracts quantitative metrics
    
    Args:
        cwe_id: CWE identifier (e.g., '79' or 'CWE-79')
        ota_context: Apply OTA-specific adjustments (default: True)
    
    Returns:
        necessary_material (0-10): Exploitation difficulty
        operation_impact (0-10): Operational/business impact
    """
    # Clean CWE ID
    cwe_id = str(cwe_id).replace('CWE-', '')
    
    print(f"📊 Parsing CWE-{cwe_id}...")
    
    # Get CWE data
    cwe_df = get_cwe()
    cwe_row = cwe_df[cwe_df['CWE-ID'] == cwe_id]
    
    if cwe_row.empty:
        print(f"   ⚠️  CWE-{cwe_id} not found in database, using defaults")
        return 5, 5  # Default values
    
    row = cwe_row.iloc[0]
    
    # Extract metrics
    necessary_material = extract_necessary_material(row)
    operation_impact = extract_operation_impact(row)
    detection_difficulty = extract_detection_difficulty(row)
    exploit_likelihood = extract_exploit_likelihood(row)
    
    
    # Log results
    print(f"   ✅ Necessary Material: {necessary_material}/10")
    print(f"   ✅ Operation Impact: {operation_impact}/10")
    print(f"   ✅ Detection Difficulty: {detection_difficulty}/10")
    print(f"   ✅ Exploit Likelihood: {exploit_likelihood}/10")
    

    return necessary_material, operation_impact


if __name__ == '__main__':
    print(get_cwe().head())