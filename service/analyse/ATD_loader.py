import pandas as pd
import os

def load_automotive_threat_database(csv_path):
    """
    Load the Automotive Threat Database from CSV file
    :param csv_path: Path to the Automotive-threat-database.csv file
    :return: pandas DataFrame with the threat data
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"ATD database not found at: {csv_path}")
    
    # Load CSV - try different separators and encodings
    try:
        df = pd.read_csv(csv_path)
    except:
        try:
            df = pd.read_csv(csv_path, sep='\t')
        except:
            df = pd.read_csv(csv_path, encoding='latin-1')
    
    # Clean and prepare data
    df = df.fillna('')
    
    # Ensure required columns exist
    required_cols = ['ATD_ID2', 'Description']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns in ATD: {missing_cols}")
    
    return df

def prepare_atd_for_embedding(df):
    """
    Prepare ATD DataFrame for embedding generation
    :param df: ATD DataFrame
    :return: tuple of (descriptions list, dataframe)
    """
    # Use Description column for embeddings
    descriptions = df['Description'].fillna('').tolist()
    
    return descriptions, df

def load_and_prepare_atd(csv_path):
    """
    Load and prepare ATD database in one step
    :param csv_path: Path to the Automotive-threat-database.csv file
    :return: tuple of (descriptions list, dataframe)
    """
    df = load_automotive_threat_database(csv_path)
    return prepare_atd_for_embedding(df)


# Example usage and column mapping documentation
ATD_COLUMN_MAPPING = {
    # Core identification
    'ATD_ID2': 'Automotive Threat Database ID',
    'CVE_ID': 'Common Vulnerabilities and Exposures ID',
    'AAD_ID': 'Automotive Attack Database ID',
    'Description': 'Threat description',
    'Reference': 'Reference URL or paper',
    'Published_year': 'Year of publication',
    
    # Impact flags (Yes/No or empty)
    'Safety': 'Safety impact flag',
    'Financial': 'Financial impact flag',
    'Operational': 'Operational impact flag',
    'Privacy': 'Privacy impact flag',
    'Systemic': 'Systemic impact (Potentially Systemic, Not Systemic)',
    
    # CWE information
    'CWE_ID': 'Common Weakness Enumeration ID',
    
    # CVSS 3.x metrics
    'CVSS3.x_vector_string': 'CVSS 3.x vector string',
    '3_Base_score': 'CVSS 3.x base score',
    '3_Exploitability_score': 'CVSS 3.x exploitability score',
    '3_Impact_score': 'CVSS 3.x impact score',
    'Attack_vector': 'Attack vector (N/A/L/P)',
    
    # CVSS 2.0 metrics (legacy)
    'CVSS_2.0_vector_string': 'CVSS 2.0 vector string',
    '2_Base_score': 'CVSS 2.0 base score',
    '2_Exploitability_score': 'CVSS 2.0 exploitability score',
    '2_Impact_score': 'CVSS 2.0 impact score',
    
    # Database source
    'Database': 'Source database (NVD, AAD)',
    
    # Additional AAD columns
    'CVE_ID_other': 'Alternative CVE ID',
    'Attack Base': 'Attack base category',
    'Attack Type': 'Type of attack',
    'Violated Security Property': 'Security property violated',
    'Interface': 'Interface targeted',
    'Consequence': 'Attack consequence',
    'Component': 'Affected component'
}

# CVSS Attack Vector mapping
ATTACK_VECTOR_MAP = {
    'N': 'NETWORK - Attack can be performed remotely',
    'A': 'ADJACENT - Attack requires access to local network',
    'L': 'LOCAL - Attack requires local access',
    'P': 'PHYSICAL - Attack requires physical access'
}

# CVSS Attack Complexity mapping
ATTACK_COMPLEXITY_MAP = {
    'L': 'LOW - No special conditions',
    'H': 'HIGH - Requires special conditions'
}

# CVSS Privileges Required mapping
PRIVILEGES_REQUIRED_MAP = {
    'N': 'NONE - No privileges required',
    'L': 'LOW - Basic user privileges',
    'H': 'HIGH - Administrative privileges'
}

# CVSS User Interaction mapping
USER_INTERACTION_MAP = {
    'N': 'NONE - No user interaction',
    'R': 'REQUIRED - Requires user interaction'
}