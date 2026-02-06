# Hybrid, adaptive, and automated risk analysis framework
An automated security risk analysis system based on the AutomotiveTD automotive database
CVE, CWE, and CAPEC are used as fallback resources when the confidence score is low.
 
# Objective
Ce système permet d'analyser automatiquement les risques de sécurité en croisant les données de différentes sources (CVE, CWE, CAPEC, MITRE ATT&CK) et en appliquant trois méthodes d'évaluation reconnues :

TARA (Threat Analysis and Risk Assessment)\
HARA (Hazard Analysis and Risk Assessment)\
DREAD (Damage, Affected Users)

# Prerequisites
Python 3.8+
pip (Python package manager)
Internet connection (to download databases)

# Installation

Clone the project

bashcd security-risk-analysis

# Install dependencies

bashpip install -r requirements.txt
requirements.txt file:

pandas>=1.5.0
numpy>=1.21.0
sentence-transformers>=2.2.0
scikit-learn>=1.1.0
requests>=2.28.0


Databases are directly stored in the repository in the data folder

# Usage
To use the program, simply navigate to the Service.py file
and use the provided main function.
All data retrieval methods are implemented in Utils.py
All methods for performing semantic analysis are in get_match.py
pythonfrom Service import get_analyse, analyse_automatique

# Provide the input
template_base = {
    'description': "Description of the vulnerability or attack",
    'safety_critical_update': True,  # If it's a critical update
    'vulnerability_location': "Cloud, edge, vehicle",  # "High", "Medium", "Low" of "affected_users" parameter
}

# Generate automatic analysis
python analyse_template = get_analyse(template_base)
print("Analysis template:", analyse_template)
Calculate final risk
pythonrisque_final = analyse_automatique(analyse_template).get_risk()
print("Final risk:", risque_final)
Concrete Example
python# Example of XSS vulnerability analysis
template_exemple = {
    'description': "The server 'ThingsBoard Server' could be a subject to a cross-site scripting attack that will compromise safety critical update by infecting the malware into the OTA source that could lead to modification of the metadata in the IPFS or the redirection of the downloading in malicious deposit",
    'safety_critical_update': True,
    'affected_user': "High",
    'knowlege_cible': "MEDIUM",
    'necessary_material': "MEDIUM",
}
Analysis
pythonresultat = get_analyse(template_exemple)  # returns the analysis template
risque = analyse_automatique(resultat).get_risk()  # returns the risk

print(f"Calculated risk: {risque}")
Analysis Methods
TARA (Threat Analysis and Risk Assessment)
Evaluates risks according to 4 impact criteria:

Safety: Impact on physical safety
Financial: Financial impact
Operational: Operational impact
Privacy: Privacy impact

HARA (Hazard Analysis and Risk Assessment)
Analysis based on 3 parameters:

Exposure: Exposure level
Controllability: Controllability level
Severity: Impact severity

DREAD
Evaluation according to 2 criteria:

Damage: Potential damage
Affected Users: Number of affected users


Advanced Configuration
Customizing mappings
You can modify the mappings in Service.py:
python# Mapping of necessary materials
material_map = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
}

analyser = analyse_automatique(test_case)
print("Test case risk:", analyser.get_risk())
```

Target knowledge mapping

# Project Structure
```
security-risk-analysis/
├── data/                          # Databases
│   ├── epss_scores-current.csv
│   ├── cwe.csv
│   ├── capec.csv
│   └── enterprise-attack.json
├── Service.py                     # Main entry point
├── analyse_automatique.py         # Analysis orchestrator
├── TARA.py                        # TARA implementation
├── HARA.py                        # HARA implementation
├── DREAD.py                       # DREAD implementation
├── capec_attack.py                # CAPEC data analysis
├── get_match.py                   # Semantic matching
├── utils.py                       # Utilities and data loading
├── *.npy                          # Saved embeddings of database descriptions
└── README.md                      # This file
```

# Input Parameters

## Base template

- **description**: Textual description of the vulnerability/attack
- **safety_critical_update**: Boolean - If it's a critical update
- **affected_user**: String - Number of affected users ("High", "Medium", "Low")
- **knowlege_cible**: String - Required knowledge level ("CRITICAL", "HIGH", "MEDIUM", "LOW")
- **necessary_material**: String - Necessary equipment ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Output

The system returns a final risk score which is the maximum of the three evaluation methods.

# Troubleshooting

## Common errors

### Missing data files
```
FileNotFoundError: [Errno 2] No such file or directory: 'data/...'
```
**Solution**: Verify that all data files are downloaded in the data/ folder

### Encoding issues
```
UnicodeDecodeError
```
**Solution**: Ensure that CSV files are encoded in UTF-8

### Network errors
```
requests.exceptions.ConnectionError
Solution: Check your Internet connection for CVE data download
Debug logs
Add logs to track execution:
pythonimport logging
logging.basicConfig(level=logging.DEBUG)


Risk 1: Low
Risk 2: Moderate
Risk 3: High
Risk 4: Critical
Risk 5: Very Critical
