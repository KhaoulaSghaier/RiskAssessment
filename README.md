# Hybrid Adaptive OTA Risk Assessment Framework

An automated security risk assessment system for Software-Defined Vehicles (SDVs) combining TARA (ISO 21434), HARA (ISO 26262), and DREAD methodologies with context-aware adaptive aggregation.

## 🎯 Objective

This framework provides automated risk quantification for Over-The-Air (OTA) update vulnerabilities by:
- **Semantic threat matching** using transformer-based NLP (all-MPNet-base-v2)
- **Multi-methodology assessment** combining cybersecurity (TARA), functional safety (HARA), and fleet-scale impact (DREAD)
- **Context-aware aggregation** adapting risk scoring based on update criticality and vulnerability location
- **Automotive-specific intelligence** leveraging the Automotive Threat Database (ATD) as primary knowledge source

### Risk Assessment Methodologies

**TARA (Threat Analysis and Risk Assessment - ISO 21434)**
- Evaluates cyber threat severity across 4 impact dimensions: Safety, Financial, Operational, Privacy
- Uses ISO 21434 values and CVSS v3.1 exploitability metrics
- Output: Risk score [1.0-5.0]

**HARA (Hazard Analysis and Risk Assessment - ISO 26262)**
- Derives ASIL classification (QM/A/B/C/D) from Severity, Exposure, Controllability parameters
- Maps to functional safety requirements per ISO 26262 Table D.4
- Output: Risk score [1.0-5.0]

**DREAD (Simplified 2-Parameter)**
- **Damage Potential**: Consequence severity (0-10 scale)
- **Affected Users**: Fleet-scale exposure (0-10 scale), location-dependent
- Output: Risk score [1.0-5.0]

**Adaptive Aggregation**
- **Safety-Critical Updates**: 50% HARA + 25% TARA + 25% DREAD (emphasizes functional safety)
- **Non-Critical Updates**: 40% HARA + 40% TARA + 20% DREAD (balanced cyber/safety)

---

## 📋 Prerequisites

- Python 3.8+
- pip (Python package manager)
- Internet connection (for initial model download)

---

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/your-repo/ota-risk-assessment.git
cd ota-risk-assessment
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
pandas>=1.5.0
numpy>=1.21.0
sentence-transformers>=2.2.0
scikit-learn>=1.1.0
torch>=2.0.0
```

### 3. Verify database files
Ensure the following files are in the `service/analyse/` directory:
- `Automotive-threat-database.csv` (509 automotive vulnerabilities)
- `cve.csv` (fallback for low-confidence matches)
- `cwe.csv` (weakness patterns)
- `capec.csv` (attack patterns)

---

## 💻 Usage

### Command-Line Interface
```bash
py -3 -m service.analyse.Service \
  -s "Tesla Model 3 Gateway Firmware Signature Validation Bypass Vulnerability" \
  -t 0.8 \
  -d "service/analyse/Automotive-threat-database.csv" \
  --vuln-location cloud \
  --safety-critical
```

**Parameters:**
- `-s, --scenario`: Natural language description of the vulnerability
- `-t, --threshold`: ATD confidence threshold (default: 0.8)
- `-d, --database`: Path to ATD CSV file
- `--vuln-location`: Vulnerability location (`cloud`, `edge`, or `vehicle`)
- `--safety-critical`: Flag indicating safety-critical OTA update context (omit for non-critical)


## 📊 Output Example
```
================================================================================
ANALYZING THREAT SCENARIO
================================================================================
Query: Firmware Signature Validation Bypass Vulnerability
ATD Confidence Threshold: 0.8
Vulnerability Location: CLOUD
Update Criticality: SAFETY-CRITICAL
================================================================================

✅ ATD MATCH FOUND (High Confidence)
   Threat: ATD-37 - CVE-2023-32156
   Confidence: 0.8897 (88.97%)
   → Using ATD for risk parameter extraction

================================================================================
EXTRACTED RISK PARAMETERS
================================================================================
Extraction Method: ATD
--- CVSS Parameters ---
  Attack Vector: ADJACENT
  Attack Complexity: LOW
  Privileges Required: LOW
  User Interaction: NONE

--- Impact Flags ---
  Safety: Yes
  Financial: Yes
  Operational: Yes
  Privacy: Yes
  Systemic: Potentially Systemic

--- DREAD Parameters ---
  Damage: 10/10 (Safety-critical)
  Affected Users: 10/10 (Location: CLOUD)

================================================================================
RISK ASSESSMENT SCORES
================================================================================
🔍 HARA ISO Classes: S3 + E4 + C3

TARA (ISO 21434):
  Impact Sum: 2200 (Severe)
  Feasibility: 2.07 (Medium)
  TARA Risk Score: 4.0 / 5.0 (CRITICAL)

HARA (ISO 26262):
  ASIL Determination: (S3, E4, C3) → ASIL D
  HARA Risk Score: 5.0 / 5.0 (CRITICAL)

DREAD (Simplified):
  Damage: 10, Affected Users: 10
  Average: 10.0
  DREAD Risk Score: 5.0 / 5.0 (CRITICAL)

================================================================================
ADAPTIVE AGGREGATION (Safety-Critical: 50% HARA + 25% TARA + 25% DREAD)
================================================================================
  HARA Contribution: 0.50 × 5.0 = 2.50
  TARA Contribution: 0.25 × 4.0 = 1.00
  DREAD Contribution: 0.25 × 5.0 = 1.25

Final Aggregated Risk Score: 4.75 / 5.0
Risk Level: CRITICAL 🚨
Priority: 1 (Urgent response <7 days)

================================================================================
✅ ANALYSIS COMPLETE
================================================================================
```

---

## 🏗️ Project Structure
```
ota-risk-assessment/
├── service/
│   └── analyse/
│       ├── Service.py              # Main CLI entry point
│       ├── analyse_automatique.py   # Risk aggregation orchestrator
│       ├── TARA.py                  # TARA (ISO 21434) implementation
│       ├── HARA.py                  # HARA (ISO 26262) implementation
│       ├── dread.py                 # DREAD (2-parameter) implementation
│       ├── get_match_atd.py         # Semantic ATD matching (MPNet)
│       ├── utils.py                 # Database loading utilities
│       ├── Automotive-threat-database.csv  # Primary threat database
│       ├── cve.csv                  # Fallback vulnerability database
│       ├── cwe.csv                  # Weakness patterns
│       └── capec.csv                # Attack patterns
├── requirements.txt
└── README.md
```

---

## 🔬 Technical Details

### Semantic Threat Matching

**Model**: all-MPNet-base-v2 (768-dimensional sentence embeddings)
- Pre-trained on diverse domains with masked and permuted language modeling
- Cosine similarity matching across 509 ATD entries
- Confidence threshold filtering (default: 0.8)
- Fallback to CVE/CWE/CAPEC when ATD confidence is low

**Performance**: 88.97% average confidence on automotive vulnerability descriptions

### TARA Impact Extraction (ISO 21434)

**Discrete Values**:
- Safety: {0, 10, 100, 1000}
- Financial: {0, 10, 100, 1000}
- Operational: {0, 1, 10, 100}
- Privacy: {0, 1, 10, 100}

**Impact Rating**: Impact_rating → {Negligible (0), Moderate (1.0), Serious (1.5), Severe (2.0)}

**Feasibility**: CVSS v3.1 exploitability score (8.22 × AV × AC × PR × UI)

**Formula**: TARA_risk = 1 + (Impact_rating × Feasibility_rating)

### HARA Parameter Derivation (ISO 26262)

**Severity**: max(Safety_severity, Operational_severity) → {S0, S1, S2, S3}

**Exposure**: max(AV_exposure, Systemic_exposure) → {E1, E2, E3, E4}
- AV: NETWORK→10, ADJACENT→7, LOCAL→4, PHYSICAL→1
- Systemic: Potentially→10, Not→1

**Controllability**: UI → {C1, C2, C3}
- NONE→10 (C3), REQUIRED→2 (C1)

**ASIL Lookup**: ISO 26262 Table D.4 (S, E, C) → {QM, A, B, C, D}

**Formula**: HARA_risk = 1 + ASIL_numeric

### DREAD Fleet-Scale Quantification

**Damage**: {0, 5, 8, 9, 10} derived from Safety/Operational flags + CVSS impact score

**Affected Users**: {0, 2.5, 6, 8, 10} based on vulnerability location
- Cloud: 10 (fleet-wide OTA distribution)
- Edge: 6 (regional infrastructure)
- Vehicle: 2.5 (individual vehicle)

**Formula**: DREAD_risk = 1 + (Damage + Affected_Users) / 5

---

## 🎛️ Context-Aware Configuration

### Update Criticality Input

**Safety-Critical Updates** (e.g., ADAS brake patches):
```python
'safety_critical': True
# Triggers: 50% HARA + 25% TARA + 25% DREAD
```

**Non-Critical Updates** (e.g., infotainment features):
```python
'safety_critical': False
# Triggers: 40% HARA + 40% TARA + 20% DREAD
```

### Vulnerability Location Input
```python
'vulnerability_location': 'cloud'    # Entire fleet exposed (Affected Users = 10)
'vulnerability_location': 'edge'     # Regional impact (Affected Users = 6)
'vulnerability_location': 'vehicle'  # Individual vehicle (Affected Users = 2.5)
```

---

## 📈 Risk Classification

| Score Range | Classification | Priority | 
|-------------|---------------|----------|
| **4.0 - 5.0** | **CRITICAL** 🚨 | Priority 1 | 
| **3.0 - 4.0** | **HIGH** 🔴 | Priority 2 | 
| **2.0 - 3.0** | **MEDIUM** 🟠 | Priority 3 | 
| **1.0 - 2.0** | **LOW** 🟡 | Priority 4 |



## 📚 References

- ISO/SAE 21434:2021 - Road vehicles — Cybersecurity engineering
- ISO 26262:2018 - Road vehicles — Functional safety
- ISO 24089:2023 — Road vehicles — Software update engineering
- CVSS v3.1 Specification - Common Vulnerability Scoring System
- Automotive Threat Database (ATD) - [https://github.com/anonymous/ATD](https://github.com/jayaratned/AutomotiveTD)

