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

## 📋 Requirements
- **Docker Desktop installed and running.** On Windows/Mac, open Docker Desktop and
  wait until it shows **"Engine running"** before running any command below.
- ~4 GB free disk, 4 GB RAM, no GPU needed.

---

## 🚀 Running code

### 1. Clone the repository
```bash
git clone -b OTARS-ATD https://github.com/KhaoulaSghaier/RiskAssessment
cd RiskAssessment
```
### 2. Build the image 
```bash
docker build -t otarq .
```
This downloads Python, the dependencies, and the all-mpnet-base-v2 model, and
packages everything with the code.

### 3. Start the container
```bash
docker run --rm -it otarq
```
This drops you into a shell inside the `PST26/` folder, ready to run the tool.

### 4. Run an analysis
```bash
python -m service.analyse.Service \
  -s "Gateway Firmware Signature Validation Bypass" \
  -t 0.8 \
  -d service/analyse/Automotive-threat-database.csv
```
This matches the input threat against the Automotive Threat Database and prints
the semantic match and the computed risk score.


## 💻 Usage

### Command-Line Interface
```bash
cd PST26
python -m service.analyse.Service \
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
======================================================================
OTARQ — AUTOMATED OTA RISK QUANTIFICATION
======================================================================
Query              : Tesla Model 3 Gateway Firmware Signature Validation Bypass Vulnerability
Confidence threshold: 0.8
Vulnerability layer : CLOUD
Safety-critical     : YES
======================================================================

Searching Automotive Threat Database...
  Loaded ATD: 509 entries
Warning: You are sending unauthenticated requests to the HF Hub. Please set a HF_TOKEN to enable higher rate limits and faster downloads.
Loading weights: 100%|██████████████████████████████████████████████████████████████| 199/199 [00:00<00:00, 469.16it/s]
Batches: 100%|███████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00,  5.20it/s]

   🔍 DEBUG get_dread_damage():
      safety_flag: 'Yes' (type: <class 'str'>)
      operational_flag: 'Yes' (type: <class 'str'>)
      impact_score: 6.0 (type: <class 'float'>)
      ✓ Safety=Yes branch
      ✓ impact_score >= 5.0 → damage = 10

  Top match : ATD-37 — CVE-2023-32156
  Confidence: 0.8608

  Match accepted — extracting risk parameters from ATD entry.

======================================================================
EXTRACTED RISK PARAMETERS
======================================================================

  CVSS Exploitability
    Attack Vector      : ADJACENT
    Attack Complexity  : LOW
    Privileges Required: LOW
    User Interaction   : NONE

  TARA Impact (ISO/SAE 21434)
    Safety             : 1000
    Financial          : 1000
    Operational        : 100
    Privacy            : 100

  HARA Parameters (ISO 26262)
    Severity           : 10/10  → S3
    Exposure           : 10/10  → E4
    Controllability    : 10/10  → C3

  DREAD Parameters
    Damage potential   : 10/10
    Affected users     : 10/10  (layer: cloud)

======================================================================
RISK ASSESSMENT
======================================================================
   🔍 HARA ISO Classes: f(S3,E4,C3)

======================================================================
   TARA PARAMETER BREAKDOWN
======================================================================

   📊 IMPACT SCORES (Discrete ISO 21434 Values):
      Safety:       1000  🔴
      Financial:    1000  🔴
      Operational:   100  🔴
      Privacy:       100  🔴

      Impact Sum:   2200  (max: 2200)
      Impact Level: Severe
      Impact Rating: 2

   🎯 FEASIBILITY PARAMETERS (CVSS v3.1):
      Attack Vector (AV):        ADJACENT   → weight: 0.62
      Attack Complexity (AC):    LOW        → weight: 0.77
      Privileges Required (PR):  LOW        → weight: 0.62
      User Interaction (UI):     NONE       → weight: 0.85

      Exploitability Score: 2.07  (formula: 8.22 × 0.62 × 0.77 × 0.62 × 0.85)
      Feasibility Rating:   1.5
      Feasibility Level:    Low

   🎯 TARA FINAL RISK:
      Formula: 1 + (Impact × Feasibility)
      Risk = 1 + (2 × 1.5)
      TARA Risk Score: 4.0 / 5.0
      Classification: 🔴 CRITICAL
======================================================================

   🔍 DREAD Calculation:
      Damage: 10
      Affected Users: 10
      Average: 10.00
      Risk (normalized [1,5]): 5.00
HARA: 5
TARA: 4.0
DREAD 5.0

  Final risk score : 4.75 / 5.0
  Risk level       : CRITICAL 🚨
  Priority         : 1

======================================================================
ANALYSIS COMPLETE  (3.593 s)
======================================================================
  Risk level : CRITICAL 🚨
  Risk score : 4.75 / 5.0
```



---

## 🏗️ Project Structure
```
RiskAssessment/
├─PST26
|___|_automotive_embedding.npy
|___|_service/
│   └── analyse/
│       ├── Service.py              # Main CLI entry point
│       ├── analyse_automatique.py   # Risk aggregation orchestrator
│       ├── TARA.py                  # TARA (ISO 21434) implementation
│       ├── HARA.py                  # HARA (ISO 26262) implementation
│       ├── dread.py                 # DREAD (2-parameter) implementation
│       ├── get_match_atd.py         # Semantic ATD matching (MPNet)
│       ├── utils.py                 # Database loading utilities
│       ├── Automotive-threat-database.csv  # Primary threat database
|       |__threshold.py
├── requirements.txt
|__ Dockerfile
└── README.md
```

---

## 🔬 Technical Details

### Semantic Threat Matching

**Model**: all-MPNet-base-v2 (768-dimensional sentence embeddings)
- Pre-trained on diverse domains with masked and permuted language modeling
- Cosine similarity matching across 509 ATD entries
- Confidence threshold filtering (default: 0.8)
- Flag expert review when ATD confidence is low

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

| Score Range | Classification | 
|-------------|---------------|
| **4.0 - 5.0** | **CRITICAL** 🚨 | 
| **3.0 - 4.0** | **HIGH** 🔴 | 
| **2.0 - 3.0** | **MEDIUM** 🟠 | 
| **1.0 - 2.0** | **LOW** 🟡 | 



## 📚 References

- ISO/SAE 21434:2021 - Road vehicles — Cybersecurity engineering
- ISO 26262:2018 - Road vehicles — Functional safety
- ISO 24089:2023 — Road vehicles — Software update engineering
- CVSS v3.1 Specification - Common Vulnerability Scoring System
- Automotive Threat Database (ATD) - [https://github.com/anonymous/ATD](https://github.com/jayaratned/AutomotiveTD)

