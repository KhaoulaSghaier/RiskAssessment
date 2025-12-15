from service.analyse.analyse_automatique import analyse_automatique, RiskAggregator
from service.analyse import utils
from service.analyse.get_match import get_top_match
from service.analyse.capec_attack import *
from service.analyse.sdv_safety_classifier import auto_classify_safety_critical, SDVSafetyClassifier

material_map = {
    "CRITICICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
}


def SearchSimilar(query):
    """

    :param query: description à comparé
    :return: CVE, CWE, Mitre ATTAck et capec les plus proches
    """
    return get_top_match(query, utils.get_all_mitre_description(), utils.get_all_cwe_description(),
                          utils.get_all_capec_description(),utils.get_cve_description(),utils.get_mitre_techniques(), utils.get_all_capec(),
                          utils.get_all_cwe(),utils.get_cve(),top_value=1)


def get_analyse(template_base):
    """
    Enhanced version with automatic safety-critical classification
    
    NEW PARAMETERS in template_base:
        'sdv_zone': Optional[str] - 'powertrain', 'chassis', 'adas', 'infotainment', etc.
        'automotive_function': Optional[str] - 'braking', 'navigation', 'media_player', etc.
        'affected_ecus': Optional[List[str]] - List of ECU names affected
    
    The old 'safety_critical_update' parameter is now OPTIONAL and will be 
    automatically determined if not provided.
    
    # Parti analyse Traduction template
        'severity': CVE base_severity U CAPEC SEVERITY (Convertion high medium low à une catégorie) + (2 * safety_critical_update) + epss_score * 10
        'expertise':  U (CAPEC likehood_attack x)
        'exploitability' : EPSS percentile * 10
        'attack_discovery': CAPEC likehood
        'necessary_material': CVE mean(C,I,A) * 10/3
        'level_damage' (en gros le nombre d'utilisateur touché ): à voir
        'affected_user': (user_input affected_user)
        'operationnel_impact' : CWE
        'leak_information': capec Confidentiality en gros on regarde c'est quoi si il y a confidentiality et on set la valeur : "Unknown": 3, "Read Data": 4, "Disclosure": 5, "Bypass Security": 6, "Gain Privileges": 7,
        attack_vector : (user_input attack_verctor) U CVE attack_vector
        'attack_complexity" : CVE  "attackComplexity"
        "privilege_required": CVE privilegesRequired
        'user interaction': CVE userInteraction

    # Partie Analyse Traduction des valeurs
        'severity': 0-11                HARA SEVERITY | TARA (severity * 100) SAFETY |
        'expertise': "Expert" ...      DREAD = tara (moyenne knowledge and expertise) REPRODUCTIBILITY
        'exploitability': TARA
        'attack_discovery': 0-10        DREAD DISCOVERY
        'necessary_material': 0-10      DREAD EXPLOITABILITY
        'level_damage':  0-10           DREAD DAMAGE       | TARA (moyenne level_damage and operationnal_impact) financial
        'affected_user': 0-10           DREAD AFFECTED_USER
        'operationnel_impact': 0-10     TARA : (operationnel_impact * 15) OPERATIONNEL | HARA  si TARA [150 - 50] = 3 / [50-10] = 2 / [10,0] = 1 CONTROLABILITY
        'leak_information': 0- 10       TARA: (leak_information * 15) PRIVACY| HARA (leak_information * 4 / 10) EXPOSURE
        'attack_vector" :  "Network" "Adjacent" "Local" "Physical"             TARA V
        'attack_complexity": "High" "Low"    TARA C
        "privilege_required": "High" "Low" "None" TARA P
        'user interaction': "Required" "None" TARA U

    :return le template d'analyse
    """
    print("\n" + "="*60)
    print("STARTING RISK ANALYSIS WITH AUTO SAFETY CLASSIFICATION")
    print("="*60)
    
    # ====================================================================
    # AUTOMATIC SAFETY-CRITICAL CLASSIFICATION
    # ====================================================================
    if 'safety_critical_update' not in template_base or template_base['safety_critical_update'] is None:
        print("\n🤖 Auto-detecting safety criticality...")
        
        # Extract classification inputs
        description = template_base.get('description', '')
        sdv_zone = template_base.get('sdv_zone')
        automotive_function = template_base.get('automotive_function')
        affected_ecus = template_base.get('affected_ecus')
        
        # Run automated classification
        is_safety_critical = auto_classify_safety_critical(
            description=description,
            zone=sdv_zone,
            function=automotive_function,
            affected_user=template_base.get('affected_user'),
        )
        
        template_base['safety_critical_update'] = is_safety_critical
        
        if is_safety_critical:
            print("   🚨 CLASSIFIED AS: SAFETY-CRITICAL")
        else:
            print("   ✅ CLASSIFIED AS: NON-SAFETY-CRITICAL")
    else:
        print(f"\n⚙️  Using manual safety classification: {template_base['safety_critical_update']}")
    
    # ====================================================================
    # ORIGINAL ANALYSIS CONTINUES
    # ====================================================================
    
    # Obtention des informations similaire
    query = template_base['description']
    print(f"\n🔍 Query: {query[:100]}...")
    
    print("\n📡 Searching similar threats in databases...")
    getSimilar = SearchSimilar(query)
    
    # Print matches
    print("\n🎯 Top Matches Found:")
    print(f"   MITRE: {getSimilar[0]['id']} - {getSimilar[0]['name']}")
    print(f"   CAPEC: {getSimilar[1]['id']} - {getSimilar[1]['name']}")
    print(f"   CWE:   {getSimilar[2]['id']} - {getSimilar[2]['name']}")
    print(f"   CVE:   {getSimilar[3]['id']}")

    # Obtention des informations EPSS
    print("\n📈 Fetching EPSS scores...")
    try:
        epss, percentile = utils.get_epss_score(getSimilar[3]['id'])
        print(f"   ✅ EPSS: {epss:.4f}, Percentile: {percentile:.2f}")
    except Exception as e:
        print(f"   ⚠️  EPSS score not available: {e}")
        epss, percentile = 0.01, 0.5  # Default values

    # Obtention des informations CAPEC
    print("\n🎭 Parsing CAPEC data...")
    try:
        likehood, severity, consequence, prerequisite = utils.get_capec_from_id(
            getSimilar[1]['id'], getSimilar[1]['name']
        )
        getCapec = CapecAnalyze(severity, likehood, consequence)
        print(f"   ✅ CAPEC parsed successfully")
    except Exception as e:
        print(f"   ⚠️  CAPEC parsing error: {e}")
        # Use defaults
        getCapec = CapecAnalyze('Medium', 'Medium', {})

    # Obtention des informations Mitre
    print("\n⚔️  Parsing MITRE ATT&CK data...")
    try:
        mitre_attack_vector, mitre_required_privileges, mitre_damage_potential, mitre_detectability = \
            utils.parse_mitre_description(getSimilar[0]['description'])
        print(f"   ✅ MITRE parsed successfully")
    except Exception as e:
        print(f"   ⚠️  MITRE parsing error: {e}")
        mitre_attack_vector = 'NETWORK'
        mitre_required_privileges = 'Low'

    # Obtention des informations CVE
    print("\n🔐 Extracting CVE CVSS fields...")
    try:
        attack_vector, attack_complexity, privilege_required, user_interaction = \
            utils.extract_cve_cvss_fields(getSimilar[3]['id'])
        print(f"   ✅ CVE parsed successfully")
    except Exception as e:
        print(f"   ⚠️  CVE parsing error: {e}")
        attack_vector = 'None'
        attack_complexity = 'Low'
        privilege_required = 'None'
        user_interaction = 'None'

    # Obtention des informations CWE (ENHANCED!)
    print("\n🔬 Parsing CWE data with enhanced parser...")
    try:
        necessary_material, operation_impact = utils.parse_cwe_info(
            getSimilar[2]['id']
        )
    except Exception as e:
        print(f"   ⚠️  CWE parsing error: {e}")
        necessary_material = 5
        operation_impact = 5

    # Calculate final scores
    print("\n📊 Calculating risk scores...")
    
    map_affected_user = {
        'High': 10,
        'Medium': 6,
        'Low': 2
    }
    
    coef_affected_user = 1
    if template_base.get('safety_critical_update'):
        coef_affected_user = 2
        print("   ⚠️  Safety-critical update detected - severity doubled!")
    
    get_severity = coef_affected_user * getCapec.getSeverity()
    
    # Resolve attack vector and privileges
    elt1 = privilege_required
    if elt1 == 'None':
        elt1 = mitre_required_privileges
    
    elt2 = attack_vector
    if elt2 == 'None':
        elt2 = mitre_attack_vector

    # Build result
    result = {
        'severity': get_severity,
        'expertise': (getCapec.getLikehood() + necessary_material) / 2,
        'exploitability': max(epss * 10, 1),
        'attack_discovery': getCapec.getLikehood(),
        'knowledge_cible': material_map.get(template_base.get('knowlege_cible'), 5),
        'necessary_material': material_map.get(template_base.get('necessary_material'), 5),
        'level_damage': min(10, round((get_severity + operation_impact) / 2)),
        'affected_user': map_affected_user.get(template_base.get('affected_user'), 5),
        'operationnel_impact': operation_impact,
        'leak_information': getCapec.isConfenditalThreat(),
        'attack_vector': elt2,
        'attack_complexity': attack_complexity,
        "privileges_required": elt1,
        "user_interaction": user_interaction,
        "safety_critical_update": template_base.get('safety_critical_update')
    }
    
    print("\n✅ Analysis complete!")
    print("="*60)
    
    return result


if __name__ == '__main__':
    # ====================================================================
    # EXAMPLE 1: Automatic classification - Infotainment (non-critical)
    # ====================================================================
    print("\n" + "🧪 TEST 1: INFOTAINMENT XSS".center(60, "="))
    
    template_infotainment = {
        'description': "XSS vulnerability in the infotainment web-based management interface allowing script injection into the media player",
        
        # NEW: SDV context (auto-classification)
        'sdv_zone': 'infotainment',  # Will auto-detect as non-safety-critical
        'automotive_function': 'media_player',
        'affected_ecus': ['IVI-HEAD-UNIT', 'MEDIA-PROCESSOR'],
        
        # Traditional parameters
        'affected_user': 'High',
        'knowlege_cible': "LOW",
        'necessary_material': "LOW",
        
        # Note: safety_critical_update is NOT provided - will be auto-detected
    }
    
    result_1 = get_analyse(template_infotainment)
    print("\n📋 Analysis Result:", result_1)
    risk_level_1 = analyse_automatique(result_1).get_risk_level(
        analyse_automatique(result_1).get_risk()
    )
    print("🎯 Risk Level:", risk_level_1)
    
    # ====================================================================
    # EXAMPLE 2: Automatic classification - Braking system (CRITICAL)
    # ====================================================================
    print("\n\n" + "🧪 TEST 2: MALICIOUS BRAKE FIRMWARE".center(60, "="))
    
    template_braking = {
        'description': "Malicious OTA firmware update for the ABS braking control module allowing attacker to disable emergency braking",
        
        # NEW: SDV context (auto-classification)
        'sdv_zone': 'chassis',  # Will auto-detect as safety-critical
        'automotive_function': 'braking',
        'affected_ecus': ['ABS-ECU', 'BRAKE-CONTROL-UNIT'],
        
        # Traditional parameters
        'affected_user': 'High',
        'knowlege_cible': "HIGH",
        'necessary_material': "LOW",
    }
    
    result_2 = get_analyse(template_braking)
    print("\n📋 Analysis Result:", result_2)
    risk_level_2 = analyse_automatique(result_2).get_risk_level(
        analyse_automatique(result_2).get_risk()
    )
    print("🎯 Risk Level:", risk_level_2)
    
    # ====================================================================
    # EXAMPLE 3: Manual override (old behavior still works)
    # ====================================================================
    print("\n\n" + "🧪 TEST 3: MANUAL CLASSIFICATION".center(60, "="))
    
    template_manual = {
        'description': "Gateway authentication bypass vulnerability",
        
        # Manual override - old behavior
        'safety_critical_update': True,  # Explicitly set
        
        'affected_user': 'High',
        'knowlege_cible': "HIGH",
        'necessary_material': "MEDIUM",
    }
    
    result_3 = get_analyse(template_manual)
    print("\n📋 Analysis Result:", result_3)
    risk_level_3 = analyse_automatique(result_3).get_risk_level(
        analyse_automatique(result_3).get_risk()
    )
    print("🎯 Risk Level:", risk_level_3)
    
    # ====================================================================
    # EXAMPLE 4: original example (auto-classified)
    # ====================================================================
    print("\n\n" + "🧪 TEST 4: ORIGINAL EXAMPLE".center(60, "="))
    
    template_original = {
        'description': "Malicious OTA firmware update. This four-stage attack begins with the attacker gaining access to the backend OTA update server, replacing a legitimate HPC firmware update with a malicious version, and signing it with a stolen cryptographic key. The vehicle, trusting the valid signature, downloads and installs the malicious firmware via its external telematics cellular interface",
        
        # Add SDV context for better classification
        'sdv_zone': 'powertrain',  # HPC = High Performance Computer (likely powertrain/ADAS)
        'automotive_function': 'engine_control',
        
        'affected_user': 'High',
        'knowlege_cible': "HIGH",
        'necessary_material': "LOW",
    }
    
    result_4 = get_analyse(template_original)
    print("\n📋 Analysis Result:", result_4)
    risk_level_4 = analyse_automatique(result_4).get_risk_level(
        analyse_automatique(result_4).get_risk()
    )
    print("🎯 Risk Level:", risk_level_4)