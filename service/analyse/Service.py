
from service.analyse.analyse_automatique import analyse_automatique
from service.analyse import utils
from service.analyse.get_match import get_top_match
from service.analyse.capec_attack import *

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
    print("STARTING RISK ANALYSIS")
    print("="*60)
    
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
    print("\n Parsing MITRE ATT&CK data...")
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
        print(f"CVE parsing error: {e}")
        attack_vector = 'None'
        attack_complexity = 'Low'
        privilege_required = 'None'
        user_interaction = 'None'

    # Obtention des informations CWE (ENHANCED!)
    print("\n Parsing CWE data with enhanced parser...")
    try:
        #Pass ota_context=True for OTA-specific adjustments
        necessary_material, operation_impact = utils.parse_cwe_info(
            getSimilar[2]['id'],
            ota_context=True  # Enable OTA adjustments
        )
    except Exception as e:
        print(f"CWE parsing error: {e}")
        necessary_material = 5
        operation_impact = 5

    # Calculate final scores
    print("\n Calculating risk scores...")
    
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
    }
    
    print("\n✅ Analysis complete!")
    print("="*60)
    
    return result



if __name__ == '__main__':
    template_base = {
        'description':"The server 'ThingsBoard Server' could be a subject to a cross-site scripting attack that will compromise safety critical update by infecting the malware into the OTA source that could lead to modification of the  metadata in the IPFS or the redirection of the downloading in malicious deposit",
        #'description': "A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an authenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of the interface. The vulnerability is due to insufficient input validation of user-supplied data. An attacker could exploit this vulnerability by sending a crafted HTTP request to the web-based management interface. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or access sensitive browser-based information.",
        #'description': "A debug/diagnostic HTTP endpoint on the vehicle’s infotainment module exposes OTA metadata (current version, staged rollout flags, scheduled update times, CDN URLs, partial hashes) without authentication when queried from the vehicle’s local network (e.g., passenger Wi-Fi or Bluetooth-tethered phone). The endpoint does not allow uploading or triggering updates — it only reveals metadata",
        #'description': "The infotainment unit fetches OTA manifests (or parts of them) from an update CDN using plain HTTP (no TLS) while connected to the vehicle’s passenger Wi-Fi / hotspot. An attacker on the same Wi-Fi/AP can perform ARP spoofing or a rogue AP attack and tamper with or replay manifest responses (metadata only — signatures are validated by the client, so binary substitution is not possible).",
        'safety_critical_update': True,
        'affected_user': 'High', # "High" "Medium" "Low"
        'knowlege_cible': "LOW",
        'necessary_material': "LOW",
    }
    get_analyse_template = get_analyse(template_base)
    print("template d'analyse :", get_analyse_template)
    print("Risque associé :", analyse_automatique(get_analyse_template).get_risk())