
from analyse_automatique import analyse_automatique
from service.analyse import utils
from service.analyse.get_match import get_top_match
from capec_attack import *

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
    # Obtention des informations similaire
    query = template_base['description']
    getSimilar = SearchSimilar(query)

    # Obtention des informations EPSS
    print(getSimilar)
    epss, percentile =  utils.get_epss_score(getSimilar[3]['id'])

    # Obtention des informations CAPEC
    likehood,severity,consequence,prerequisite = utils.get_capec_from_id(getSimilar[1]['id'],getSimilar[1]['name'])

    getCapec = CapecAnalyze(severity,likehood,consequence)

    # Obtention des informations Mitre
    mitre_attack_vector, mitre_required_privileges, mitre_damage_potential, mitre_detectability = utils.parse_mitre_description(getSimilar[0]['description'])


    # Obtention des informations  CVE
    attack_vector,attack_complexity, privilege_required, user_interaction = utils.extract_cve_cvss_fields(getSimilar[3]['id'])
    necessary_material, operation_impact = utils.parse_cwe_info(getSimilar[2]['id'])

    map_affected_user = {
        'High': 10,
        'Medium':6,
        'Low':2
    }
    coef_affected_user = 1
    if template_base.get('safety_critical_update'):
        coef_affected_user = 2
    get_severity = coef_affected_user * getCapec.getSeverity()
    elt1 = privilege_required
    if elt1 == 'None':
        elt1 = mitre_required_privileges
    elt2 = attack_vector
    if elt2 == 'None':
        elt2 = mitre_attack_vector

    return {
        'severity':  get_severity,
        'expertise': (getCapec.getLikehood() + necessary_material)/2,
        'exploitability': max(epss * 10,1),
        'attack_discovery': getCapec.getLikehood(),
        'knowledge_cible':material_map.get(template_base.get('knowlege_cible')),
        'necessary_material': material_map.get(template_base.get('necessary_material')),
        'level_damage': 10 if (round((get_severity + operation_impact) /2)) > 10 else (round((get_severity + operation_impact) /2)),
        'affected_user': map_affected_user.get(template_base.get('affected_user')),
        'operationnel_impact': operation_impact,
        'leak_information': getCapec.isConfenditalThreat() ,
        'attack_vector': elt2,
        'attack_complexity': attack_complexity,
        "privileges_required": elt1,
        "user_interaction":   user_interaction,
    }



if __name__ == '__main__':
    template_base = {
        'description':"The server 'ThingsBoard Server' could be a subject to a cross-site scripting attack that will compromise safety critical update by infecting the malware into the OTA source  that could lead to modification of the  metadata in the IPFS or the redirection of the downloading in malicious deposit",
        'safety_critical_update': True,
        'affected_user': "High", # "High" "Medium" "Low"
        'knowlege_cible': "MEDIUM",
        'necessary_material': "MEDIUM",
    }
    get_analyse_template = get_analyse(template_base)
    print("template d'analyse :", get_analyse_template)
    print("Risque associé :", analyse_automatique(get_analyse_template).get_risk())