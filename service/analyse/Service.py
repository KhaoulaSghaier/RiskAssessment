from service.analyse.analyse_automatique import analyse_automatique, RiskAggregator
from service.analyse import utils
from service.analyse.get_match import get_top_match, calculate_overall_confidence, get_confidence_level
from service.analyse.capec_attack import *
import argparse
import sys


material_map = {
    "CRITICAL": 2,
    "HIGH": 4,
    "MEDIUM": 6,
    "LOW": 8,
    "VERY_LOW": 10
}


def SearchSimilar(query):
    """
    :param query: description à comparé
    :return: Dictionary with top-3 matches per database with confidence scores
    """
    return get_top_match(query, utils.get_all_mitre_description(), utils.get_all_cwe_description(),
                          utils.get_all_capec_description(), utils.get_cve_description(), utils.get_mitre_techniques(), 
                          utils.get_all_capec(), utils.get_all_cwe(), utils.get_cve(), top_value=3)


def get_analyse(template_base):
    print("\n" + "="*60)
    print("STARTING RISK ANALYSIS")
    print("="*60)
    
    # Initialize review tracking
    flag_for_review = False
    review_reasons = []
    default_values_used = []
    
    def add_default_flag(field_name, default_value, reason):
        """Track when default values are assigned due to extraction failure"""
        nonlocal flag_for_review, review_reasons, default_values_used
        flag_for_review = True
        message = f"⚠️  Default value assigned: '{field_name}' = {default_value} - {reason}"
        review_reasons.append(message)
        default_values_used.append({
            'field': field_name,
            'value': default_value,
            'reason': reason
        })
        print(message)
    
    # Search similar threats
    query = template_base['description']
    print(f"\n🔍 Query: {query[:100]}...")
    
    print("\n📡 Searching similar threats in databases...")
    getSimilar = SearchSimilar(query)
    
    # Calculate overall confidence
    overall_confidence = calculate_overall_confidence(getSimilar)
    confidence_level, confidence_desc = get_confidence_level(overall_confidence)
    
    # Print top 3 matches
    print("\n🎯 Top 3 Matches Found:")
    print("\n📊 MITRE ATT&CK:")
    for match in getSimilar['mitre']:
        print(f"   #{match['rank']} {match['id']} - {match['name'][:60]}")
        print(f"       Confidence: {match['confidence']:.3f} ({match['confidence']*100:.1f}%)")
    
    print("\n🎭 CAPEC:")
    for match in getSimilar['capec']:
        print(f"   #{match['rank']} {match['id']} - {match['name'][:60]}")
        print(f"       Confidence: {match['confidence']:.3f} ({match['confidence']*100:.1f}%)")
    
    print("\n🛡️ CWE:")
    for match in getSimilar['cwe']:
        print(f"   #{match['rank']} {match['id']} - {match['name'][:60]}")
        print(f"       Confidence: {match['confidence']:.3f} ({match['confidence']*100:.1f}%)")
    
    print("\n🔐 CVE:")
    for match in getSimilar['cve']:
        print(f"   #{match['rank']} {match['id']}")
        print(f"       Confidence: {match['confidence']:.3f} ({match['confidence']*100:.1f}%)")
    
    print(f"\n📈 Overall Confidence: {overall_confidence:.3f} ({confidence_level})")
    print(f"   {confidence_desc}")
    
    # Use top matches (rank 1)
    top_mitre = getSimilar['mitre'][0]
    top_capec = getSimilar['capec'][0]
    top_cwe = getSimilar['cwe'][0]
    top_cve = getSimilar['cve'][0]

    # EPSS scores
    print("\n📈 Fetching EPSS scores...")
    try:
        epss, percentile = utils.get_epss_score(top_cve['id'])
        print(f"   ✅ EPSS: {epss:.4f}, Percentile: {percentile:.2f}")
    except Exception as e:
        print(f"   ⚠️  EPSS score not available: {e}")
        epss, percentile = 0.01, 0.5
        add_default_flag('epss_score', epss, 'EPSS data unavailable from API')
        add_default_flag('epss_percentile', percentile, 'EPSS data unavailable from API')

    # CAPEC parsing
    print("\n🎭 Parsing CAPEC data...")
    try:
        likehood, severity, consequence, prerequisite = utils.get_capec_from_id(
            top_capec['id'], top_capec['name']
        )
        getCapec = CapecAnalyze(severity, likehood, consequence)
        print(f"   ✅ CAPEC parsed successfully")
    except Exception as e:
        print(f"   ⚠️  CAPEC parsing error: {e}")
        getCapec = CapecAnalyze('Medium', 'Medium', {})
        add_default_flag('capec_severity', 'Medium', f'CAPEC parsing failed: {str(e)}')
        add_default_flag('capec_likelihood', 'Medium', f'CAPEC parsing failed: {str(e)}')

    # MITRE parsing
    print("\n⚔️ Parsing MITRE ATT&CK data...")
    mitre_failed = False
    try:
        mitre_attack_vector, mitre_required_privileges, mitre_damage_potential, mitre_detectability = \
            utils.parse_mitre_description(top_mitre['description'])
        print(f"   ✅ MITRE parsed successfully")
    except Exception as e:
        print(f"   ⚠️  MITRE parsing error: {e}")
        mitre_attack_vector = 'NETWORK'
        mitre_required_privileges = 'Low'
        mitre_failed = True
        add_default_flag('mitre_attack_vector', mitre_attack_vector, f'MITRE parsing failed: {str(e)}')
        add_default_flag('mitre_required_privileges', mitre_required_privileges, f'MITRE parsing failed: {str(e)}')

    # CVE CVSS extraction
    print("\n🔐 Extracting CVE CVSS fields...")
    cve_failed = False
    try:
        attack_vector, attack_complexity, privilege_required, user_interaction = \
            utils.extract_cve_cvss_fields(top_cve['id'])
        print(f"   ✅ CVE parsed successfully")
    except Exception as e:
        print(f"   ⚠️  CVE parsing error: {e}")
        attack_vector = 'None'
        attack_complexity = 'Low'
        privilege_required = 'None'
        user_interaction = 'None'
        cve_failed = True

    # CWE parsing
    print("\n🛡️ Parsing CWE data...")
    try:
        necessary_material, operation_impact = utils.parse_cwe_info(top_cwe['id'])
        print(f"   ✅ CWE parsed successfully")
    except Exception as e:
        print(f"   ⚠️  CWE parsing error: {e}")
        necessary_material = 5
        operation_impact = 5
        add_default_flag('cwe_necessary_material', necessary_material, f'CWE parsing failed: {str(e)}')
        add_default_flag('cwe_operation_impact', operation_impact, f'CWE parsing failed: {str(e)}')

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
    if get_severity > 10:
        get_severity = 10
    
    deployment_to_affected_user = {
        'cloud': 10,
        'edge': 6,
        'vehicle': 2
    }
    
    deployment_location = template_base.get('deployment_location', 'vehicle')
    affected_user = deployment_to_affected_user.get(deployment_location, 5)
    
    # Resolve attack vector with fallback (only flag if BOTH fail)
    elt2 = attack_vector
    if elt2 == 'None':
        elt2 = mitre_attack_vector
        if elt2 == 'None' or elt2 is None:
            elt2 = 'NETWORK'
            add_default_flag('attack_vector', elt2, 'Both CVE and MITRE extraction failed')
        else:
            print(f"   ✅ Using MITRE fallback for attack_vector: {elt2}")
    
    # Resolve privilege_required with fallback (only flag if BOTH fail)
    elt1 = privilege_required
    if elt1 == 'None':
        elt1 = mitre_required_privileges
        if elt1 == 'None' or elt1 is None:
            elt1 = 'Low'
            add_default_flag('privilege_required', elt1, 'Both CVE and MITRE extraction failed')
        else:
            print(f"   ✅ Using MITRE fallback for privilege_required: {elt1}")
    
    # Flag CVE-only fields if CVE failed
    if cve_failed:
        if attack_complexity == 'Low':
            add_default_flag('attack_complexity', attack_complexity, 'CVE extraction failed')
        if user_interaction == 'None':
            add_default_flag('user_interaction', user_interaction, 'CVE extraction failed')
    
    # Flag low confidence
    if overall_confidence < 0.70:
        flag_for_review = True
        message = f"⚠️  Low semantic confidence ({overall_confidence:.2f}) - expert verification recommended"
        review_reasons.append(message)
        print(message)
    
    # User inputs (no flagging - optional)
    knowledge_cible_value = material_map.get(template_base.get('knowledge_cible'), 5)
    necessary_material_value = material_map.get(template_base.get('necessary_material'), 5)
    affected_user_value = map_affected_user.get(template_base.get('affected_user'), 5)

    # Build result
    result = {
        'severity': get_severity,
        'expertise': (getCapec.getLikehood() + necessary_material) / 2,
        'exploitability': material_map.get(
            template_base.get('necessary_material'), 
            necessary_material
        ),
        'attack_discovery': getCapec.getLikehood(),
        'knowledge_cible': knowledge_cible_value,
        'necessary_material': necessary_material_value,
        'level_damage': min(10, round((get_severity + operation_impact) / 2)),
        'affected_user': affected_user_value,
        'operational_impact': operation_impact,
        'leak_information': getCapec.isConfenditalThreat(),
        'attack_vector': elt2,
        'attack_complexity': attack_complexity,
        "privileges_required": elt1,
        "user_interaction": user_interaction,
        "safety_critical_update": template_base.get('safety_critical_update'),
        
        # Confidence metadata
        'semantic_confidence': overall_confidence,
        'confidence_level': confidence_level,
        'matched_threats': {
            'mitre_top3': getSimilar['mitre'],
            'capec_top3': getSimilar['capec'],
            'cwe_top3': getSimilar['cwe'],
            'cve_top3': getSimilar['cve']
        },
        
        # Review metadata
        'flag_for_review': flag_for_review,
        'review_reasons': review_reasons,
        'default_values_used': default_values_used
    }
    
    # Summary
    if flag_for_review:
        print("\n" + "="*60)
        print("⚠️  EXPERT REVIEW REQUIRED")
        print("="*60)
        print(f"   {len(default_values_used)} default value(s) assigned:")
        for dv in default_values_used:
            print(f"   • {dv['field']}: {dv['value']}")
        print("="*60)
    
    print("\n✅ Analysis complete!")
    print("="*60)
    
    return result


if __name__ == '__main__':
    # Setup argument parser
    parser = argparse.ArgumentParser(
        description='Automotive OTA Risk Assessment Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python service.py -s "OTA malware injection"
  python service.py -s "Malicious firmware targeting brake ECU" --safety-critical
  python service.py -s "Edge node authentication bypass" --deployment cloud
        '''
    )
    
    parser.add_argument('-s', '--scenario', required=True, type=str,
                        help='Vulnerability or threat scenario description')
    parser.add_argument('--safety-critical', choices=['YES', 'NO'],
                        help='Mark as safety-critical update')
    parser.add_argument('--deployment', type=str, choices=['cloud', 'edge', 'vehicle'],
                        default='vehicle', help='Deployment location')
    parser.add_argument('--affected-user', type=str, choices=['High', 'Medium', 'Low'],
                        help='Number of affected users')
    parser.add_argument('--knowledge', type=str, choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'VERY_LOW'],
                        help='Required knowledge level')
    parser.add_argument('--material', type=str, choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'VERY_LOW'],
                        help='Required material/equipment')
    
    args = parser.parse_args()
    
    # Build template
    template_base = {
        'description': args.scenario,
        'safety_critical_update': args.safety_critical,
        'deployment_location': args.deployment,
    }
    
    if args.affected_user:
        template_base['affected_user'] = args.affected_user
    if args.knowledge:
        template_base['knowledge_cible'] = args.knowledge
    if args.material:
        template_base['necessary_material'] = args.material
    
    # Print header
    print("\n" + "="*80)
    print("AUTOMOTIVE OTA RISK ASSESSMENT FRAMEWORK")
    print("="*80)
    print(f"Scenario: {args.scenario}")
    print(f"Safety-Critical: {'YES' if args.safety_critical else 'NO'}")
    print(f"Deployment: {args.deployment.upper()}")
    print("="*80)
    
    try:
        # Analyze
        get_analyse_template = get_analyse(template_base)
        
        # Create risk analyzer
        print("\n" + "="*60)
        print("CALCULATING RISK SCORES")
        print("="*60)
        risk_analyzer = analyse_automatique(get_analyse_template)
        
        # Transfer review flags
        risk_analyzer.flag_for_review = get_analyse_template.get('flag_for_review', False)
        risk_analyzer.review_reasons = get_analyse_template.get('review_reasons', [])
        risk_analyzer.default_values_used = get_analyse_template.get('default_values_used', [])
        
        # Calculate risk
        risk_score = risk_analyzer.get_risk()
        risk_level, risk_props = risk_analyzer.get_risk_level(risk_score)
        
        # Results
        print("\n" + "="*60)
        print("FINAL RISK ASSESSMENT:")
        print("="*60)
        print(f"Risk Score: {risk_score:.2f}/5.0")
        print(f"Risk Level: {risk_level} {risk_props['color']}")
        print(f"Priority: {risk_props['priority']}")
        print(f"\nHARA: {risk_analyzer.hara.getRisque():.2f} (ASIL: {risk_analyzer.hara.getAsil()})")
        print(f"TARA: {risk_analyzer.tara.Risque():.2f}")
        print(f"DREAD: {risk_analyzer.dread.get_risque():.2f}")
        
        # Review summary
        if risk_analyzer.flag_for_review:
            print("\n" + "="*60)
            print("⚠️  EXPERT REVIEW REQUIRED")
            print("="*60)
            for reason in risk_analyzer.review_reasons:
                print(f"   {reason}")
        else:
            print("\n✅ No expert review required")
        
        print("="*60)
    
    except Exception as e:
        print("\n" + "="*60)
        print("❌ ERROR:")
        print("="*60)
        print(f"{str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)