"""
Service.py - Main service with TWO-TIER risk extraction logic
"""

import argparse
import sys
import os
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from service.analyse import utils
from service.analyse.get_match import get_top_match
from service.analyse.get_match_atd import try_atd_extraction, map_hara_to_iso26262 
from service.analyse.analyse_automatique import analyse_automatique, RISK_LEVELS
from service.analyse.ATD_loader import load_and_prepare_atd


# FONCTION : Extract from CVE/CWE/CAPEC

def extract_risk_from_matches(matches, vulnerability_location='vehicle'):
    """
    Extract risk parameters from CVE/CWE/CAPEC matches
    """
    cve_match = matches['cve'][0]
    cwe_match = matches['cwe'][0]
    capec_match = matches['capec'][0]
    
    cve_id = cve_match['id']
    cwe_id = cwe_match['id'].replace('CWE-', '') 
    capec_id = capec_match['id']
    capec_name = capec_match['name']
    
    print(f"\n   📊 Extracting parameters from:")
    print(f"      CVE: {cve_id} (confidence: {cve_match['confidence']:.3f})")
    print(f"      CWE: {cwe_id} (confidence: {cwe_match['confidence']:.3f})")
    print(f"      CAPEC: {capec_id} (confidence: {capec_match['confidence']:.3f})")
    
    # ===== Extract from CVE =====
    try:
        attack_vector, attack_complexity, privilege_required, user_interaction = \
            utils.extract_cve_cvss_fields(cve_id)
    except Exception as e:
        print(f"      ⚠️  CVE extraction failed: {e}")
        attack_vector = 'NETWORK'
        attack_complexity = 'LOW'
        privilege_required = 'NONE'
        user_interaction = 'NONE'
    
    # ===== Extract from CWE =====
    try:
        necessary_material, operation_impact = utils.parse_cwe_info(cwe_id)
    except Exception as e:
        print(f"      ⚠️  CWE extraction failed: {e}")
        necessary_material = 5
        operation_impact = 5
    
    # ===== Extract from CAPEC =====
    try:
        likelihood, severity, consequences, prerequisites = \
            utils.get_capec_from_id(capec_id, capec_name)
    except Exception as e:
        print(f"      ⚠️  CAPEC extraction failed: {e}")
        likelihood = 'Medium'
        severity = 'Medium'
        consequences = {}
        prerequisites = ''
    
    # ===== Get EPSS score =====
    try:
        epss_score, epss_percentile = utils.get_epss_score(cve_id)
    except:
        epss_score = 0.5
        epss_percentile = 50
    
    
    # TARA: Opportunity
    vector_opportunity_map = {
        'NETWORK': 'Unlimited',
        'ADJACENT_NETWORK': 'Much',
        'ADJACENT': 'Much',
        'LOCAL': 'Moderate',
        'PHYSICAL': 'Difficult'
    }
    opportunity = vector_opportunity_map.get(str(attack_vector).upper(), 'Moderate')
    
    # TARA: Elapsed time
    elapsed_time = 'day' if str(attack_complexity).upper() == 'LOW' else 'week'
    
    # DREAD: Attack discovery
    complexity_discovery_map = {'LOW': 8, 'HIGH': 4}
    base_discovery = complexity_discovery_map.get(str(attack_complexity).upper(), 6)
    
    likelihood_boost = {'High': 2, 'Medium': 0, 'Low': -2}
    attack_discovery = max(1, min(10, base_discovery + likelihood_boost.get(likelihood, 0)))
    
    # DREAD: Damage
    severity_damage_map = {
        'Very High': 10, 'High': 8, 'Medium': 6, 'Low': 4, 'Very Low': 2
    }
    base_damage = severity_damage_map.get(severity, 6)
    level_damage = max(base_damage, operation_impact)
    
    # DREAD: Affected users
    vector_affected_map = {
        'NETWORK': 10, 'ADJACENT_NETWORK': 7, 'ADJACENT': 7, 'LOCAL': 4, 'PHYSICAL': 2
    }
    location_affected_map = {
        'cloud': 10,   # Fleet-wide impact (tous les véhicules)
        'edge': 7,     # Regional impact (plusieurs véhicules)
        'vehicle': 3   # Single vehicle impact
    }
    
    # Utiliser la location si fournie, sinon inférer du attack_vector
    if vulnerability_location:
        affected_user = location_affected_map.get(vulnerability_location, 5)
        print(f"   🌍 Affected users from location '{vulnerability_location}': {affected_user}/10")
    else:
        # Fallback: inférer de l'attack vector (ancien comportement)
        vector_affected_map = {
            'NETWORK': 10, 'ADJACENT_NETWORK': 7, 'ADJACENT': 7, 
            'LOCAL': 4, 'PHYSICAL': 2
        }
        affected_user = vector_affected_map.get(str(attack_vector).upper(), 5)
        print(f"   🌍 Affected users from attack vector '{attack_vector}': {affected_user}/10")
    
    
    # HARA: Infer from consequences
    hara_severity = 0
    leak_information = 0

    if consequences:
        print(f"\n   🔍 Analyzing CAPEC consequences for HARA:")
        
        for scope, impacts in consequences.items():
            impacts_str = str(impacts).lower()
            
            print(f"      {scope}: {impacts_str[:100]}...")  # Debug
            
            # Severity (safety impact) - PATTERNS PLUS LARGES
            if any(term in impacts_str for term in [
                'execute', 'code execution', 'arbitrary code',
                'gain privilege', 'elevate privilege', 'privilege escalation',
                'bypass', 'override'
            ]):
                hara_severity = max(hara_severity, 10)
                print(f"         → Severity: 10 (code execution/privilege)")
            
            elif any(term in impacts_str for term in [
                'modify memory', 'write memory', 'memory corruption',
                'buffer overflow', 'injection'
            ]):
                hara_severity = max(hara_severity, 8)
                print(f"         → Severity: 8 (memory corruption)")
            
            elif any(term in impacts_str for term in [
                'modify', 'alter', 'change data',
                'denial of service', 'dos', 'crash', 'unavailable'
            ]):
                hara_severity = max(hara_severity, 6)
                print(f"         → Severity: 6 (data modification/DoS)")
            
            elif any(term in impacts_str for term in [
                'read', 'access', 'disclose', 'leak', 'expose'
            ]):
                hara_severity = max(hara_severity, 4)
                print(f"         → Severity: 4 (information disclosure)")
            
            # Privacy/Leak information
            if any(term in impacts_str for term in [
                'confidentiality', 'read data', 'read file', 'information disclosure',
                'leak', 'expose', 'access data'
            ]):
                if any(term in impacts_str for term in ['read data', 'read file', 'full access']):
                    leak_information = max(leak_information, 10)
                    print(f"         → Privacy: 10 (full data access)")
                elif 'read memory' in impacts_str:
                    leak_information = max(leak_information, 7)
                    print(f"         → Privacy: 7 (memory access)")
                else:
                    leak_information = max(leak_information, 5)
                    print(f"         → Privacy: 5 (partial disclosure)")

    # Si toujours aucun impact détecté, utiliser le CWE operation_impact comme proxy
    if hara_severity == 0 and operation_impact >= 7:
        hara_severity = operation_impact
        print(f"   ⚠️  No CAPEC severity found, using CWE operation_impact: {hara_severity}")

    print(f"\n   📊 Final HARA values (0-10):")
    print(f"      Severity: {hara_severity}")
    print(f"      Operational: {operation_impact}")
    print(f"      Privacy: {leak_information}")

    # Map to ISO 26262 classes
    severity_iso, controllability_iso, exposure_iso = map_hara_to_iso26262(
        hara_severity, operation_impact, leak_information
    )

    print(f"   🔍 ISO Classes: S{severity_iso} + E{exposure_iso} + C{controllability_iso}")

    # Convert strings to numbers for DREAD
    knowledge_numeric_map = {'PUBLIC': 10, 'RESTRICTED': 7, 'SENSITIVE': 5, 'CRITICAL': 3}
    expertise_numeric_map = {'Layman': 10, 'Proficient': 6, 'Expert': 3}
    
    privilege_expertise_map = {'NONE': 'Layman', 'LOW': 'Proficient', 'HIGH': 'Expert'}
    expertise = privilege_expertise_map.get(str(privilege_required).upper(), 'Proficient')
    
    vector_knowledge_map = {
        'NETWORK': 'PUBLIC', 'ADJACENT_NETWORK': 'RESTRICTED', 
        'ADJACENT': 'RESTRICTED', 'LOCAL': 'SENSITIVE', 'PHYSICAL': 'CRITICAL'
    }
    knowledge_cible = vector_knowledge_map.get(str(attack_vector).upper(), 'RESTRICTED')
    
    # Assemble final parameters
    risk_params = {
        # TARA parameters
        'attack_vector': str(attack_vector),
        'attack_complexity': str(attack_complexity),
        'privileges_required': str(privilege_required),
        'user_interaction': str(user_interaction),
        'opportunity': opportunity,
        'elapsed_time': elapsed_time,
        
        # DREAD parameters
        'level_damage': int(level_damage),
        'affected_user': int(affected_user),
        #'necessary_material': int(necessary_material),
        #'attack_discovery': int(attack_discovery),
        #'expertise': expertise_numeric_map.get(expertise, 6),
        #'knowledge_cible': knowledge_numeric_map.get(knowledge_cible, 7),
        'vulnerability_location': vulnerability_location,
        
        # HARA parameters (0-10 for display)
        'severity': int(hara_severity),
        'operational_impact': int(operation_impact),
        'leak_information': int(leak_information),
        
        # ✅ HARA ISO 26262 classes (for calculation)
        'severity_iso': severity_iso,
        'exposure_iso': exposure_iso,
        'controllability_iso': controllability_iso,
        
        # Safety critical flag (will be overridden by user input)
        'safety_critical_update': False,
        
        # Metadata
        'cve_id': cve_id,
        'cwe_id': cwe_id,
        'capec_id': capec_id,
        'epss_score': float(epss_score),
        'database_source': 'CVE+CWE+CAPEC'
    }
    
    print(f"   ✅ Parameters extracted successfully")
    print(f"   🔍 ISO Classes: S{severity_iso} + E{exposure_iso} + C{controllability_iso}")
    
    return risk_params


# FONCTION : Analyze Threat Scenario (Main)
def analyze_threat_scenario(scenario_query, 
                           atd_path='Automotive-threat-database.csv',
                           atd_confidence_threshold=0.70,
                           top_k=3,
                           safety_critical_update=False,
                           vulnerability_location='vehicle'):
    """
    Analyze threat scenario with TWO-TIER extraction logic
    """
    
    print(f"\n{'='*80}")
    print(f"ANALYZING VULNERABILITY SCENARIO")
    print(f"{'='*80}")
    print(f"Query: {scenario_query}")
    print(f"ATD Confidence Threshold: {atd_confidence_threshold}")
    print(f"Vulnerability Location: {vulnerability_location.upper()}")
    print(f"{'='*80}\n")
    

    # TIER 1: TRY ATD FIRST
    risk_params = None
    extraction_method = None
    atd_match_info = None
    
    print("🔍 TIER 1: Checking Automotive Threat Database (ATD)...")
    
    try:
        desc_atd, tec_atd = load_and_prepare_atd(atd_path)
        print(f"   ✓ Loaded ATD: {len(tec_atd)} threats")
        
        success, risk_params, atd_match = try_atd_extraction(
            query=scenario_query,
            desc_atd=desc_atd,
            tec_atd=tec_atd,
            confidence_threshold=atd_confidence_threshold,
            vulnerability_location=vulnerability_location
        )
        
        if success:
            extraction_method = 'ATD'
            atd_match_info = atd_match
            
            print(f"\n   ✅ ATD MATCH FOUND (High Confidence)")
            print(f"   Threat: {atd_match['id']} - {atd_match['name']}")
            print(f"   Confidence: {atd_match['confidence']:.4f}")
            print(f"   → Using ATD for risk parameter extraction")
            
        elif atd_match:
            print(f"\n   ⚠️  ATD match found but confidence too low")
            print(f"   Threat: {atd_match['id']} - {atd_match['name']}")
            print(f"   Confidence: {atd_match['confidence']:.4f} < {atd_confidence_threshold}")
            print(f"   → Falling back to CVE/CWE/CAPEC extraction")
            
        else:
            print(f"\n   ℹ️  No ATD match found")
            print(f"   → Falling back to CVE/CWE/CAPEC extraction")
            
    except FileNotFoundError:
        print(f"   ⚠️  ATD database not found at: {atd_path}")
        print(f"   → Falling back to CVE/CWE/CAPEC extraction")
    except Exception as e:
        print(f"   ⚠️  ATD extraction error: {e}")
        print(f"   → Falling back to CVE/CWE/CAPEC extraction")
    
    # TIER 2: FALLBACK TO CVE/CWE/CAPEC
    if risk_params is None:
        print(f"\n🔍 TIER 2: Using CVE/CWE/CAPEC databases...")
        
        try:
            cve_df = utils.get_cve()
            cwe_df = utils.get_cwe()
            capec_df = utils.get_capec()
            
            desc_cve = utils.get_cve_description().tolist()
            desc_cwe = utils.get_all_cwe_description().tolist()
            desc_capec = utils.get_all_capec_description().tolist()
            
            tec_cve = cve_df
            tec_cwe = utils.get_all_cwe()
            tec_capec = utils.get_all_capec()
            
            print(f"   ✓ Loaded CVE: {len(tec_cve)} entries")
            print(f"   ✓ Loaded CWE: {len(tec_cwe)} entries")
            print(f"   ✓ Loaded CAPEC: {len(tec_capec)} entries")
            
            matches = get_top_match(
                query=scenario_query,
                desc_cwe=desc_cwe,
                desc_capec=desc_capec,
                desc_cve=desc_cve,
                tec_capec=tec_capec,
                tec_cwe=tec_cwe,
                tec_cve=tec_cve,
                top_value=top_k
            )
            
            print(f"\n   ✅ CVE/CWE/CAPEC matches found")
            print(f"   Top CVE: {matches['cve'][0]['id']}")
            print(f"   Top CWE: {matches['cwe'][0]['id']}")
            print(f"   Top CAPEC: {matches['capec'][0]['id']}")
            
            risk_params = extract_risk_from_matches(matches, vulnerability_location=vulnerability_location)
            extraction_method = 'CVE+CWE+CAPEC'
            
        except Exception as e:
            print(f"   ✗ Error loading CVE/CWE/CAPEC databases: {e}")
            import traceback
            traceback.print_exc()
            return None
    

    # DISPLAY RESULTS
    if risk_params is None:
        print(f"\n✗ Could not extract risk parameters")
        return None
    
    # Override with user-specified safety_critical flag
    risk_params['safety_critical_update'] = safety_critical_update
    risk_params['vulnerability_location'] = vulnerability_location

    print(f"\n{'='*80}")
    print(f"EXTRACTED RISK PARAMETERS")
    print(f"{'='*80}")
    print(f"Extraction Method: {extraction_method}")
    
    if atd_match_info:
        print(f"ATD Match: {atd_match_info['id']} - {atd_match_info['name']}")
        print(f"ATD Confidence: {atd_match_info['confidence']:.4f}")
    
    print(f"\n--- TARA Parameters ---")
    print(f"  Attack Vector: {risk_params.get('attack_vector')}")
    print(f"  Attack Complexity: {risk_params.get('attack_complexity')}")
    print(f"  Privileges Required: {risk_params.get('privileges_required')}")
    print(f"  User Interaction: {risk_params.get('user_interaction')}")
    
    print(f"\n--- DREAD Parameters ---")
    print(f"  Damage: {risk_params.get('level_damage')}/10")
    #print(f"  Reproducibility (Expertise): {risk_params.get('expertise')}")
    #print(f"  Exploitability: {risk_params.get('necessary_material')}/10")
    print(f"  Affected Users: {risk_params.get('affected_user')}/10 (Location: {risk_params.get('vulnerability_location', 'N/A').upper()})")
    #print(f"  Discoverability: {risk_params.get('attack_discovery')}/10")
    
    print(f"\n--- HARA Parameters ---")
    print(f"  Severity: {risk_params.get('severity')}/10")
    print(f"  Operational Impact: {risk_params.get('operational_impact')}/10")
    print(f"  Privacy Impact: {risk_params.get('leak_information')}/10")
    
    print(f"\n--- Safety Critical ---")
    print(f"  Safety Critical Update: {'YES' if risk_params.get('safety_critical_update') else 'NO'}")
    

    # CALCULATE RISK SCORES
    print(f"\n{'='*80}")
    print(f"RISK ASSESSMENT SCORES")
    print(f"{'='*80}")
    
    try:
        analyzer = analyse_automatique(risk_params)
        final_risk_score = analyzer.get_risk()
        risk_level, risk_props = analyzer.get_risk_level(final_risk_score)
        
        print(f"\nFinal Aggregated Risk Score: {final_risk_score:.2f}/5.0")
        print(f"Risk Level: {risk_level} {risk_props['color']}")
        print(f"Priority: {risk_props['priority']}")
        
        results = {
            'scenario': scenario_query,
            'extraction_method': extraction_method,
            'atd_match': atd_match_info,
            'risk_parameters': risk_params,
            'risk_scores': {
                'final_score': final_risk_score,
                'risk_level': risk_level,
                'risk_properties': risk_props
            }
        }
        
        return results
        
    except Exception as e:
        print(f"\n✗ Error during risk calculation: {e}")
        import traceback
        traceback.print_exc()
        return None


# MAIN

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Automotive Threat Risk Assessment with Two-Tier Extraction',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
TWO-TIER EXTRACTION LOGIC:
  1. ATD (Automotive Threat Database) - if confidence >= threshold
  2. CVE/CWE/CAPEC - fallback if ATD confidence too low
        '''
    )
    
    parser.add_argument('-s', '--scenario', required=True,
                        help='Threat scenario description')
    parser.add_argument('-t', '--threshold', type=float, default=0.70,
                        help='ATD confidence threshold (default: 0.70)')
    parser.add_argument('-k', '--top-k', type=int, default=3,
                        help='Number of top matches (default: 3)')
    parser.add_argument('-d', '--database', default='Automotive-threat-database.csv',
                        help='Path to ATD CSV file')
    parser.add_argument('--safety-critical', action='store_true',
                        help='Flag if the update targets a safety-critical component')
    parser.add_argument('-v', '--vuln-location', type=str, 
                        choices=['cloud', 'edge', 'vehicle'],
                        default='vehicle',
                        help='Vulnerability location: cloud (fleet-wide), edge (regional), vehicle (single)')
    
    
    args = parser.parse_args()
    
    try:
        results = analyze_threat_scenario(
            scenario_query=args.scenario,
            atd_path=args.database,
            atd_confidence_threshold=args.threshold,
            top_k=args.top_k,
            safety_critical_update=args.safety_critical,
            vulnerability_location=args.vuln_location
        )
        
        if results:
            print(f"\n{'='*80}")
            print(f"✅ ANALYSIS COMPLETE")
            print(f"{'='*80}")
            print(f"\nExtraction Method: {results['extraction_method']}")
            print(f"Final Risk Level: {results['risk_scores']['risk_level']} {results['risk_scores']['risk_properties']['color']}")
            print(f"Risk Score: {results['risk_scores']['final_score']:.2f}/5.0")
            return 0
        else:
            print(f"\n{'='*80}")
            print(f"✗ ANALYSIS FAILED")
            print(f"{'='*80}")
            return 1
        
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())