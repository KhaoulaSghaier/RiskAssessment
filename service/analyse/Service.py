"""
service.py - OTARQ risk assessment service (ATD-based extraction)
"""

import argparse
import sys
import os
import time
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from service.analyse.get_match_atd import try_atd_extraction, map_hara_to_iso26262
from service.analyse.analyse_automatique import analyse_automatique, RISK_LEVELS
from service.analyse.ATD_loader import load_and_prepare_atd


def analyze_threat_scenario(scenario_query,
                             atd_path='Automotive-threat-database.csv',
                             atd_confidence_threshold=0.5,
                             top_k=3,
                             safety_critical_update=False,
                             vulnerability_location='vehicle'):
    """
    Analyze a threat scenario against the Automotive Threat Database (ATD).

    Risk parameters are extracted from the best-matching ATD entry using
    semantic similarity. If the confidence score falls below the threshold,
    the result is flagged for expert review rather than propagated downstream.

    :param scenario_query:           Natural language description of the threat scenario
    :param atd_path:                 Path to the ATD CSV file
    :param atd_confidence_threshold: Minimum cosine similarity to accept an ATD match (default: 0.5)
    :param top_k:                    Number of candidate matches to retrieve
    :param safety_critical_update:   True if the OTA update targets a safety-critical component
    :param vulnerability_location:   Deployment layer: 'cloud', 'edge', or 'vehicle'
    :return:                         Dict with extracted parameters and risk scores, or None on failure
    """

    print(f"\n{'='*70}")
    print(f"OTARQ — AUTOMATED OTA RISK QUANTIFICATION")
    print(f"{'='*70}")
    print(f"Query              : {scenario_query}")
    print(f"Confidence threshold: {atd_confidence_threshold}")
    print(f"Vulnerability layer : {vulnerability_location.upper()}")
    print(f"Safety-critical     : {'YES' if safety_critical_update else 'NO'}")
    print(f"{'='*70}\n")

    # ------------------------------------------------------------------
    # STEP 1: Load ATD and run semantic matching
    # ------------------------------------------------------------------
    print("Searching Automotive Threat Database...")

    try:
        desc_atd, tec_atd = load_and_prepare_atd(atd_path)
        print(f"  Loaded ATD: {len(tec_atd)} entries")
    except FileNotFoundError:
        print(f"  ATD file not found at: {atd_path}")
        return None
    except Exception as e:
        print(f"  Failed to load ATD: {e}")
        return None

    success, risk_params, atd_match = try_atd_extraction(
        query=scenario_query,
        desc_atd=desc_atd,
        tec_atd=tec_atd,
        confidence_threshold=atd_confidence_threshold,
        vulnerability_location=vulnerability_location
    )

    # ------------------------------------------------------------------
    # STEP 2: Evaluate match quality
    # ------------------------------------------------------------------
    if atd_match:
        print(f"\n  Top match : {atd_match['id']} — {atd_match['name']}")
        print(f"  Confidence: {atd_match['confidence']:.4f}")

    if not success:
        if atd_match:
            print(
                f"\n  Confidence {atd_match['confidence']:.4f} is below threshold "
                f"{atd_confidence_threshold}. Result flagged for expert review."
            )
        else:
            print("\n  No ATD match found. Please refine the scenario description.")
        return None

    print(f"\n  Match accepted — extracting risk parameters from ATD entry.")

    # ------------------------------------------------------------------
    # STEP 3: Apply user-specified context flags
    # ------------------------------------------------------------------
    risk_params['safety_critical_update'] = safety_critical_update
    risk_params['vulnerability_location'] = vulnerability_location

    # ------------------------------------------------------------------
    # STEP 4: Display extracted parameters
    # ------------------------------------------------------------------
    print(f"\n{'='*70}")
    print(f"EXTRACTED RISK PARAMETERS")
    print(f"{'='*70}")

    print(f"\n  CVSS Exploitability")
    print(f"    Attack Vector      : {risk_params.get('attack_vector')}")
    print(f"    Attack Complexity  : {risk_params.get('attack_complexity')}")
    print(f"    Privileges Required: {risk_params.get('privileges_required')}")
    print(f"    User Interaction   : {risk_params.get('user_interaction')}")

    print(f"\n  TARA Impact (ISO/SAE 21434)")
    print(f"    Safety             : {risk_params.get('safety_tara')}")
    print(f"    Financial          : {risk_params.get('financial_tara')}")
    print(f"    Operational        : {risk_params.get('operational_tara')}")
    print(f"    Privacy            : {risk_params.get('privacy_tara')}")

    print(f"\n  HARA Parameters (ISO 26262)")
    print(f"    Severity           : {risk_params.get('severity')}/10  → S{risk_params.get('severity_iso')}")
    print(f"    Exposure           : {risk_params.get('hara_exposure')}/10  → E{risk_params.get('exposure_iso')}")
    print(f"    Controllability    : {risk_params.get('hara_controllability')}/10  → C{risk_params.get('controllability_iso')}")

    print(f"\n  DREAD Parameters")
    print(f"    Damage potential   : {risk_params.get('level_damage')}/10")
    print(f"    Affected users     : {risk_params.get('affected_user')}/10  (layer: {vulnerability_location})")

    # ------------------------------------------------------------------
    # STEP 5: Compute risk scores
    # ------------------------------------------------------------------
    print(f"\n{'='*70}")
    print(f"RISK ASSESSMENT")
    print(f"{'='*70}")

    try:
        analyzer = analyse_automatique(risk_params)
        final_score = analyzer.get_risk()
        risk_level, risk_props = analyzer.get_risk_level(final_score)

        print(f"\n  Final risk score : {final_score:.2f} / 5.0")
        print(f"  Risk level       : {risk_level} {risk_props['color']}")
        print(f"  Priority         : {risk_props['priority']}")

        return {
            'scenario': scenario_query,
            'atd_match': atd_match,
            'risk_parameters': risk_params,
            'risk_scores': {
                'final_score': final_score,
                'risk_level': risk_level,
                'risk_properties': risk_props
            }
        }

    except Exception as e:
        print(f"\n  Risk calculation failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():

    parser = argparse.ArgumentParser(
        description='OTARQ — Automated OTA Risk Quantification for Software-Defined Vehicles',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python service.py -s "Hardcoded secret in TCU firmware allows UDS authentication bypass"
  python service.py -s "Firmware signature validation bypass on gateway ECU" -v cloud --safety-critical
  python service.py -s "Remote API exploit via VIN to execute fleet-wide commands" -v cloud -t 0.6
        '''
    )

    parser.add_argument(
        '-s', '--scenario', required=True,
        help='Natural language description of the threat scenario'
    )
    parser.add_argument(
        '-t', '--threshold', type=float, default=0.5,
        help='ATD confidence threshold — matches below this value are flagged for expert review (default: 0.5)'
    )
    parser.add_argument(
        '-k', '--top-k', type=int, default=3,
        help='Number of candidate ATD matches to retrieve (default: 3)'
    )
    parser.add_argument(
        '-d', '--database', default='Automotive-threat-database.csv',
        help='Path to the ATD CSV file (default: Automotive-threat-database.csv)'
    )
    parser.add_argument(
        '--safety-critical', action='store_true',
        help='Flag when the OTA update targets a safety-critical component'
    )
    parser.add_argument(
        '-v', '--vuln-location', type=str,
        choices=['cloud', 'edge', 'vehicle'],
        default='vehicle',
        help='Vulnerability deployment layer: cloud (fleet-wide), edge (regional), vehicle (single)'
    )

    args = parser.parse_args()

    start_time = time.perf_counter()

    try:
        results = analyze_threat_scenario(
            scenario_query=args.scenario,
            atd_path=args.database,
            atd_confidence_threshold=args.threshold,
            top_k=args.top_k,
            safety_critical_update=args.safety_critical,
            vulnerability_location=args.vuln_location
        )
        elapsed = time.perf_counter() - start_time

        print(f"\n{'='*70}")
        if results:
            print(f"ANALYSIS COMPLETE  ({elapsed:.3f} s)")
            print(f"{'='*70}")
            print(f"  Risk level : {results['risk_scores']['risk_level']} "
                  f"{results['risk_scores']['risk_properties']['color']}")
            print(f"  Risk score : {results['risk_scores']['final_score']:.2f} / 5.0")
            return 0
        else:
            print(f"ANALYSIS INCOMPLETE  ({elapsed:.3f} s)")
            print(f"{'='*70}")
            print(f"  Review the scenario description or lower the confidence threshold (-t).")
            return 1

    except Exception as e:
        print(f"\n  Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())