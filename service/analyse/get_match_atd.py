from sentence_transformers import SentenceTransformer, util
import os
import numpy as np
import pandas as pd

def load_or_generate_embeddings_atd(description, path_embedding, model):
    """
    Load or generate embeddings for ATD
    """
    embedding = None
    if os.path.exists(path_embedding):
        embedding = np.load(path_embedding)
    else:
        embedding = model.encode(description, batch_size=64, show_progress_bar=True)
        np.save(path_embedding, embedding)
    return embedding

def get_top_atd(query_embedding, embeddings, atd_dataframe, top_n=3):
    """
    Get top N matches from ATD with confidence scores
    """
    scores = util.cos_sim(query_embedding, embeddings)[0].numpy()
    top_indices = np.argsort(scores)[::-1][:top_n]
    
    results = []
    for rank, idx in enumerate(top_indices, start=1):
        confidence = float(scores[idx])
        threat_data = atd_dataframe.iloc[idx].to_dict()
        
        results.append({
            'source': 'ATD',
            'id': threat_data.get('ATD_ID2', f'ATD-{idx}'),
            'name': threat_data.get('CVE_ID', 'Unknown'),
            'description': threat_data.get('Description', ''),
            'confidence': confidence,
            'rank': rank,
            'threat_data': threat_data
        })
    
    return results


def match_atd(query, desc_atd, tec_atd, atd_path='automotive_embedding.npy', 
              model_name="all-mpnet-base-v2", top_value=3):
    """
    Match query against ATD database
    
    :param query: threat scenario description
    :param desc_atd: list of ATD descriptions
    :param tec_atd: ATD dataframe
    :param atd_path: path to ATD embeddings
    :param model_name: sentence transformer model
    :param top_value: number of top matches
    :return: list of top ATD matches
    """
    model = SentenceTransformer(model_name)
    
    # Load or generate ATD embeddings
    embeddings_atd = load_or_generate_embeddings_atd(desc_atd, atd_path, model)
    
    # Encode query
    query_embedding = model.encode(query, batch_size=64, show_progress_bar=True)
    
    # Get top matches
    atd_matches = get_top_atd(query_embedding, embeddings_atd, tec_atd, top_value)
    
    return atd_matches

def map_hara_to_iso26262(severity_0_10, operational_0_10, privacy_0_10):
    """
    Map extracted HARA parameters (0-10 scale) to ISO 26262 classes
    
    ISO 26262 HARA uses:
    - Severity (S): S1, S2, S3 (mapped from our severity)
    - Exposure (E): E1, E2, E3, E4 (mapped from operational impact)
    - Controllability (C): C1, C2, C3 (mapped from privacy/leak )
    
    Returns: (severity_class, controllability_class, exposure_class)
    """
    
    # Severity: How bad is the harm?
    # S1: Light injuries
    # S2: Medium injuries 
    # S3: High injuries
    if severity_0_10 >= 8:
        severity_class = 3  # S3
    elif severity_0_10 >= 5:
        severity_class = 2  # S2
    elif severity_0_10 >= 2:
        severity_class = 1  # S1
    else:
        severity_class = 1  # Default to S1
    
    # Exposure: How often is the hazard present?
    # E1: Very low probability 
    # E2: Low probability 
    # E3: Medium probability 
    # E4: High probability 
    if operational_0_10 >= 8:
        exposure_class = 4  # E4: High
    elif operational_0_10 >= 6:
        exposure_class = 3  # E3: Medium
    elif operational_0_10 >= 3:
        exposure_class = 2  # E2: Low
    else:
        exposure_class = 1  # E1: Very low
    
    # Controllability: Can driver/system avoid harm?
    # C1: Simply controllable 
    # C2: Normally controllable 
    # C3: Difficult/impossible to control 

    if privacy_0_10 >= 7:
        controllability_class = 3  # C3: Difficult to control
    elif privacy_0_10 >= 4:
        controllability_class = 2  # C2: Normally controllable
    else:
        controllability_class = 1  # C1: Simply controllable
    
    return severity_class,exposure_class, controllability_class

def get_safety_discrete(safety_flag, impact_score):
    """Return discrete TARA Safety value: {0, 10, 100, 1000}"""
    if safety_flag == 'No':
        return 0
    elif safety_flag == 'Yes':
        if impact_score >= 5.0:
            return 1000
        elif impact_score >= 3.6:
            return 100
        elif impact_score >= 1.4:
            return 10
        else:
            return 0
    else:  # empty
        if impact_score >= 4.0:
            return 100
        elif impact_score >= 2.0:
            return 10
        else:
            return 0

def get_financial_discrete(financial_flag, impact_score, systemic_flag, vuln_location):
    """Return discrete TARA Financial value: {0, 10, 100, 1000}"""
    if financial_flag == 'No':
        return 0
    elif financial_flag == 'Yes':
        if impact_score >= 5.0:
            return 1000
        elif impact_score >= 3.6:
            return 100
        elif impact_score >= 1.4:
            return 10
        else:
            return 0
    else:  # empty - use Systemic/location as proxy
        if systemic_flag == 'Potentially Systemic' or vuln_location == 'cloud':
            return 100
        elif vuln_location == 'edge':
            return 10
        elif systemic_flag == 'Not Systemic' or vuln_location == 'vehicle':
            return 10
        else:
            return 0

def get_operational_discrete(operational_flag, impact_score):
    """Return discrete TARA Operational value: {0, 1, 10, 100}"""
    if operational_flag == 'No':
        return 0
    elif operational_flag == 'Yes':
        if impact_score >= 5.0:
            return 100
        elif impact_score >= 3.6:
            return 10
        elif impact_score >= 1.4:
            return 1
        else:
            return 0
    else:  # empty
        if impact_score >= 4.0:
            return 10
        elif impact_score >= 2.0:
            return 1
        else:
            return 0

def get_privacy_discrete(privacy_flag, cvss_confidentiality):
    """Return discrete TARA Privacy value: {0, 1, 10, 100}"""
    if privacy_flag == 'No':
        return 0
    elif privacy_flag == 'Yes':
        if cvss_confidentiality == 'H':
            return 100
        elif cvss_confidentiality == 'L':
            return 10
        else:  # 'N'
            return 0
    else:  # empty
        if cvss_confidentiality == 'H':
            return 10
        elif cvss_confidentiality == 'L':
            return 1
        else:
            return 0



def get_hara_severity_from_safety(safety_flag, impact_score):
    """
    Map Safety flag + Impact Score to HARA Severity (0-10 scale)
    For ISO 26262 S classes: S0, S1, S2, S3
    
    Returns:
        int: 0-10 where 10=S3, 6=S2, 3=S1, 0=S0
    """
    if safety_flag == 'No':
        return 0  # S0 - No safety impact
    
    elif safety_flag == 'Yes':
        if impact_score >= 5.0:
            return 10  # S3 
        elif impact_score >= 3.0:
            return 6   # S2 
        elif impact_score >= 1.0:
            return 3   # S1 
        else:
            return 0   # S0 
    
    else:  # safety_flag is empty/None
        if impact_score >= 4.0:
            return 6   # S2 
        elif impact_score >= 2.0:
            return 3   # S1
        else:
            return 0   # S0


def get_hara_severity_from_operational(operational_flag, impact_score):
    """
    Map Operational flag + Impact Score to HARA Severity (0-10 scale)
    
    Returns:
        int: 0-10 where max is 6 (S2) for operational impacts
    """
    if operational_flag == 'No':
        return 0  # No operational impact
    
    elif operational_flag == 'Yes':
        if impact_score >= 5.0:
            return 6   # S2 
        elif impact_score >= 3.0:
            return 3   # S1 
        else:
            return 0   # S0 
    
    else:  # operational_flag is empty/None
        if impact_score >= 4.0:
            return 3   # S1 
        else:
            return 0   # S0


def get_hara_exposure_from_av(attack_vector):
    """
    Map Attack Vector (AV) to HARA Exposure (0-10 scale)
    Represents operational situation exposure frequency
    
    AV → Exposure logic:
    - NETWORK: Vehicle always connected → E4 (>10% time)
    - ADJACENT: Nearby network access → E3 (1-10% time)
    - LOCAL: Physical proximity needed → E2 (0.001-1% time)
    - PHYSICAL: Physical access required → E1 (<0.001% time)
    
    Returns:
        int: 0-10 where 10=E4, 7=E3, 4=E2, 1=E1
    """
    av = attack_vector.upper() if attack_vector else ''
    
    if av == 'NETWORK' or av == 'N':
        return 10  # E4 - High exposure 
    elif av == 'ADJACENT' or av == 'A':
        return 7   # E3 - Medium exposure
    elif av == 'LOCAL' or av == 'L':
        return 4   # E2 - Low exposure 
    elif av == 'PHYSICAL' or av == 'P':
        return 1   # E1 - Very low exposure
    else:
        return 4   # E2 - Default: conservative medium-low


def get_hara_exposure_from_systemic(systemic_flag):
    """
    Map Systemic flag to HARA Exposure (0-10 scale)
    Fleet-wide systemic issues → all vehicles exposed
    
    Returns:
        int: 0-10 where 10=E4 (systemic), 1=E1 (not systemic)
    """
    if systemic_flag == 'Potentially Systemic':
        return 10  # E4 - All vehicles in fleet exposed
    elif systemic_flag == 'Not Systemic':
        return 1   # E1 - Single vehicle only
    else:
        return 1   # E1 - Default: not systemic 


def get_hara_controllability_from_ui(user_interaction):
    """
    Map User Interaction (UI) to HARA Controllability (0-10 scale)
    Driver awareness → ability to control/avoid harm
    
    UI → Controllability logic:
    - REQUIRED: Driver must act → aware → C1 (>90% can control)
    - NONE: Silent attack → unaware → C3 (<50% can control)
    
    Returns:
        int: 0-10 where 2=C1, 10=C3
    """
    ui = user_interaction.upper() if user_interaction else ''
    
    if ui == 'REQUIRED' or ui == 'R':
        return 2   # C1 - Simple to control
    elif ui == 'NONE' or ui == 'N':
        return 10  # C3 - Difficult to control
    else:
        return 10  # C3 - Default: assume uncontrollable 


def get_dread_damage(safety_flag, operational_flag, impact_score):
    """
    Calculate DREAD Damage parameter from Safety + Operational impacts
    
    Discrete values: {0, 5, 8, 9, 10}
    - 10: Destruction (safety-critical, high impact)
    - 9: Non-Sensitive+ (safety-critical, medium impact)
    - 8: Non-Sensitive (operational-critical, high impact)
    - 5: Low (operational-critical, medium impact)
    - 0: Zero (no significant impact)
    
    Returns:
        float: {0, 5, 8, 9, 10}
    """

    print(f"\n   🔍 DEBUG get_dread_damage():")
    print(f"      safety_flag: '{safety_flag}' (type: {type(safety_flag)})")
    print(f"      operational_flag: '{operational_flag}' (type: {type(operational_flag)})")
    print(f"      impact_score: {impact_score} (type: {type(impact_score)})")
    
    # Priority 1: Safety impacts (most severe)
    if safety_flag == 'Yes':
        print(f"      ✓ Safety=Yes branch")
        if impact_score >= 5.0:
            print(f"      ✓ impact_score >= 5.0 → damage = 10")
            return 10  # Destruction - Life-threatening
        elif impact_score >= 3.0:
            print(f"      ✓ impact_score >= 3.0 → damage = 9")
            return 9   # Non-Sensitive+ - Severe injuries
        # If safety but low impact, fall through to operational check
    else:
        print(f"      ✗ Safety != 'Yes', checking operational...")
    
    # Priority 2: Operational impacts
    if operational_flag == 'Yes':
        print(f"      ✓ Operational=Yes branch")
        if impact_score >= 5.0:
            return 8   # Non-Sensitive - Vehicle inoperable
        elif impact_score >= 3.0:
            return 5   # Low - Serious limitation
        # If operational but low impact, fall through to zero
    
    # No significant damage
    print(f"      → Returning 0 (no conditions met)")
    return 0 


def extract_risk_parameters_from_atd(atd_match, vulnerability_location='vehicle'):
    threat_data = atd_match.get('threat_data', {})
    
    # ============================================================
    # EXTRACT ATD DATA
    # ============================================================
    safety_flag = threat_data.get('Safety', '')
    financial_flag = threat_data.get('Financial', '')
    operational_flag = threat_data.get('Operational', '')
    privacy_flag = threat_data.get('Privacy', '')
    systemic_flag = threat_data.get('Systemic', '')
    impact_score = float(threat_data.get('3_Impact_score', 0))
    #attack_vector = threat_data.get('Attack_vector', '')
    
    # Parse CVSS vector
    cvss_vector = threat_data.get('CVSS3.x_vector_string', '')
    # Parse CVSS vector string
    if cvss_vector:
        for part in cvss_vector.split('/'):
            if ':' not in part:
                continue
            
            key, value = part.split(':', 1)
            
            if key == 'AV':
                attack_vector = value  # N/A/L/P
            elif key == 'AC':
                attack_complexity = value  # L/H
            elif key == 'PR':
                privileges_required = value  # N/L/H
            elif key == 'UI':
                user_interaction = value  # N/R
            elif key == 'C':
                cvss_c = value  # H/L/N
            elif key == 'I':
                cvss_i = value  # H/L/N
            elif key == 'A':
                cvss_a = value  # H/L/N
    av_map = {
        'N': 'NETWORK',
        'A': 'ADJACENT',
        'L': 'LOCAL',
        'P': 'PHYSICAL'
    }
    attack_vector_long = av_map.get(attack_vector, 'LOCAL')
    ac_map = {
        'L': 'LOW',
        'H': 'HIGH'
    }
    attack_complexity_long = ac_map.get(attack_complexity, 'LOW')
    pr_map = {
        'N': 'NONE',
        'L': 'LOW',
        'H': 'HIGH'
    }
    privileges_required_long = pr_map.get(privileges_required, 'NONE')
    ui_map = {
        'N': 'NONE',
        'R': 'REQUIRED'
    }
    user_interaction_long = ui_map.get(user_interaction, 'NONE')
    # Fallback: Check if Attack_vector column exists separately
    if not attack_vector or attack_vector == 'L':
        av_column = threat_data.get('Attack_vector', '')
        if av_column:
            # Map single letter to full value if needed
            av_map = {'N': 'N', 'A': 'A', 'L': 'L', 'P': 'P',
                     'NETWORK': 'N', 'ADJACENT': 'A', 'LOCAL': 'L', 'PHYSICAL': 'P'}
            attack_vector = av_map.get(av_column.upper(), 'L')
    
    for part in cvss_vector.split('/'):
        if part.startswith('C:'):
            cvss_c = part.split(':')[1]
        elif part.startswith('UI:'):
            user_interaction = part.split(':')[1]
    

    # TARA IMPACTS (ISO 21434 values)

    safety_tara = get_safety_discrete(safety_flag, impact_score)
    financial_tara = get_financial_discrete(financial_flag, impact_score, systemic_flag, vulnerability_location)
    operational_tara = get_operational_discrete(operational_flag, impact_score)
    privacy_tara = get_privacy_discrete(privacy_flag, cvss_c)
    

    # HARA PARAMETERS (0-10 scale for ISO 26262 mapping)

    
    # Severity: max(Safety, Operational)
    hara_severity = max(
        get_hara_severity_from_safety(safety_flag, impact_score),
        get_hara_severity_from_operational(operational_flag, impact_score)
    )
    
    # Exposure: max(AV, Systemic)
    hara_exposure = max(
        get_hara_exposure_from_av(attack_vector),
        get_hara_exposure_from_systemic(systemic_flag)
    )
    
    # Controllability: from UI
    hara_controllability = get_hara_controllability_from_ui(user_interaction)
    
    # Map to ISO 26262 classes
    severity_class, exposure_class, controllability_class = map_hara_to_iso26262(
        hara_severity,
        hara_exposure,
        hara_controllability
    )
    

    # DREAD PARAMETERS 

    
    # Damage: combined Safety + Operational
    level_damage = get_dread_damage(safety_flag, operational_flag, impact_score)
    
    # Affected Users: from location or Systemic
    if vulnerability_location == 'cloud':
        affected_user = 10
    elif vulnerability_location == 'edge':
        affected_user = 6
    elif vulnerability_location == 'vehicle':
        affected_user = 2.5
    elif systemic_flag == 'Potentially Systemic':
        affected_user = 10
    else:
        affected_user = 2.5
    

    # RETURN RISK_PARAMS
    risk_params = {
        # TARA discrete values
        'attack_vector': attack_vector_long,
        'attack_complexity': attack_complexity_long,
        'privileges_required': privileges_required_long,
        'user_interaction': user_interaction_long,
        'safety_tara': safety_tara,
        'financial_tara': financial_tara,
        'operational_tara': operational_tara,
        'privacy_tara': privacy_tara,
        
        # HARA parameters (0-10 scale)
        'severity': hara_severity,
        'hara_exposure': hara_exposure,
        'hara_controllability': hara_controllability,
        
        # HARA ISO classes
        'severity_iso': severity_class,
        'exposure_iso': exposure_class,
        'controllability_iso': controllability_class,
        
        # DREAD parameters
        'level_damage': level_damage,
        'affected_user': affected_user,

        
        # Safety critical flag
        'safety_critical_update': (safety_tara == 10),
        
        # Metadata---------------------------------------------------------------------------
        'cve_id': threat_data.get('CVE_ID', ''),
        'published_year': threat_data.get('Published_year', ''),
        'reference': threat_data.get('Reference', ''),
        'component': threat_data.get('Component', ''),
        'database_source': 'ATD'
    }
    
    return risk_params


def try_atd_extraction(query, desc_atd, tec_atd, 
                       atd_path='automotive_embedding.npy',
                       confidence_threshold=0.70,
                       vulnerability_location='vehicle'):
    """
    Try to extract risk parameters from ATD
    
    :param query: threat scenario
    :param desc_atd: ATD descriptions
    :param tec_atd: ATD dataframe
    :param atd_path: path to embeddings
    :param confidence_threshold: minimum confidence to use ATD (default 0.70)
    :return: tuple (success: bool, risk_params: dict or None, atd_match: dict or None)
    """
    try:
        # Match against ATD
        atd_matches = match_atd(query, desc_atd, tec_atd, atd_path)
        
        if not atd_matches or len(atd_matches) == 0:
            return False, None, None
        
        top_match = atd_matches[0]
        confidence = top_match['confidence']
        
        # Check confidence threshold
        if confidence >= confidence_threshold:
            # Extract risk parameters
            risk_params = extract_risk_parameters_from_atd(top_match,
                                                           vulnerability_location=vulnerability_location)
            return True, risk_params, top_match
        else:
            # Confidence too low
            return False, None, top_match
            
    except Exception as e:
        print(f"Error in ATD extraction: {e}")
        return False, None, None