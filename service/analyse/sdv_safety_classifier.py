"""
SDV Safety Classifier
Automatically determines if an OTA update is safety-critical based on
the affected automotive domain, zone, or function.

Based on ISO 26262 ASIL classifications and automotive E/E architectures.
"""

from enum import Enum
from typing import List, Dict, Optional


class ASILLevel(Enum):
    """ASIL levels from ISO 26262"""
    QM = 0      # Quality Management (non-safety)
    ASIL_A = 1
    ASIL_B = 2
    ASIL_C = 3
    ASIL_D = 4  # Highest safety integrity


class SDVZone(Enum):
    """Software-Defined Vehicle Zones"""
    # Safety-Critical Zones
    POWERTRAIN = "powertrain"
    CHASSIS = "chassis"
    ADAS = "adas"
    BODY_CONTROL = "body_control"
    
    # Non-Safety-Critical Zones
    INFOTAINMENT = "infotainment"
    CONNECTIVITY = "connectivity"
    COMFORT = "comfort"
    CONVENIENCE = "convenience"
    
    # Mixed/Context-Dependent
    GATEWAY = "gateway"
    TELEMATICS = "telematics"


class AutomotiveFunction(Enum):
    """Specific automotive functions with safety classification"""
    
    # SAFETY-CRITICAL (ASIL B-D)
    BRAKING = ("braking", ASILLevel.ASIL_D, True)
    ABS = ("abs", ASILLevel.ASIL_D, True)
    ESC = ("esc", ASILLevel.ASIL_D, True)
    STEERING = ("steering", ASILLevel.ASIL_D, True)
    EPS = ("eps", ASILLevel.ASIL_D, True)
    AIRBAG = ("airbag", ASILLevel.ASIL_D, True)
    ENGINE_CONTROL = ("engine_control", ASILLevel.ASIL_C, True)
    TRANSMISSION = ("transmission", ASILLevel.ASIL_C, True)
    BATTERY_MANAGEMENT = ("battery_management", ASILLevel.ASIL_D, True)
    AUTONOMOUS_DRIVING = ("autonomous_driving", ASILLevel.ASIL_D, True)
    ADAPTIVE_CRUISE = ("adaptive_cruise", ASILLevel.ASIL_C, True)
    LANE_KEEPING = ("lane_keeping", ASILLevel.ASIL_B, True)
    COLLISION_AVOIDANCE = ("collision_avoidance", ASILLevel.ASIL_D, True)
    PARKING_ASSIST = ("parking_assist", ASILLevel.ASIL_B, True)
    
    # SEMI-CRITICAL (ASIL A or context-dependent)
    GATEWAY_ROUTING = ("gateway_routing", ASILLevel.ASIL_A, True)  # Can affect safety
    DIAGNOSTIC = ("diagnostic", ASILLevel.ASIL_A, True)
    SECURITY_MODULE = ("security_module", ASILLevel.ASIL_B, True)  # Protects safety functions
    BOOTLOADER = ("bootloader", ASILLevel.ASIL_B, True)  # Update integrity
    
    # NON-SAFETY-CRITICAL (QM)
    INFOTAINMENT_APP = ("infotainment_app", ASILLevel.QM, False)
    NAVIGATION = ("navigation", ASILLevel.QM, False)
    MEDIA_PLAYER = ("media_player", ASILLevel.QM, False)
    BLUETOOTH = ("bluetooth", ASILLevel.QM, False)
    WIFI = ("wifi", ASILLevel.QM, False)
    CLIMATE_CONTROL = ("climate_control", ASILLevel.QM, False)
    SEAT_ADJUSTMENT = ("seat_adjustment", ASILLevel.QM, False)
    AMBIENT_LIGHTING = ("ambient_lighting", ASILLevel.QM, False)
    VOICE_ASSISTANT = ("voice_assistant", ASILLevel.QM, False)
    OTA_CLIENT = ("ota_client", ASILLevel.ASIL_A, True)  # Infrastructure, affects updates
    
    def __init__(self, name: str, asil: ASILLevel, is_safety_critical: bool):
        self._name = name
        self.asil = asil
        self.is_safety_critical = is_safety_critical


class SDVSafetyClassifier:
    """
    Classifies OTA updates as safety-critical or non-safety-critical
    based on affected components, zones, and functions.
    """
    
    # Zone-level classification
    SAFETY_CRITICAL_ZONES = {
        SDVZone.POWERTRAIN,
        SDVZone.CHASSIS,
        SDVZone.ADAS,
    }
    
    NON_SAFETY_ZONES = {
        SDVZone.INFOTAINMENT,
        SDVZone.CONNECTIVITY,
        SDVZone.COMFORT,
        SDVZone.CONVENIENCE,
    }
    
    # Keyword mapping for automatic detection
    SAFETY_CRITICAL_KEYWORDS = {
        # Braking
        'brake', 'braking', 'abs', 'ebs', 'brake-by-wire',
        
        # Steering
        'steering', 'eps', 'steer-by-wire', 'steering control',
        
        # Powertrain
        'engine', 'motor', 'transmission', 'powertrain', 'drivetrain',
        'throttle', 'acceleration', 'torque', 'ecu', 'battery management',
        'bms', 'high voltage',
        
        # ADAS/Autonomous
        'adas', 'autonomous', 'self-driving', 'autopilot', 'adaptive cruise',
        'acc', 'lane keeping', 'lka', 'collision avoidance', 'aeb',
        'parking assist', 'surround view',
        
        # Safety Systems
        'airbag', 'srs', 'restraint', 'esc', 'traction control',
        'stability control', 'rollover', 'crash detection',
        
        # Critical Infrastructure
        'gateway', 'bootloader', 'secure boot', 'hsm', 'firewall',
        'security module', 'crypto',
    }
    
    NON_SAFETY_KEYWORDS = {
        'infotainment', 'entertainment', 'media', 'audio', 'radio',
        'navigation', 'map', 'gps', 'bluetooth', 'wifi', 'connectivity',
        'app', 'application', 'ui', 'display', 'screen', 'hmi',
        'climate', 'hvac', 'seat', 'comfort', 'ambient', 'lighting',
        'voice', 'assistant', 'telematics', 'cloud', 'mobile',
    }
    
    def __init__(self):
        self.classification_log = []
    
    def classify_by_description(self, description: str) -> bool:
        """
        Classify based on text description of the update/threat.
        
        Args:
            description: Natural language description of the update or vulnerability
        
        Returns:
            True if safety-critical, False otherwise
        """
        description_lower = description.lower()
        
        # Count keyword matches
        safety_matches = sum(
            1 for keyword in self.SAFETY_CRITICAL_KEYWORDS 
            if keyword in description_lower
        )
        
        non_safety_matches = sum(
            1 for keyword in self.NON_SAFETY_KEYWORDS 
            if keyword in description_lower
        )
        
        # Log the analysis
        self.classification_log.append({
            'description': description[:100],
            'safety_matches': safety_matches,
            'non_safety_matches': non_safety_matches,
        })
        
        # Decision logic
        if safety_matches > 0 and non_safety_matches == 0:
            return True
        elif safety_matches == 0 and non_safety_matches > 0:
            return False
        elif safety_matches > non_safety_matches:
            return True
        elif non_safety_matches > safety_matches:
            return False
        else:
            # Ambiguous - default to safety-critical (fail-safe)
            return True
    
    def classify_by_zone(self, zone: SDVZone) -> bool:
        """
        Classify based on SDV zone.
        
        Args:
            zone: SDVZone enum value
        
        Returns:
            True if safety-critical, False otherwise
        """
        if zone in self.SAFETY_CRITICAL_ZONES:
            return True
        elif zone in self.NON_SAFETY_ZONES:
            return False
        else:
            # Gateway/Telematics are context-dependent, default to critical
            return True
    
    def classify_by_function(self, function: AutomotiveFunction) -> bool:
        """
        Classify based on automotive function.
        
        Args:
            function: AutomotiveFunction enum value
        
        Returns:
            True if safety-critical, False otherwise
        """
        return function.is_safety_critical
    
    def classify_by_asil(self, asil_level: ASILLevel) -> bool:
        """
        Classify based on ASIL level.
        
        Args:
            asil_level: ASILLevel enum value
        
        Returns:
            True if ASIL A or higher, False for QM
        """
        return asil_level != ASILLevel.QM
    
    def classify_comprehensive(
        self,
        description: Optional[str] = None,
        zone: Optional[SDVZone] = None,
        function: Optional[AutomotiveFunction] = None,
        asil: Optional[ASILLevel] = None,
        affected_ecus: Optional[List[str]] = None,
    ) -> Dict:
        """
        Comprehensive classification using all available information.
        
        Args:
            description: Text description
            zone: SDV zone
            function: Automotive function
            asil: ASIL level
            affected_ecus: List of affected ECU names
        
        Returns:
            Dict with classification results and confidence
        """
        results = []
        weights = []
        
        # Description-based (weight: 0.3)
        if description:
            desc_result = self.classify_by_description(description)
            results.append(desc_result)
            weights.append(0.3)
        
        # Zone-based (weight: 0.25)
        if zone:
            zone_result = self.classify_by_zone(zone)
            results.append(zone_result)
            weights.append(0.25)
        
        # Function-based (weight: 0.25)
        if function:
            func_result = self.classify_by_function(function)
            results.append(func_result)
            weights.append(0.25)
        
        # ASIL-based (weight: 0.2)
        if asil:
            asil_result = self.classify_by_asil(asil)
            results.append(asil_result)
            weights.append(0.2)
        
        # ECU name analysis (weight: 0.15 if present)
        if affected_ecus:
            ecu_text = ' '.join(affected_ecus).lower()
            ecu_result = self.classify_by_description(ecu_text)
            results.append(ecu_result)
            weights.append(0.15)
        
        # Normalize weights
        total_weight = sum(weights)
        if total_weight > 0:
            normalized_weights = [w / total_weight for w in weights]
        else:
            # No inputs provided - default to safety-critical
            return {
                'is_safety_critical': True,
                'confidence': 0.0,
                'reasoning': 'No information provided, defaulting to safety-critical',
                'vote_breakdown': {},
            }
        
        # Weighted voting
        safety_score = sum(
            1.0 * w if r else 0.0 
            for r, w in zip(results, normalized_weights)
        )
        
        is_safety_critical = safety_score >= 0.5
        confidence = abs(safety_score - 0.5) * 2  # Scale to 0-1
        
        # Build vote breakdown safely
        vote_breakdown = {}
        result_idx = 0
        
        if description:
            vote_breakdown['description'] = results[result_idx]
            result_idx += 1
        
        if zone:
            vote_breakdown['zone'] = results[result_idx] if result_idx < len(results) else None
            result_idx += 1
        
        if function:
            vote_breakdown['function'] = results[result_idx] if result_idx < len(results) else None
            result_idx += 1
        
        if asil:
            vote_breakdown['asil'] = results[result_idx] if result_idx < len(results) else None
            result_idx += 1
        
        if affected_ecus:
            vote_breakdown['ecus'] = results[result_idx] if result_idx < len(results) else None
        
        return {
            'is_safety_critical': is_safety_critical,
            'confidence': confidence,
            'safety_score': safety_score,
            'vote_breakdown': vote_breakdown,
            'reasoning': self._generate_reasoning(
                is_safety_critical, confidence, description, zone, function
            ),
        }
    
    def _generate_reasoning(
        self,
        is_safety_critical: bool,
        confidence: float,
        description: Optional[str],
        zone: Optional[SDVZone],
        function: Optional[AutomotiveFunction],
    ) -> str:
        """Generate human-readable reasoning for the classification."""
        reasons = []
        
        if description and self.classification_log:
            log = self.classification_log[-1]
            if log['safety_matches'] > 0:
                reasons.append(
                    f"Description contains {log['safety_matches']} safety-critical keywords"
                )
            if log['non_safety_matches'] > 0:
                reasons.append(
                    f"Description contains {log['non_safety_matches']} non-safety keywords"
                )
        
        if zone:
            if zone in self.SAFETY_CRITICAL_ZONES:
                reasons.append(f"Zone '{zone.value}' is safety-critical")
            else:
                reasons.append(f"Zone '{zone.value}' is non-safety-critical")
        
        if function:
            reasons.append(
                f"Function '{function._name}' has ASIL {function.asil.name}"
            )
        
        result_str = "SAFETY-CRITICAL" if is_safety_critical else "NON-SAFETY-CRITICAL"
        conf_str = f"(confidence: {confidence:.1%})"
        
        return f"{result_str} {conf_str} - " + "; ".join(reasons)


# Convenience function for integration with existing code
def auto_classify_safety_critical(
    description: str,
    zone: Optional[str] = None,
    function: Optional[str] = None,
    affected_user: Optional[str] = None,
) -> bool:
    """
    Automatically classify if an update is safety-critical.
    
    This is the main function to use in service.py
    
    Args:
        description: Description of the update/vulnerability
        zone: Optional SDV zone name (string)
        function: Optional function name (string)
        affected_user: Optional affected user scope (for additional context)
    
    Returns:
        True if safety-critical, False otherwise
    """
    classifier = SDVSafetyClassifier()
    
    # Convert string inputs to enums if provided
    zone_enum = None
    if zone:
        try:
            zone_enum = SDVZone(zone.lower())
        except ValueError:
            pass  # Invalid zone, will be ignored
    
    function_enum = None
    if function:
        # Try to match function name
        for func in AutomotiveFunction:
            if func._name.lower() == function.lower():
                function_enum = func
                break
    
    # Run classification
    result = classifier.classify_comprehensive(
        description=description,
        zone=zone_enum,
        function=function_enum,
    )
    
    print(f"\n🛡️  Safety Classification: {result['reasoning']}")
    
    return result['is_safety_critical']


if __name__ == '__main__':
    # Test cases
    classifier = SDVSafetyClassifier()
    
    test_cases = [
        {
            'name': 'Infotainment XSS',
            'description': 'XSS vulnerability in the infotainment web interface allowing script injection',
            'zone': 'infotainment',
            'expected': False,
        },
        {
            'name': 'Brake ECU firmware',
            'description': 'Malicious firmware update for the ABS brake control module',
            'zone': 'chassis',
            'expected': True,
        },
        {
            'name': 'Navigation map update',
            'description': 'Corrupted map data in the GPS navigation system',
            'zone': 'infotainment',
            'expected': False,
        },
        {
            'name': 'Gateway compromise',
            'description': 'Authentication bypass in the central gateway ECU',
            'zone': 'gateway',
            'expected': True,
        },
        {
            'name': 'ADAS sensor fusion',
            'description': 'Buffer overflow in autonomous driving sensor fusion module',
            'zone': 'adas',
            'expected': True,
        },
        {
            'name': 'Bluetooth audio',
            'description': 'Bluetooth pairing vulnerability in media player',
            'zone': 'connectivity',
            'expected': False,
        },
    ]
    
    print("="*80)
    print("SDV SAFETY CLASSIFIER - TEST RESULTS")
    print("="*80)
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n🧪 Test {i}: {test['name']}")
        print(f"   Description: {test['description']}")
        
        zone_enum = SDVZone(test['zone']) if test['zone'] != 'gateway' else None
        
        result = classifier.classify_comprehensive(
            description=test['description'],
            zone=zone_enum,
        )
        
        is_correct = result['is_safety_critical'] == test['expected']
        status = "✅ PASS" if is_correct else "❌ FAIL"
        
        print(f"   {status}")
        print(f"   Result: {result['reasoning']}")
        print(f"   Expected: {'SAFETY-CRITICAL' if test['expected'] else 'NON-SAFETY-CRITICAL'}")