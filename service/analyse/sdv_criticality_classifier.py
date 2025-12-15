"""
Simplified SDV Safety Classifier
Automatically determines if an OTA update is safety-critical based on keyword detection.
"""

from typing import Dict, Optional, List


class SimpleSafetyClassifier:
    """
    Simple keyword-based safety classifier for automotive OTA updates.
    No ASIL levels, no complex zones - just keyword detection.
    """
    
    # Safety-critical keywords (if found → CRITICAL)
    SAFETY_CRITICAL_KEYWORDS = {
        # Braking systems
        'brake', 'braking', 'abs', 'ebs', 'brake-by-wire', 'anti-lock',
        
        # Steering systems
        'steering', 'eps', 'steer-by-wire', 'power steering', 'steering control',
        
        # Powertrain / Engine
        'engine', 'motor', 'transmission', 'powertrain', 'drivetrain',
        'throttle', 'acceleration', 'torque', 'ecu', 'electronic control unit',
        
        # Battery / High Voltage
        'battery management', 'bms', 'high voltage', 'high-voltage',  # Be specific, not just 'hv'
        'hv battery', 'hv system', 'battery control',
        'charging system', 'power management',
        
        # ADAS / Autonomous
        'adas', 'autonomous', 'self-driving', 'autopilot', 
        'adaptive cruise control', 'adaptive cruise',  # Use full phrase, not just 'acc'
        'lane keeping', 'lka', 'collision avoidance', 'aeb',
        'automatic emergency', 'parking assist', 'surround view', 'sensor fusion',
        
        # Safety systems
        'airbag', 'srs', 'restraint', 'esc', 'traction control',
        'stability control', 'rollover', 'crash detection', 'collision',
        
        # Critical infrastructure
        'gateway', 'central gateway', 'domain controller', 'bootloader', 
        'secure boot', 'hsm', 'firewall', 'security module', 'crypto',
        
        # Critical ECUs
        'abs ecu', 'esp ecu', 'brake ecu', 'engine ecu', 'transmission ecu',
        'battery ecu', 'motor ecu', 'steering ecu',
        
        # OTA security critical
        'firmware signature', 'code signing', 'update verification',
        'secure update', 'ota security',
        
        # Can affect safety
        'can bus', 'vehicle control', 'drive control', 'safety function',
        'safety critical', 'critical system',
    }
    
    # Non-safety keywords (if found WITHOUT safety keywords → NON-CRITICAL)
    NON_SAFETY_KEYWORDS = {
        # Infotainment
        'infotainment', 'entertainment', 'media', 'audio', 'radio', 'speaker',
        'display', 'screen', 'hmi', 'user interface', 'ui', 'ux',
        
        # Navigation
        'navigation', 'map', 'gps', 'location', 'route', 'poi',
        
        # Connectivity
        'bluetooth', 'wifi', 'wi-fi', 'cellular', '4g', '5g', 'mobile',
        'connectivity', 'network', 'internet', 'cloud', 'app', 'application',
        
        # Comfort
        'climate', 'hvac', 'air conditioning', 'heating', 'ventilation',
        'seat', 'comfort', 'seating', 'massage',
        
        # Convenience
        'ambient', 'lighting', 'light', 'mirror', 'wiper', 'window',
        'voice', 'assistant', 'siri', 'alexa', 'hey google',
        
        # Entertainment features
        'video', 'movie', 'youtube', 'streaming', 'music', 'playlist',
        'podcast', 'game', 'gaming',
    }
    
    def __init__(self):
        self.classification_log = []
    
    def classify(
        self, 
        description: str,
        zone: Optional[str] = None,
        function: Optional[str] = None,
        affected_ecus: Optional[List[str]] = None
    ) -> Dict:
        """
        Classify if an update is safety-critical based on keywords.
        
        Args:
            description: Text description of the update/threat (REQUIRED)
            zone: Optional zone name (used for keyword matching)
            function: Optional function name (used for keyword matching)
            affected_ecus: Optional list of ECU names (used for keyword matching)
        
        Returns:
            Dict with:
                - is_safety_critical (bool): True if critical
                - confidence (float): 0.0-1.0
                - safety_keywords_found (list): Critical keywords found
                - non_safety_keywords_found (list): Non-critical keywords found
                - reasoning (str): Explanation
        """
        # Combine all text for analysis
        text_parts = [description or ""]
        if zone:
            text_parts.append(zone)
        if function:
            text_parts.append(function)
        if affected_ecus:
            text_parts.extend(affected_ecus)
        
        full_text = " ".join(text_parts).lower()
        
        # Find matching keywords
        safety_matches = [
            keyword for keyword in self.SAFETY_CRITICAL_KEYWORDS
            if keyword in full_text
        ]
        
        non_safety_matches = [
            keyword for keyword in self.NON_SAFETY_KEYWORDS
            if keyword in full_text
        ]
        
        # Classification logic
        if safety_matches:
            # Any safety-critical keyword → CRITICAL
            is_critical = True
            confidence = 1.0 if not non_safety_matches else 0.8
            reasoning = f"SAFETY-CRITICAL - Found {len(safety_matches)} critical keyword(s): {', '.join(safety_matches[:3])}"
            
        elif non_safety_matches:
            # Only non-safety keywords → NON-CRITICAL
            is_critical = False
            confidence = 1.0
            reasoning = f"NON-SAFETY-CRITICAL - Found only non-critical keywords: {', '.join(non_safety_matches[:3])}"
            
        else:
            # No keywords matched → Default to CRITICAL (fail-safe)
            is_critical = True
            confidence = 0.0
            reasoning = "SAFETY-CRITICAL (default) - No recognizable keywords, failing safe"
        
        # Log the classification
        self.classification_log.append({
            'text': full_text[:100],
            'is_critical': is_critical,
            'confidence': confidence,
        })
        
        return {
            'is_safety_critical': is_critical,
            'confidence': confidence,
            'safety_keywords_found': safety_matches,
            'non_safety_keywords_found': non_safety_matches,
            'reasoning': reasoning,
        }


# Global instance for convenience
_classifier = SimpleSafetyClassifier()


def auto_classify_safety_critical(
    description: str,
    zone: Optional[str] = None,
    function: Optional[str] = None,
    affected_ecus: Optional[List[str]] = None
) -> bool:
    """
    Simple function to classify if an update is safety-critical.
    
    Args:
        description: Description of the update/vulnerability
        zone: Optional zone name
        function: Optional function name  
        affected_ecus: Optional list of ECU names
    
    Returns:
        True if safety-critical, False otherwise
    """
    result = _classifier.classify(
        description=description,
        zone=zone,
        function=function,
        affected_ecus=affected_ecus
    )
    
    print(f"\n🛡️  Safety Classification: {result['reasoning']}")
    
    return result['is_safety_critical']


if __name__ == '__main__':
    # Quick test
    classifier = SimpleSafetyClassifier()
    
    print("="*80)
    print("SIMPLE SDV SAFETY CLASSIFIER - QUICK TEST")
    print("="*80)
    
    test_cases = [
        {
            'description': 'XSS vulnerability in infotainment web interface',
            'expected': False,
        },
        {
            'description': 'Malicious firmware update for ABS brake control module',
            'expected': True,
        },
        {
            'description': 'Media player crashes when playing MP3 files',
            'expected': False,
        },
        {
            'description': 'Authentication bypass in central gateway ECU',
            'expected': True,
        },
        {
            'description': 'Buffer overflow in autonomous driving sensor fusion',
            'expected': True,
        },
    ]
    
    passed = 0
    for i, test in enumerate(test_cases, 1):
        result = classifier.classify(description=test['description'])
        is_correct = result['is_safety_critical'] == test['expected']
        
        status = "✅" if is_correct else "❌"
        print(f"\n{status} Test {i}: {test['description'][:60]}...")
        print(f"   Result: {result['reasoning']}")
        
        if is_correct:
            passed += 1
    
    print(f"\n{'='*80}")
    print(f"Tests Passed: {passed}/{len(test_cases)}")
    print(f"{'='*80}")