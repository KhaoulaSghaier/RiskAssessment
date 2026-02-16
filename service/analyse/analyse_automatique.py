from service.analyse.TARA import *
from service.analyse.HARA import *
from service.analyse.DREAD import *


RISK_LEVELS = {
    'VERY_LOW': {
        'range': (0, 1.0),
        'numeric': 1,
        'color': '🟢',
        'priority': 5
    },
    'LOW': {
        'range': (1.0, 2.0),
        'numeric': 2,
        'color': '🟡',
        'priority': 4
    },
    'MEDIUM': {
        'range': (2.0, 3.5),
        'numeric': 3,
        'color': '🟠',
        'priority': 3
    },
    'HIGH': {
        'range': (3.5, 4.5),
        'numeric': 4,
        'color': '🔴',
        'priority': 2
    },
    'CRITICAL': {
        'range': (4.5, 5.0),
        'numeric': 5,
        'color': '🚨',
        'priority': 1
    }
}



class analyse_automatique:
    def __init__(self,scenario):
        self.scenario = scenario
        self.tara = None
        self.hara = None
        self.dread = None

    def compileDread(self):
        damage = self.scenario["level_damage"]
        #reproduction = (self.scenario["knowledge_cible"] + self.scenario["expertise"]) / 2
        #exploitation = self.scenario["necessary_material"]
        #discover = self.scenario["attack_discovery"]
        affected_user = self.scenario["affected_user"]
        self.dread = Dread(damage,affected_user)

    def compileTARA(self):
        # Impact categories
        safety = self.scenario.get("safety_tara", 0)        # {0, 10, 100, 1000}
        financial = self.scenario.get("financial_tara", 0)  # {0, 10, 100, 1000}
        operational = self.scenario.get("operational_tara", 0)  # {0, 1, 10, 100}
        privacy = self.scenario.get("privacy_tara", 0)      # {0, 1, 10, 100} 
        
        # Feasibility parameters
        attack_vector = self.scenario["attack_vector"]
        attack_complexity = self.scenario['attack_complexity']
        privileges_required = self.scenario['privileges_required']
        user_interaction = self.scenario['user_interaction']
        
        self.tara = TARA(
            safety, financial, operational, privacy,
            attack_vector, attack_complexity, privileges_required, user_interaction
        )
    def compileHara(self):
        # Use ISO 26262 classes (1-3 for S/C, 1-4 for E)
        severity_iso = self.scenario.get("severity_iso", 1)         # 1-3
        exposure_iso = self.scenario.get("exposure_iso", 1)          # 1-4
        controllability_iso = self.scenario.get("controllability_iso", 1)  # 1-3
        
        # HARA expects (exposure, controllability, severity)
        self.hara = Hara(exposure_iso, controllability_iso, severity_iso)
        print(f"   🔍 HARA ISO Classes: f(S{severity_iso},E{exposure_iso},C{controllability_iso})")

    def compile_all(self):
        self.compileHara()
        self.compileTARA()
        self.compileDread()

    def get_risk(self):
        self.compile_all()
        val1 = self.hara.getRisque()
        val2 = self.tara.Risque()
        val3 = self.dread.get_risque()
        print('HARA:', val1)
        print('TARA:', val2)
        print('DREAD', val3)
        
        aggregator = RiskAggregator(
            tara_score=val2,
            hara_score=val1,
            dread_score=val3,
            safety_critical_update = self.scenario['safety_critical_update'] 
            )
        return aggregator.weighted_aggregation()
    
    def get_risk_level(self, score):
        #Map continuous score (1-5) to risk level
        for level, props in RISK_LEVELS.items():
            if props['range'][0] <= score < props['range'][1]:
                return level, props
        return 'CRITICAL', RISK_LEVELS['CRITICAL']  # Fallback for score >= 5

class RiskAggregator:
    def __init__(self, tara_score, hara_score, dread_score, safety_critical_update=True):
        """
        Args:
            tara_score: Cyber threat risk (1-5)
            hara_score: Safety hazard level (1-5) 
            dread_score: Attack impact scale (1-5)
            safety_critical: Boolean flag for safety-critical updates
        """
        self.tara = tara_score
        self.hara = hara_score
        self.dread = dread_score
        self.safety_critical_update = safety_critical_update
        
    def weighted_aggregation(self):
        # Define weights based on context
        if self.safety_critical_update:
            # Safety-critical: HARA dominates 
            w_tara = 0.25
            w_hara = 0.50  
            w_dread = 0.25
        else:
            # Non-critical: Balanced approach
            w_tara = 0.40  
            w_hara = 0.40 
            w_dread = 0.20 

        return self.hara * w_hara + self.tara * w_tara + self.dread * w_dread
#value = analyse_automatique(test_case).get_risk()
#print(value)