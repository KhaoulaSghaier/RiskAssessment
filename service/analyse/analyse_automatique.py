from service.analyse.TARA import *
from service.analyse.HARA import *
from service.analyse.DREAD import *



"""
  # Partie Analyse
        'opportunity' : "Unlimited" ... TARA Opportunity
        'knowledge_cible':
        'exploitability': TARA
        'expertise': "Expert" ... TARA expertise | DREAD = tara (moyenne knowledge and expertise) REPRODUCTIBILITY
        'attack_discovery': 0-10        DREAD DISCOVERY
        'elapsed_time': "YEAR" ...       TARA elapsed_time
        'necessary_material': 0-10      DREAD EXPLOITABILITY | TARA EQUIPEMENT
        'level_damage':  0-10           DREAD DAMAGE       | TARA (moyenne level_damage and operationnal_impact) financial
        'affected_user': 0-10           DREAD AFFECTED_USER
        'operationnel_impact': 0-10     TARA : (operationnel_impact * 15) OPERATIONNEL | HARA  si TARA [150 - 50] = 3 / [50-10] = 2 / [10,0] = 1 CONTROLABILITY
        'leak_information': 0- 10       TARA: (leak_information * 15) PRIVACY| HARA (leak_information * 4 / 10) EXPOSURE
        'severity': 0-11                HARA SEVERITY | TARA (severity * 100) SAFETY |
"""

test_case  = {
        'opportunity' : "Unlimited",
        'knowledge_cible': 'Restricted',
        'expertise': 'Layman',
        'attack_discovery': 10,
        'elapsed_time': "day" ,
        'necessary_material': 10,
        'level_damage':  0,
        'affected_user':  10,
        'operationnel_impact': 10,
    'leak_information': 10,
    'severity': 10 ,
}


"""
 return {
        'severity': 11 if get_severity > 11 else get_severity ,
        'expertise': (getCapec.getLikehood() + necessary_material)/2,
        'exploitability': max(epss * 10,1),
        'attack_discovery': getCapec.getLikehood(),
        'knowledge_cible':knowledge_map.get(template_base.get('type_cible')),
        'necessary_material': material_map.get(template_base.get('type_cible')),
        'level_damage': 10 if (round((get_severity + operation_impact) /2)) > 10 else (round((get_severity + operation_impact) /2)),
        'affected_user': map_affected_user.get(template_base.get('affected_user')),
        'operationnel_impact': operation_impact,
        'leak_information': getCapec.isConfenditalThreat() ,
        'attack_vector': elt2,
        'attack_complexity': attack_complexity,
        "privilege_required": elt1,
        "user interaction":   user_interaction,
    }
    
"""

RISK_LEVELS = {
    'VERY_LOW': {
        'range': (0, 1.0),
        'numeric': 1,
        'color': '🟢',
        #'action': 'Accept - No action required',
        'priority': 5
    },
    'LOW': {
        'range': (1.0, 2.0),
        'numeric': 2,
        'color': '🟡',
        #'action': 'Monitor - Review periodically',
        'priority': 4
    },
    'MEDIUM': {
        'range': (2.0, 3.5),
        'numeric': 3,
        'color': '🟠',
        #'action': 'Mitigate - Plan risk treatment',
        'priority': 3
    },
    'HIGH': {
        'range': (3.5, 4.5),
        'numeric': 4,
        'color': '🔴',
        #'action': 'Remediate - Immediate action required',
        'priority': 2
    },
    'CRITICAL': {
        'range': (4.5, 5.0),
        'numeric': 5,
        'color': '🚨',
        #'action': 'Emergency - Stop deployment',
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
        reproduction = (self.scenario["knowledge_cible"] + self.scenario["expertise"]) / 2
        exploitation = self.scenario["necessary_material"]
        discover = self.scenario["attack_discovery"]
        affected_user = self.scenario["affected_user"]
        self.dread = Dread(damage,reproduction,exploitation,affected_user,discover)

    def compileTARA(self):


        Opportunity = {  # Windows opportunity
            'Unlimited': [0, 1],
            'Much': [1, 4],
            'Moderate': [4, 10],
            'Difficult': [10, -1],
        }

        safety = self.scenario["severity"] * 100
        financial = round(((self.scenario["level_damage"] + self.scenario["operationnel_impact"]) / 2 )) * 15
        operational = self.scenario["operationnel_impact"] * 15
        privacy = self.scenario["leak_information"] * 15
        attack_vector = self.scenario["attack_vector"]
        attack_complexity = self.scenario['attack_complexity']
        privileges_required = self.scenario['privileges_required']
        user_interaction = self.scenario['user_interaction']


        self.tara = TARA(safety,financial,operational,privacy,attack_vector,attack_complexity,privileges_required,user_interaction)

    def compileHara(self):
        exposure =round((self.scenario["leak_information"] * 4) / 10)
        severy = 0
        if self.scenario["severity"] == 11:
            severy = 4
        else:
            severy = round((self.scenario["severity"] * 4) / 10)
        compare = self.scenario["operationnel_impact"] * 15
        controllability = 0
        if 50 <= compare <= 150:
            controllability = 3
        elif 10 <= compare < 50:
            controllability = 2
        elif 0 < compare < 10:
            controllability = 1
        else:
            controllability = 0
        self.hara = Hara(exposure,controllability,severy)

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
        
        #return max(val1,val2,val3)
        aggregator = RiskAggregator(
            tara_score=val2,
            hara_score=val1,
            dread_score=val3,
            safety_critical_update = self.scenario['safety_critical_update'] 
            )
        return aggregator.weighted_aggregation()
    
    def get_risk_level(self, score):
        #Map continuous score (0-5) to risk level
        for level, props in RISK_LEVELS.items():
            if props['range'][0] <= score < props['range'][1]:
                return level, props
        return 'CRITICAL', RISK_LEVELS['CRITICAL']  # Fallback for score >= 5

class RiskAggregator:
    def __init__(self, tara_score, hara_score, dread_score, safety_critical_update=False):
        """
        Args:
            tara_score: Cyber threat risk (0-5)
            hara_score: Safety hazard level (0-5) 
            dread_score: Attack impact scale (0-5)
            safety_critical: Boolean flag for safety-critical updates
        """
        self.tara = tara_score
        self.hara = hara_score
        self.dread = dread_score
        self.safety_critical_update = safety_critical_update
        
    def weighted_aggregation(self):
        # Define weights based on context
        if self.safety_critical_update:
            # Safety-critical: HARA dominates (50% weight)
            w_tara = 0.25
            w_hara = 0.50  # Double weight for functional safety
            w_dread = 0.25
        else:
            # Non-critical: Balanced approach
            w_tara = 0.40  # Automotive
            w_hara = 0.40  # Automotive
            w_dread = 0.20  # Attack scale matters

        return self.hara * w_hara + self.tara * w_tara + self.dread * w_dread
#value = analyse_automatique(test_case).get_risk()
#print(value)