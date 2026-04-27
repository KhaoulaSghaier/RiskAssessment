# Critère qui vont vérifier qu'on respect bien
# les critères de sécurité imporsé par la CIA(confidentiality,Integrity,Availabiliity)
# low = 0 and max = 12
import numpy as np

critereImpact = {
    'Safety': {
        'No impact': 0, # No injuries
        'Low': 10, # Light injury
        'Medium': 100, # Severe injury
        'High': 1000, # threat against life
    },
    'Financial' : {
        'No impact': 0, # Negligible losses
        'Low': 10, # Moderate Losses
        'Medium': 100, # Substantial losses
        'High': 1000 # Personnal Bankruptcy
    },
    'Operationnal': {
        'No impact': 0,  # Neglibible Disturbance
        'Low':1,  # Vehicle mostly Operationnal
        'Medium': 10,  # Serious limitation in Vehicule Operation
        'High': 100  # Vehicle not Operationnal
    },
    'Privacy': {
        'No impact': 0, # Few Inconveniences
        'Low': 1, # Siginificant Inconveniences
        'Medium': 10, # Serious Impact on PII
        'High': 100 # Irreversible Impact on PII
    }
}

cvss_mapping = {
    # Attack Vector (V)
    "attack_vector": {
        "NETWORK": 0.85,  # Attaque à distance via réseau
        "ADJACENT": 0.62,  # Attaque depuis le réseau adjacent
        "LOCAL": 0.55,  # Accès local requis
        "PHYSICAL": 0.20  # Accès physique nécessaire
    },

    # Attack Complexity (C)
    "attack_complexity": {
        "LOW": 0.77,  # Conditions d'exploitation simples
        "HIGH": 0.44  # Conditions complexes/specific
    },

    # Privileges Required (P)
    "privileges_required": {
        "NONE": 0.85,  # Aucun privilège requis
        "LOW": 0.62,  # Privilèges utilisateur de base
        "HIGH": 0.27  # Privilèges administrateur
    },

    # User Interaction (U)
    "user_interaction": {
        "NONE": 0.85,  # Aucune interaction utilisateur
        "REQUIRED": 0.62  # Action utilisateur nécessaire
    }
}



FeasabilityRating = {
    'Very low': 0,
    'Low': 1,
    'Medium':1.5,
    'High':2,
}
ImpactRating = {
    'Neglible': 0,
    'Moderate': 1,
    'Serious': 1.5,
    'Severe': 2,
}


# Dans TARA.py, remplacer les fonctions getImpactInfo() et calcul_impact()

class TARA:
    def __init__(self, safety, financial, operational, privacy,
                 attack_vector, attack_complexity, privileges_required, user_interaction):
        """
        Initialize TARA with discrete ISO 21434 values
        """
        # Store discrete impact values
        self.safety = safety
        self.financial = financial
        self.operational = operational
        self.privacy = privacy
        
        # CVSS metrics
        self.attack_vector_str = attack_vector
        self.attack_complexity_str = attack_complexity
        self.privileges_required_str = privileges_required
        self.user_interaction_str = user_interaction
        
        # CVSS weight mapping
        self.cvss_mapping = {
            "attack_vector": {
                "NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.20,
                "N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20
            },
            "attack_complexity": {
                "LOW": 0.77, "HIGH": 0.44,
                "L": 0.77, "H": 0.44
            },
            "privileges_required": {
                "NONE": 0.85, "LOW": 0.62, "HIGH": 0.27,
                "N": 0.85, "L": 0.62, "H": 0.27
            },
            "user_interaction": {
                "NONE": 0.85, "REQUIRED": 0.62,
                "N": 0.85, "R": 0.62
            }
        }
        
        # Calculate feasibility weights
        self.av_weight = self.cvss_mapping["attack_vector"][attack_vector.upper()]
        self.ac_weight = self.cvss_mapping["attack_complexity"][attack_complexity.upper()]
        self.pr_weight = self.cvss_mapping["privileges_required"][privileges_required.upper()]
        self.ui_weight = self.cvss_mapping["user_interaction"][user_interaction.upper()]
        
        self.feasibility = np.array([self.av_weight, self.ac_weight, self.pr_weight, self.ui_weight])
        
        # Print detailed breakdown
        self._print_tara_details()
    
    def _print_tara_details(self):
        """Print comprehensive TARA parameter breakdown"""
        print("\n" + "="*70)
        print("   TARA PARAMETER BREAKDOWN")
        print("="*70)
        
        # Impact scores
        print("\n   📊 IMPACT SCORES (Discrete ISO 21434 Values):")
        print(f"      Safety:       {self.safety:>4}  {'🔴' if self.safety >= 1000 else '🟡' if self.safety >= 100 else '🟢'}")
        print(f"      Financial:    {self.financial:>4}  {'🔴' if self.financial >= 1000 else '🟡' if self.financial >= 100 else '🟢'}")
        print(f"      Operational:  {self.operational:>4}  {'🔴' if self.operational >= 100 else '🟡' if self.operational >= 10 else '🟢'}")
        print(f"      Privacy:      {self.privacy:>4}  {'🔴' if self.privacy >= 100 else '🟡' if self.privacy >= 10 else '🟢'}")
        
        # Calculate impact sum and rating
        impact_sum = self.safety + self.financial + self.operational + self.privacy
        impact_rating = self.calcul_impact()
        impact_level = self.getImpactInfo()
        
        print(f"\n      Impact Sum:   {impact_sum:>4}  (max: 2200)")
        print(f"      Impact Level: {impact_level}")
        print(f"      Impact Rating: {impact_rating}")
        
        # Feasibility parameters
        print("\n   🎯 FEASIBILITY PARAMETERS (CVSS v3.1):")
        print(f"      Attack Vector (AV):        {self.attack_vector_str:<10} → weight: {self.av_weight}")
        print(f"      Attack Complexity (AC):    {self.attack_complexity_str:<10} → weight: {self.ac_weight}")
        print(f"      Privileges Required (PR):  {self.privileges_required_str:<10} → weight: {self.pr_weight}")
        print(f"      User Interaction (UI):     {self.user_interaction_str:<10} → weight: {self.ui_weight}")
        
        # Calculate exploitability and feasibility
        exploitability = self.calcul_exploitability()
        feasibility_rating = self.calcul_feasibility()
        
        print(f"\n      Exploitability Score: {exploitability:.2f}  (formula: 8.22 × {self.av_weight} × {self.ac_weight} × {self.pr_weight} × {self.ui_weight})")
        print(f"      Feasibility Rating:   {feasibility_rating}")
        
        # Feasibility level
        if 0.12 <= feasibility_rating <= 1.05:
            feasibility_level = "Very Low"
        elif 1.06 < feasibility_rating <= 1.99:
            feasibility_level = "Low"
        elif 2 < feasibility_rating <= 2.95:
            feasibility_level = "Medium"
        elif 2.96 < feasibility_rating <= 3.89:
            feasibility_level = "High"
        else:
            feasibility_level = "Very Low"
        
        print(f"      Feasibility Level:    {feasibility_level}")
        
        # Final risk
        tara_risk = self.Risque()
        print(f"\n   🎯 TARA FINAL RISK:")
        print(f"      Formula: 1 + (Impact × Feasibility)")
        print(f"      Risk = 1 + ({impact_rating} × {feasibility_rating})")
        print(f"      TARA Risk Score: {tara_risk} / 5.0")
        
        # Risk classification
        if tara_risk >= 4.0:
            risk_class = "🔴 CRITICAL"
        elif tara_risk >= 3.0:
            risk_class = "🟠 HIGH"
        elif tara_risk >= 2.0:
            risk_class = "🟡 MEDIUM"
        else:
            risk_class = "🟢 LOW"
        
        print(f"      Classification: {risk_class}")
        print("="*70 + "\n")
    
    def calcul_exploitability(self):
        """Calculate CVSS exploitability score"""
        return 8.22 * np.prod(self.feasibility)
    
    def getImpactInfo(self):
        """Determine impact level from discrete impact sum"""
        impact_sum = self.safety + self.financial + self.operational + self.privacy
        
        if impact_sum >= 1000:
            return 'Severe'
        elif impact_sum >= 100:
            return 'Serious'
        elif impact_sum >= 10:
            return 'Moderate'
        else:
            return 'Negligible'
    
    def calcul_impact(self):
        """Calculate impact rating (0-2) for TARA formula"""
        impact_info = self.getImpactInfo()
        
        impact_rating_map = {
            'Negligible': 0,
            'Moderate': 1,
            'Serious': 1.5,
            'Severe': 2
        }
        
        return impact_rating_map[impact_info]
    
    def calcul_feasibility(self):
        """Calculate attack feasibility rating (0-2)"""
        exploitability = self.calcul_exploitability()
        
        if exploitability >= 2.96:
            return 2      # High
        elif exploitability >= 2.0:
            return 1.5    # Medium
        elif exploitability >= 1.06:
            return 1      # Low
        else:
            return 0      # Very Low
    
    def Risque(self):
        """Calculate final TARA risk score"""
        impact_rating = self.calcul_impact()
        feasibility_rating = self.calcul_feasibility()
        
        tara_risk = 1 + (impact_rating * feasibility_rating)
        
        return round(tara_risk, 2)



