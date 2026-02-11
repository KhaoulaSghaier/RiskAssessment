import numpy as np

# représente les différentes valeurs pour chaque catégorie dread
DreadImpact = {

    'Damage': {
     'Zero': 0,
     'Low': 5,
    'Non-Sensitive': 8,
    'Non-Sensitive+': 9,
     
    'Destruction': 10
    },
    'Reproducibility': {
    'Difficult': 0,
    'Complex': 5,
    'Easy': 7.5,
    'Very Easy': 10
    },
    'Exploitability': {
    'Difficult': 2.5,
    'Complex': 5,
    'Medium': 9,
    'Easy': 10
    }
    ,
    'Affected_Users':{
        'Zero': 0,
        'Low': 2.5,
        'Few': 6,
        'Administrative':8,
        'All':10,
    },

    'Discoverability':{
        'Hard':0,
        'OpenRequest':5,
        'PublicThreat': 8,
        'EasyThreat': 10
    }

}

# index = zone et string = niveaux d'user affécté
ZoneLevel = {
    0: 'ALL',
    1: 'Administrative',
    2: 'Few'
}


class Dread:
    """
    Simplified DREAD with 2 parameters for automotive OTA risk assessment
    
    Parameters:
    - damage: Severity of consequences {0, 5, 8, 9, 10}
    - affected_user: Fleet-scale impact {0, 2.5, 6, 8, 10}
    
    Risk normalized to [1.0, 5.0] for consistency with TARA and HARA
    """
    
    def __init__(self, damage, affected_user):
        """
        Initialize DREAD with 2 parameters
        
        Args:
            damage (float): {0, 5, 8, 9, 10}
            affected_user (float): {0, 2.5, 6, 8, 10}
        """
        self.damage = damage
        self.affected_user = affected_user
        
        # Store as array for compatibility
        self.impact = np.array([damage, affected_user])
    
    def get_risque(self):
        """
        Calculate DREAD risk score (1-5 scale)
        
        Formula:
            avg = (damage + affected_user) / 2
            risk = 1 + (avg / 10) × 4
        
        Simplified:
            risk = 1 + (damage + affected_user) / 5
        
        Returns:
            float: Risk score in [1.0, 5.0]
        """
        # Simple average (like DREAD original)
        dread_avg = (self.damage + self.affected_user) / 2.0
        
        # Normalize [0, 10] to [1, 5]
        dread_risk = 1.0 + (dread_avg / 10.0) * 4.0
        
        print(f"   🔍 DREAD Calculation:")
        print(f"      Damage: {self.damage}")
        print(f"      Affected Users: {self.affected_user}")
        print(f"      Average: {dread_avg:.2f}")
        print(f"      Risk (normalized [1,5]): {dread_risk:.2f}")
        
        return round(dread_risk, 2)
    
    def get_impact(self):
        """
        Return impact details (for compatibility with old code)
        
        Returns:
            dict: Impact breakdown
        """
        return {
            'damage': {'SetValue': self.damage},
            'affected_user': {'SetValue': self.affected_user}
        }
    
    def __str__(self):
        """String representation for debugging"""
        return f"DREAD(damage={self.damage}, affected_user={self.affected_user}, risk={self.get_risque()})"