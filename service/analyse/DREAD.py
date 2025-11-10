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
    def __init__(self, damage, reproductability, exploitability, affected_user, discoverability):
        self.impact = np.array([
            damage,
            reproductability,
            exploitability,
            affected_user,
            discoverability
        ])

    def get_impact(self):
        """Mapping vers niveaux discrets"""
        categories = ['Damage', 'Reproducibility', 'Exploitability', 
                      'Affected_Users', 'Discoverability']
        result = {}
        
        for i, category in enumerate(categories):
            input_impact = np.round(self.impact[i])
            level_dread = DreadImpact[category]
            
            res_level = None
            res_value = 0
            
            # Trouve le niveau le plus proche (sans dépasser)
            for level, value in level_dread.items():
                if input_impact >= value:  # ✅ Plus grand ou égal
                    res_level = level
                    res_value = value
                else:
                    break
                    
            result[category] = {
                'inputValue': self.impact[i],
                'SetValue': res_value,
                'level': res_level
            }
        return result

    def get_risque(self):
        """
        Calcul du risque DREAD normalisé (1-4 pour compatibilité TARA/HARA)
        """
        get_all = self.get_impact()
        impact_total = np.sum([element['SetValue'] for element in get_all.values()])
        
        # ✅ Mapping cohérent (score max = 50)
        if impact_total <= 10:
            dread =  1  # Low (0-20% du max)
        elif impact_total <= 24:
            dread =  2  # Medium (21-48% du max)
        elif impact_total <= 39:
            dread =  3  # High (49-78% du max)
        else:
            dread = 4  # Critical (79-100% du max)
        return 1 + (dread - 1) * (4/3) 