
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

    def __init__(self,damage,reproductability, exploitability, affected_user,discoverability):
        self.impact = np.array([10 - damage,10 - reproductability,10 -exploitability,10 -affected_user,discoverability])

    def get_impact(self):
        """
        méthode qui récupère la liste des niveaux dread pour chaque catégories
        :return: une liste des différentes niveaux dread pour chaque catégorie
        """
        categories = ['Damage', 'Reproducibility','Exploitability', 'Affected_Users', 'Discoverability']
        result = {}
        for i,category in enumerate(categories):
            input_impact = np.round(self.impact[i])
            level_dread = DreadImpact[category]
            res_level = None
            res_value = 0
            for level,value in level_dread.items():
                if input_impact < value:
                    if res_level is None:
                        res_level = level
                    break
                else:
                    res_level = level
                    res_value = value
            result[category] = { 'inputValue': self.impact[i], 'SetValue': res_value, 'level': res_level}
        return result

    def get_risque(self):
        """
        méthode qui récupère le risque : en  appliquant le mapping des valeurs, de la manière suivante:
        1. faire la somme des valeurs de chaque catégories
        2. regarder dans quel interval on se situe
        :return: le risque dread
        """
        get_all = self.get_impact()
        impact_total = np.sum(np.array([element['SetValue'] for element in get_all.values()]))
        if impact_total <= 10:
            return 1 # Low
        elif impact_total <= 24:
            return 2 # Medium
        elif impact_total <= 39:
            return 3 # High
        else:
            return 4 # critical
