# Critère qui vont vérifier qu'on respect bien
# les critères de sécurité imporsé par la CIA(confidentiality,Integrity,Availabiliity)
# low = 0 and max = 12
import numpy as np

critereImpact = {
    'Safety': {
        'Negligible': [0,100], # No injuries
        'Moderate': [10,100], # Light injury
        'Serious': [100,1000], # Severe injury
        'Severe': [1000,-1], # threat against life
    },
    'Financial' : {
        'Neglible': [0,10], # Negligible losses
        'Moderate': [10,100], # Moderate Losses
        'Serrious': [100,150], # Substantial losses
        'Severe': [150,-1] # Personnal Bankruptcy
    },
    'Operationnal': {
        'Neglible': [0,10],  # Neglibible Disturbance
        'Moderate':[10,100],  # Vehicle mostly Operationnal
        'Serrious': [100,150],  # Serious limitation in Vehicule Operation
        'Severe': [150,-1]  # Vehicle not Operationnal
    },
    'Privacy': {
        'Neglible': [0,10], # Few Inconveniences
        'Moderate': [10,100], # Siginificant Inconveniences
        'Serious': [100,1000], # Serious Impact on PII
        'Severe': [150,-1] # Irreversible Impact on PII
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


class TARA:

    def __init__(self,safety,financial,operational,privacy,attack_vector,attack_complexity,privilege_required,user_interaction):
        """
        constructeur qui prend tout les paramètre tara pour faire l'analyse
        :param safety: score safety
        :param financial: score financial
        :param operational: score operational du template
        :param privacy: score privay du template
        :param attack_vector:  score attack vector du template
        :param attack_complexity:  score complexity du template
        :param privilege_required:  score privileges required du template
        :param user_interaction:  socre user interaction du template
        """
        self.impact = np.array([safety,financial,operational,privacy])
        self.feasability = np.array([cvss_mapping["attack_vector"][attack_vector.upper()],
                                     cvss_mapping["attack_complexity"][attack_complexity.upper()],
                                     cvss_mapping["privileges_required"][privilege_required.upper()],
                                     cvss_mapping["user_interaction"][user_interaction.upper()]])

    def getImpactInfo(self):
        """
        renvoie un dicitionnaire indiquant l'impact de la valeur et ou elle se situe selon le score
        par exemple pour financial,si la valeur vaut 60 alors la valeur de dictionnaire à cette forme:
        {'inputValue': 60, 'SetValue': [10,100], 'level': 'Moderate'}
        :return: liste de dictionnarie représentant chaque résultat de niveau d'impact
        """
        categories = ['Safety', 'Financial', 'Operationnal', 'Privacy']
        result = {}
        for i, category in enumerate(categories):
            input_impact = np.round(self.impact[i])
            level_tara = critereImpact[category]
            res_level = None
            res_value = 0
            for level, value in level_tara.items():
                if value[1] == -1:
                    res_level = level
                    res_value = value

                else:
                    res_level = level
                    res_value = value
                    if value[0] <= input_impact < value[1]:
                        #if (input_impact - value[0]) < (value[1] - input_impact):
                        break

            result[category] = {'inputValue': self.impact[i], 'SetValue': res_value, 'level': res_level}
        return result


    def calcul_impact(self):
        impact_info = self.getImpactInfo()
        value =   np.sum(np.array([m['SetValue'] for m in impact_info.values()]))
        if value >= 550:
            return 'Severe'
        elif value >= 220:
            return 'Serious'
        elif value >= 20:
            return 'Moderate'
        else:
            return 'Neglible'



    def calculfeasibility(self):
        """
        calcul de la faisabilité selon l'approche ISO 21434 définit par:
        8.22 * exploitability *  attack_vector * attack_complexity *  privilege_required * user_interaction
        :return: le niveau de faisabilité

        """
        exploitability = 8.22
        for elt in self.feasability:
            exploitability *= elt
        if 2.96 <= exploitability <= 3.89:
            return "High"
        elif 2.0 <= exploitability <= 2.95:
            return "Medium"
        elif 1.06 <= exploitability <= 1.99:
            return 'Low'
        else:
            return 'Very low'

    def Risque(self):
        """
        récupération de l'impact et de la faisabilité pour appliquer la formule suivante:
        1 + faisabilité * impact
        :return: le risque final définit sur l'échelle [1,5]
        """
        resultat_impact =  ImpactRating[self.calcul_impact()]
        resultat_feasability = FeasabilityRating[self.calculfeasibility()]
        return 1 + resultat_impact * resultat_feasability



