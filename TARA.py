# Critère qui vont vérifier qu'on respect bien
# les critères de sécurité imporsé par la CIA(confidentiality,Integrity,Availabiliity)
# low = 0 and max = 12
critereImpact = {
    'Safety': {
        'Negligible': 0, # No injuries
        'Moderate': 1, # Light injury
        'Serious': 2, # Severe injury
        'Severe': 3 # threat against life
    },
    'Financial' : {
        'Neglible': 0, # Negligible losses
        'Moderate': 1, # Moderate Losses
        'Serrious': 2, # Substantial losses
        'Severe': 3 # Personnal Bankruptcy
    },
    'Operationnal': {
        'Neglible': 0,  # Neglibible Disturbance
        'Moderate': 1,  # Vehicle mostly Operationnal
        'Serrious': 2,  # Serious limitation in Vehicule Operation
        'Severe': 3  # Vehicle not Operationnal
    },
    'Privacy': {
        'Neglible': 0, # Few Inconveniences
        'Moderate': 1, # Siginificant Inconveniences
        'Serious': 2, # Serious Impact on PII
        'Severe': 3 # Irreversible Impact on PII
    }
}

#Criteria for feasibility of the attack
# lower = 0 and max = 53
critereFeasibility = {
    'Expertise': { # Level required to do the attack
     'Layman': 0,
     'Proficient': 3,
     'Expert': 6,
     'Expert+': 8,
    },
    'Opportunity': { # Windows opportunity
        'Unlimited': 0,
        'Much' : 1,
        'Moderate': 4,
        'Difficult': 10,
    },
    'Time': { # Time to do the attack
    'week': 0,   # <= 1 week
    'month': 1,  # <= 1 month
    'months':4, # <= 6 month
    'year': 10, # <= 1 year
    'years': 15 # > 1 year
    },

    'Equipment' : { # Equipment required
        'Standard': 0,
        'Specialized': 4,
        'Bespoke': 7,
        'Bespoke+': 10
    },

    'Knowledge' : { # knowledge of the item
        'Public' : 0,
        'Restricted' : 3,
        'Sensitive': 7,
        'Critical' : 10,
    }
}

ImpactLevel = {
    'Neglible': 0,
    'Moderate': 1,
    'Serious': 2,
    'Severe': 3
}

# feasibility with level in perrcentage (%)
FeasibilityLevel = [(0,13,'High'),(14,19,'Medium'),(20,25,'Low'),(26,53,'Very Low')]
maxscore = 53

# attack impact on

rules = {
    'Spoofing': ['Safety', 'Privacy'],
    'Information Disclosure': ['Financial', 'Privacy'],
    'Denial Of Service': ['Operationnal'],
    'Tampering': ['Safety', 'Operationnal'],
    'Elevation Of Privilege': ['Safety', 'Operationnal', 'Privacy']
}
# weight for type of impact
#  A justifier !!!
weight = {
    'Safety': 0.5,
    'Operationnal': 0.25,
    'Financial': 0.125,
    'Privacy': 0.125
}

# max score of the impact for a category
max_score = 3

intToImpactLevel = {
    0: 'Neglible',
    1: 'Moderate',
    2: 'Serious',
    3: 'Severe'
}


# Associate for each attack an impact
# Multiple Criteria Decision Analysis Algorithm
def ImpactAssociation(row):
    #inialisation of every needed information

    # row score
    impactScore = {'Safety': 0, 'Financial':0,'Operationnal': 0, 'Privacy':0 }

    category = row['Category']
    for impact in rules.get(category,[]):
        impactScore[impact] = 2

    description = str(row['Description']).lower()
    title = str(row['Title']).lower()

    # finir l'algorithme en réadaptant l'algortihme avec les infos de l'iso 


    # list of every score with weight and dived by max score: wi * (impact / max_impact)
    Scores = [weight.get(i) * (impactScore.get(i) / max_score) for i in impactScore.keys()]

    total = sum(Scores)

    if total >= 0.75:
        return 3
    elif total >= 0.5:
        return 2
    elif total >= 0.25:
        return 1
    return 0

# Associate for each attack a faisability


def FaisabilityAssociation(row):
    # en train d'être refait de manière correcte
    return 'High'




def RiskMatrix(feasibily,impacts):
    impact = intToImpactLevel.get(impacts,'Neglible')
    matrix = {
        ('Very Low', 'Neglible'): 'Negligible',
        ('Very Low', 'Moderate'): 'Negligible',
        ('Very Low', 'Serious'): 'Low',
        ('Very Low', 'Severe'): 'Medium',

        ('Low', 'Neglible'): 'Negligible',
        ('Low', 'Moderate'): 'Low',
        ('Low', 'Serious'): 'Medium',
        ('Low', 'Severe'): 'High',

        ('Medium', 'Neglible'): 'Low',
        ('Medium', 'Moderate'): 'Medium',
        ('Medium', 'Serious'): 'High',
        ('Medium', 'Severe'): 'Critical',

        ('High', 'Neglible'): 'Medium',
        ('High', 'Moderate'): 'High',
        ('High', 'Serious'): 'Critical',
        ('High', 'Severe'): 'Critical'
    }
    return matrix.get((feasibily,impact), 'Unknow')



