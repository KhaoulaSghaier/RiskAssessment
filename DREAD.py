


DreadImpact = {
    'Damage': {
     'Zero': 0,
     'Low': 2.5,
    'Non-Sensitive':8,
    'Non-Sensitive+': 9,
    'Destruction': 10,
    },
    'Reproducibility': {
    'Difficult': 0,
    'Complex': 5,
    'Easy': 7.5,
    'Very Easy': 10
},
    'Exploitability': {
    'Difficult': 0,
    'Complex': 5,
    'Medium': 7.5,
    'Easy': 10
    }
    ,
    'Affected_Users':{
        'Zero': 0,
        'Low': 2.5,
        'Few': 6,
        'Administrative':8,
        'All':10
    },
    'Discoverability':{
        'Hard':0,
        'OpenRequest':5,
        'PublicThreat': 8,
        'EasyThreat': 10
    }

}

AssetZone = [['ota sources','thingsboard server','ipfs cluster','http-2'],
             ['thingsboard edge','mec','upf','ipfs edge node','cid','https'],
             ['launcher','v2v','ipfs client','bitswap']]

# index = zone et string = niveaux d'user affécté
ZoneLevel = {
    0: 'ALL',
    1: 'Administrative',
    2: 'Few'
}

# check si le mot est bien présent dans place
def isWordinHere(word,place):
    return word in place

# renvoie dans quel compartiement l'attaque c'est réalisé
def getIndexAttackType(where):
    for i,zone in enumerate(AssetZone):
        for j in zone:
            if isWordinHere(j,where):
                return i
    return -1

def ImpactDread(row):
    # setting impact to 0
    impact = {'Damage': 0, 'Reproducibility': 0, 'Exploitability': 0, 'Affected_Users': 0, 'Discoverability': 0}
    whereAttack = str(row['Interaction']).lower()

    #obtention de la valeur a associté pour l'impact affected user
    placeofAttack =  ZoneLevel.get(getIndexAttackType(whereAttack),'Low')

    impact['Affected_Users'] = DreadImpact['Affected_Users'].get(placeofAttack)

    impactTotal = sum(impact.values())
    if (impactTotal <= 10):
        return 'Low'
    elif (impactTotal <= 24):
        return 'Moderate'
    elif (impactTotal <= 39):
        return 'High'
    else:
        return 'Critical'
