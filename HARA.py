
# Inspiré de  Hazard Analysis and Risk Assessment (HARA) | Engineering Expertise EE#4
# de UL Solutions - YTB

from enum import Enum
import fasttext
import numpy as np
from numpy.linalg import norm



model = fasttext.load_model('cc.en.300.bin')

class Exposure(Enum):
    E0 = 0
    E1 = 1
    E2 = 2
    E3 = 3
    E4 = 4

class Controllability(Enum):
    C0 = 0
    C1 = 1
    C2 = 2
    C3 = 3

class Severity(Enum):
    S0 = 0
    S1 = 1
    S2 = 2
    S3 = 3

class ASIL(Enum):
    QM = 0
    ASIL_A = 1
    ASIL_B = 2
    ASIL_C = 3

ASIL_TABLE = {
    (Severity.S1, Controllability.C1, Exposure.E1): ASIL.QM,
    (Severity.S1, Controllability.C1, Exposure.E2): ASIL.QM,
    (Severity.S1, Controllability.C1, Exposure.E3): ASIL.QM,
    (Severity.S1, Controllability.C1, Exposure.E4): ASIL.QM,
    (Severity.S1, Controllability.C2, Exposure.E1): ASIL.QM,
    (Severity.S1, Controllability.C2, Exposure.E2): ASIL.QM,
    (Severity.S1, Controllability.C2, Exposure.E3):  ASIL.QM,
    (Severity.S1, Controllability.C2, Exposure.E4): ASIL.ASIL_A,
    (Severity.S1, Controllability.C3, Exposure.E1): ASIL.QM,
    (Severity.S1, Controllability.C3, Exposure.E2): ASIL.QM,
    (Severity.S1, Controllability.C3, Exposure.E3): ASIL.ASIL_A,
    (Severity.S1, Controllability.C3, Exposure.E4): ASIL.ASIL_B,

   (Severity.S2, Controllability.C1, Exposure.E1): ASIL.QM,
    (Severity.S2, Controllability.C1, Exposure.E2): ASIL.QM,
    (Severity.S2, Controllability.C1, Exposure.E3): ASIL.QM,
    (Severity.S2, Controllability.C1, Exposure.E4): ASIL.ASIL_A,
    (Severity.S2, Controllability.C2, Exposure.E1): ASIL.QM,
    (Severity.S2, Controllability.C2, Exposure.E2): ASIL.QM,
    (Severity.S2, Controllability.C2, Exposure.E3): ASIL.ASIL_A,
    (Severity.S2, Controllability.C2, Exposure.E4): ASIL.ASIL_B,
    (Severity.S2, Controllability.C3, Exposure.E1): ASIL.QM,
    (Severity.S2, Controllability.C3, Exposure.E2): ASIL.ASIL_A,
    (Severity.S2, Controllability.C3, Exposure.E3): ASIL.ASIL_B,
    (Severity.S2, Controllability.C3, Exposure.E4): ASIL.ASIL_C,

    (Severity.S3, Controllability.C1, Exposure.E1): ASIL.QM,
    (Severity.S3, Controllability.C1, Exposure.E2): ASIL.QM,
    (Severity.S3, Controllability.C1, Exposure.E3): ASIL.ASIL_A,
    (Severity.S3, Controllability.C1, Exposure.E4): ASIL.ASIL_B,
    (Severity.S3, Controllability.C2, Exposure.E1): ASIL.QM,
    (Severity.S3, Controllability.C2, Exposure.E2): ASIL.ASIL_A,
    (Severity.S3, Controllability.C2, Exposure.E3): ASIL.ASIL_B,
    (Severity.S3, Controllability.C2, Exposure.E4): ASIL.ASIL_C,
    (Severity.S3, Controllability.C3, Exposure.E1): ASIL.ASIL_A,
    (Severity.S3, Controllability.C3, Exposure.E2): ASIL.ASIL_B,
    (Severity.S3, Controllability.C3, Exposure.E3): ASIL.ASIL_C,
    (Severity.S3, Controllability.C3, Exposure.E4): ASIL.ASIL_D,
}

EXPOSURE_Words = {
    Exposure.E0: ["never", "isolated"],
    Exposure.E1: ["infrequent", "private", "specific"],
    Exposure.E2: ["sometimes", "occasional", "rarely", "local"],
    Exposure.E3: ["often", "common", "internet", "network"],
    Exposure.E4: ["always", "frequent", "public", "open"],
}

CONTROLLABILITY_Words = {
    Controllability.C0: ["automatic correction", "fail-safe"],
    Controllability.C1: ["manual override", "alert", "user warning"],
    Controllability.C2: ["limited control", "difficult", "complex"],
    Controllability.C3: ["no control", "silent failure", "sudden"],
}

# rajouter des infos sur la mise à jour severity_value * (le type de la mise à jour : en poids)
# basé plus les infos sur les cve + détailler les attaques et adapter les scénarios


SEVERITY_Words = {
    Severity.S0: ["info", "log", "monitoring", "safe"],
    Severity.S1: ["accident", "instability", "airbag", "alert"],
    Severity.S2: ["hazard", "brake failure", "dangerous", "collision", "loss of control"],
    Severity.S3: ["fatal", "injury", "disable brakes", "uncontrolled", "fire", "explosion"],
}

def cosine_similarity(A,B):
    """
    :param A:  vector A
    :param B: vector B
    :return: la similarité entre ces deux vecteurs
    """
    X = np.array(A)
    Y = np.array(B)
    return np.dot(X,Y) / (norm(X) * norm(Y))

def extend_description(tokens,fasttext,NbrSame=10):
    """
    :param tokens: description tokenisé
    :param fasttext: application du word bedding fast text
    :param NbrSame: nombre de mot similaire à prendre d'un mot
    :return: la description complètement extend
    """
    extend = set(tokens)
    no_duplicate = set(tokens)
    for token in no_duplicate:
        getsimilar = fasttext.get_nearest_neighbors(token,NbrSame)
        findwords = [word for (_,word) in getsimilar]
        extend.update(findwords)
    return list(extend)

def vectorizationDico(dicoLevel,model):
    """
    :param dicoLevel: dictionnaire de niveau choisie
    :param model: fastext model
    :return: retourne un dictionnaire avec les mots vectorisé du dico
    """
    vectdico = {}
    for niveau, WORDS in dicoLevel.items():
        vectdico[niveau] = [model.get_word_vector(word) for word in WORDS ]
    return vectdico

def  CalculCategorie(word,vectorDico,model):
    """
    :param word: mot à trouver avec quel mot du dico il matche
    :param vectorDico: vecteur des valeurs
    :param model:  fasttext model
    :return:
    """
    try:
       vectorized_word = model.get_word_vector
       scores = {}
       for level, vectozied_elt in vectorDico.items():
            #calcul de la similarité entre les deux vecteur
            similarity = [cosine_similarity(vectorized_word,vectelt) for vectelt in vectozied_elt]
            # récupération de la plus grande ressemblance
            scores[level] = max(max(similarity),0)
       level = max(scores,key=scores.get)
       return level, scores[level] #renvoie le niveau avec la plus grosse valeur
    except:
        return None,{}

SeverityVector = vectorizationDico(SEVERITY_Words,model)
ControllabilityVector = vectorizationDico(CONTROLLABILITY_Words,model)
ExposureVector = vectorizationDico(EXPOSURE_Words,model)


def getLevel(model,dico,description):
    """

    :param model:
    :param dico:
    :param description:
    :return:  retourne le level
    """
    res = []
    maxREs = {}
    for word in description:
        level, score = CalculCategorie(word, dico, model)
        if level:
            res.append((word,level,score))
    for _,level,score in res:
        maxREs[level] = maxREs.setdefault(level,0.0) + score

    return max(maxREs,key=maxREs.get)

# Hara creator class HaraBuilder:
class HaraBuilder:
    def __init__(self):
        self.exposure = None
        self.controllability = None
        self.severity = None
        self.description = None
        self.vectDescription = None


    def getdescription(self):
        return self.description
    def getSeverity(self):
        return self.severity
    def getExposure(self):
        return self.exposure
    def getControllability(self):
        return self.controllability

    def setdescription(self,description):
        token = str(description).lower().split()
        self.description  = extend_description(token,model)

    def setSeverity(self, severity: Severity):
        self.severity = severity

    def setControllability(self, controllability: Controllability):
        self.controllability = controllability

    def setExposure(self, exposure: Exposure):
        self.exposure = exposure

    def compile(self,description):
        self.setdescription(description)
        severity = getLevel(model,SeverityVector,self.getdescription())
        exposure = getLevel(model,ExposureVector,self.getdescription())
        controllability = getLevel(model,ControllabilityVector,self.getdescription())
        self.setSeverity(severity)
        self.setExposure(exposure)
        self.setControllability(controllability)

    def getAsil(self):
        if self.exposure is None or self.severity is None or self.controllability is None:
            return None
        return ASIL_TABLE.get((self.severity, self.controllability, self.exposure))


def AsilApplication(row):
    hara = HaraBuilder()
    hara.compile(row['Description'])
    # rajouter la criticité de la mise à jour
    return {"Severity": hara.getSeverity(), "Controllability": hara.getControllability(), "Exposure": hara.getExposure(), "ASIL": hara.getAsil()}

row = {'Description': "ThingsBoard server may be spoofed by an attacker and this may lead to unauthorized access to ThingsBoard Edge. Consider using a standard authentication mechanism to identify the source process."}
print(AsilApplication())