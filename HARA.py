
# Inspiré de  Hazard Analysis and Risk Assessment (HARA) | Engineering Expertise EE#4
# de UL Solutions - YTB

from enum import Enum


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

MSIL = {
    (Severity.S1, Controllability.C1, Exposure.E1): 'QM',
    (Severity.S1, Controllability.C1, Exposure.E2): 'QM',
    (Severity.S1, Controllability.C1, Exposure.E3): 'QM',
    (Severity.S1, Controllability.C1, Exposure.E4): 'QM',
    (Severity.S1, Controllability.C2, Exposure.E1): 'QM',
    (Severity.S1, Controllability.C2, Exposure.E2): 'QM',
    (Severity.S1, Controllability.C2, Exposure.E3):  'QM',
    (Severity.S1, Controllability.C2, Exposure.E4): 'MSIL A',
    (Severity.S1, Controllability.C3, Exposure.E1): 'QM',
    (Severity.S1, Controllability.C3, Exposure.E2): 'QM',
    (Severity.S1, Controllability.C3, Exposure.E3): 'MSIL A',
    (Severity.S1, Controllability.C3, Exposure.E4): 'MSIL B',

   (Severity.S2, Controllability.C1, Exposure.E1): 'QM',
    (Severity.S2, Controllability.C1, Exposure.E2): 'QM',
    (Severity.S2, Controllability.C1, Exposure.E3): 'QM',
    (Severity.S2, Controllability.C1, Exposure.E4): 'MSIL A',
    (Severity.S2, Controllability.C2, Exposure.E1): 'QM',
    (Severity.S2, Controllability.C2, Exposure.E2): 'QM',
    (Severity.S2, Controllability.C2, Exposure.E3): 'MSIL A',
    (Severity.S2, Controllability.C2, Exposure.E4): 'MSIL B',
    (Severity.S2, Controllability.C3, Exposure.E1): 'QM',
    (Severity.S2, Controllability.C3, Exposure.E2): 'MSIL A',
    (Severity.S2, Controllability.C3, Exposure.E3): 'MSIL B',
    (Severity.S2, Controllability.C3, Exposure.E4): 'MSIL C',

    (Severity.S3, Controllability.C1, Exposure.E1): 'QM',
    (Severity.S3, Controllability.C1, Exposure.E2): 'QM',
    (Severity.S3, Controllability.C1, Exposure.E3): 'MSIL A',
    (Severity.S3, Controllability.C1, Exposure.E4): 'MSIL B',
    (Severity.S3, Controllability.C2, Exposure.E1): 'QM',
    (Severity.S3, Controllability.C2, Exposure.E2): 'MSIL A',
    (Severity.S3, Controllability.C2, Exposure.E3): 'MSIL B',
    (Severity.S3, Controllability.C2, Exposure.E4): 'MSIL C',
    (Severity.S3, Controllability.C3, Exposure.E1): 'MSIL A',
    (Severity.S3, Controllability.C3, Exposure.E2): 'MSIL B',
    (Severity.S3, Controllability.C3, Exposure.E3): 'MSIL C',
    (Severity.S3, Controllability.C3, Exposure.E4): 'MSIL D',
}

ASILS = {
    'QM': ASIL.QM,
    'MSIL A': ASIL.QM,
    'MSIL B': ASIL.ASIL_A,
    'MSIL C': ASIL.ASIL_B,
    'MSIL D': ASIL.ASIL_C
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



def SeveryScore(description):
    token = description.lower().split()
    matches = sum(1 for i in token if i in SEVERITY_Words)
    return min(matches / 5, 1)


# Hara creator class HaraBuilder:
class HaraBuilder:
    def __init__(self):
        self.exposure = None
        self.controllability = None
        self.severity = None

    def setSeverity(self, severity: Severity):
        self.severity = severity

    def setControllability(self, controllability: Controllability):
        self.controllability = controllability

    def setExposure(self, exposure: Exposure):
        self.exposure = exposure

    def getMSIL(self):
        if self.exposure is None or self.severity is None or self.controllability is None:
            return None
        return MSIL.get((self.severity, self.controllability, self.exposure))

    def getAsil(self):
        return ASILS.get(self.getMSIL())

def setLevel(tokens, Words):
    levelAccepted = set()
    for l, keywords in  Words.items():
        if any(i in tokens for i in keywords):
            levelAccepted.append(l)
    return max(levelAccepted)

def AsilApplication(row):
    hara = HaraBuilder()
    description = str(row['Description']).lower().split()
    hara.setExposure(setLevel(description, EXPOSURE_Words))
    hara.setControllability(setLevel(description, CONTROLLABILITY_Words))
    hara.setSeverity(setLevel(description, SEVERITY_Words))
    # rajouter la criticité de la mise à jour
    return {"Severity": hara.severity, "Controllability": hara.controllability, "Exposure": hara.exposure, "ASIL": hara.getAsil()}