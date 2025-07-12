
# Inspiré de  Hazard Analysis and Risk Assessment (HARA) | Engineering Expertise EE#4
# de UL Solutions - YTB

from enum import Enum
# import fasttext
import numpy as np
from numpy.linalg import norm



model = 1 # fasttext.load_model('cc.en.300.bin')

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
    ASIL_D = 4


"""
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

"""

# Hara creator class HaraBuilder:
class Hara:
    def __init__(self,exposure,controllability,severity):
        self.exposure = exposure
        self.severity = severity
        self.controllability = controllability


    def getAsil(self):
        """

        :return:
        """
        if self.exposure is None or self.severity is None or self.controllability is None:
            return 0
        somme = self.exposure + self.severity + self.controllability
        if somme < 7:
            return 0 #QM
        elif somme == 7:
            return 1 # ASIL_A
        elif somme == 8:
            return 2 # ASIL_B
        elif somme == 9:
            return 3 # ASIL_C
        else:
            return 4 #ASIL_D


    def getRisque(self):
        return 1 + self.getAsil()