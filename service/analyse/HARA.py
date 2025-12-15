class Hara:
    def __init__(self, exposure, controllability, severity):
        self.exposure = exposure
        self.severity = severity
        self.controllability = controllability
        
        # ISO 26262 ASIL Determination Table
        self.ASIL_TABLE = {
            # S1 combinations
            (1, 1, 1): 0, (1, 1, 2): 0, (1, 1, 3): 0, (1, 1, 4): 0,
            (1, 2, 1): 0, (1, 2, 2): 0, (1, 2, 3): 0, (1, 2, 4): 1,
            (1, 3, 1): 0, (1, 3, 2): 0, (1, 3, 3): 1, (1, 3, 4): 2,
            
            # S2 combinations
            (2, 1, 1): 0, (2, 1, 2): 0, (2, 1, 3): 0, (2, 1, 4): 1,
            (2, 2, 1): 0, (2, 2, 2): 0, (2, 2, 3): 1, (2, 2, 4): 2,
            (2, 3, 1): 0, (2, 3, 2): 1, (2, 3, 3): 2, (2, 3, 4): 3,
            
            # S3 combinations
            (3, 1, 1): 0, (3, 1, 2): 0, (3, 1, 3): 1, (3, 1, 4): 2,
            (3, 2, 1): 0, (3, 2, 2): 1, (3, 2, 3): 2, (3, 2, 4): 3,
            (3, 3, 1): 1, (3, 3, 2): 2, (3, 3, 3): 3, (3, 3, 4): 4,  
        }

    def getAsil(self):
        """
        Get ASIL using ISO 26262 lookup table
        """
        if self.exposure is None or self.severity is None or self.controllability is None:
            return 0
        
        # Lookup in table
        key = (self.severity, self.controllability, self.exposure)
        asil = self.ASIL_TABLE.get(key, 0)
        
        #print(f"   HARA Debug: S{self.severity} + C{self.controllability} + E{self.exposure} = ASIL {asil}")
        
        return asil

    def getRisque(self):
        return 1 + self.getAsil()