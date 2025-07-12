likehood = {
    "High": 8,
    "Medium": 5,
    "Low": 2
}

expertise = {
    "High": "Expert",
    "Medium": "Advanced",
    "Low": "Novice",
}

severity = {
    "High":8,
    "Medium": 5,
    "Low": 2
}

class CapecAnalyze:

    def __init__(self,severity, likelihood,consequence):
        self.likelihood = likelihood
        self.severity = severity
        self.consequences =consequence

    def getLikehood(self):
        return likehood.get(self.likelihood,2)


    def getSeverity(self):
        return severity.get(self.severity,2)

    def isConfenditalThreat(self):
        setconsequence = {
            "Unknown": 3,
            "Read Data": 4,
            "Disclosure": 5,
            "Bypass Security": 6,
            "Gain Privileges": 7,
        }
        getconsequence = self.consequences.get('Confidentiality',[])
        if getconsequence:
            if "Gain Privileges" in getconsequence:
                return  7
            elif "Bypass Security" in getconsequence:
                return 6
            elif "Disclosure" in getconsequence:
                return 5
            elif "Read Data" in getconsequence:
                return 4
            elif "Unknown" in getconsequence:
                return 3
        return 0
