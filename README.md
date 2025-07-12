# Système d'Analyse de Risques de Sécurité
Un système d'analyse automatique de risques de sécurité basé sur les méthodes TARA, HARA et DREAD, avec intégration des bases de données MITRE ATT&CK, CVE, CWE et CAPEC.
 
# Objectif
Ce système permet d'analyser automatiquement les risques de sécurité en croisant les données de différentes sources (CVE, CWE, CAPEC, MITRE ATT&CK) et en appliquant trois méthodes d'évaluation reconnues :

TARA (Threat Analysis and Risk Assessment)\
HARA (Hazard Analysis and Risk Assessment)\
DREAD (Damage, Reproducibility, Exploitability, Affected Users, Discoverability)

#  Prérequis

Python 3.8+
pip (gestionnaire de packages Python)
Connexion Internet (pour télécharger les bases de données)

# Installation
1. Clonage du projet
bashgit clone <votre-repo>
cd security-risk-analysis
2. Installation des dépendances
bashpip install -r requirements.txt
Fichier requirements.txt :
- pandas>=1.5.0
- numpy>=1.21.0
- sentence-transformers>=2.2.0
- scikit-learn>=1.1.0
- requests>=2.28.0
3. Les Base de données sont directement stocké dans le repot dans le dossier data


# Utilisation
Pour utiliser le programme, il suffit de se rendre dans le fichier Service.py
et d'utiliser le main mis à disposition.\
L'ensemble des méthodes de récupération de donnée sont réalisé dans Utils.py\
L'ensemble des méthodes pour réaliser la sémantique sont présentes dans get_match.py\
python 


````python
from Service import get_analyse, analyse_automatique

# Définir le template de base
template_base = {
    'description': "Description de la vulnérabilité ou de l'attaque",
    'safety_critical_update': True,  # Si c'est une mise à jour critique
    'affected_user': "High",         # "High", "Medium", "Low"
    'knowlege_cible': "MEDIUM",      # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    'necessary_material': "MEDIUM",   # "CRITICAL", "HIGH", "MEDIUM", "LOW"
}
````


# Générer l'analyse automatique
````python
analyse_template = get_analyse(template_base)
print("Template d'analyse :", analyse_template)
````


# Calculer le risque final

````python
risque_final = analyse_automatique(analyse_template).get_risk()
print("Risque final :", risque_final)
Exemple concret



# Exemple d'analyse d'une vulnérabilité XSS
template_exemple = {
    'description': "The server 'ThingsBoard Server' could be a subject to a cross-site scripting attack that will compromise safety critical update by infecting the malware into the OTA source that could lead to modification of the metadata in the IPFS or the redirection of the downloading in malicious deposit",
    'safety_critical_update': True,
    'affected_user': "High",
    'knowlege_cible': "MEDIUM",
    'necessary_material': "MEDIUM",
}

````
# Analyse
```python
resultat = get_analyse(template_exemple) # renvoie le template d'analyse 
risque = analyse_automatique(resultat).get_risk() # renvoie le risque

print(f"Risque calculé : {risque}")
```



#  Méthodes d'analyse
TARA (Threat Analysis and Risk Assessment)
Évalue les risques selon 4 critères d'impact :

Safety : Impact sur la sécurité physique\
Financial : Impact financier\
Operational : Impact opérationnel\
Privacy : Impact sur la vie privée

HARA (Hazard Analysis and Risk Assessment)
Analyse basée sur 3 paramètres :

Exposure : Niveau d'exposition\
Controllability : Niveau de contrôlabilité\
Severity : Sévérité de l'impact

DREAD
Évaluation selon 5 critères :

Damage : Dommages potentiels\
Reproducibility : Facilité de reproduction\
Exploitability : Facilité d'exploitation\
Affected Users : Nombre d'utilisateurs affectés\
Discoverability : Facilité de découverte

#  Configuration avancée
Personnalisation des mappings\
Vous pouvez modifier les mappings dans Service.py :
```python
 
# Mapping des matériaux nécessaires
material_map = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
}

analyser = analyse_automatique(test_case)\
print("Risque du cas de test :", analyser.get_risk())\
```
Mapping des connaissances cibles

#  Structure du projet
security-risk-analysis/\
├── data/                    # Bases de données\
│   ├── epss_scores-current.csv\
│   ├── cwe.csv\
│   ├── capec.csv\
│   └── enterprise-attack.json\
├── Service.py                    # Point d'entrée principal  
├── analyse_automatique.py         # Orchestrateur des analyses   
├── TARA.py                       # Implémentation TARA        
├── HARA.py                      # Implémentation HARA    
├── DREAD.py                      # Implémentation DREAD    
├── capec_attack.py              # Analyse des données CAPEC    
├── get_match.py                  # Correspondance sémantique    
├── utils.py                     # Utilitaires et chargement des données   
├── *.npy                        # Sauvegarde des embedding des descriptions des base de donnée   
└── README.md                     # Ce fichier    
🎛️ Paramètres d'entrée

# Template de base

description : Description textuelle de la vulnérabilité/attaque\
safety_critical_update : Boolean - Si c'est une mise à jour critique\
affected_user : String - Nombre d'utilisateurs affectés ("High", "Medium", "Low")\
knowlege_cible : String - Niveau de connaissance requis ("CRITICAL", "HIGH", "MEDIUM", "LOW")\
necessary_material : String - Matériel nécessaire ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Sortie

Le système retourne un score de risque final qui est le maximum des trois méthodes d'évaluation.
 Dépannage
Erreurs communes

Fichiers de données manquants\
FileNotFoundError: [Errno 2] No such file or directory: 'data/...'\
Solution : Vérifiez que tous les fichiers de données sont téléchargés dans le dossier data/
Problèmes d'encodage
UnicodeDecodeError
Solution : Assurez-vous que les fichiers CSV sont encodés en UTF-8
Erreurs de réseau
requests.exceptions.ConnectionError
Solution : Vérifiez votre connexion Internet pour le téléchargement des données CVE

Logs de débogage
Ajoutez des logs pour suivre l'exécution :
pythonimport logging
logging.basicConfig(level=logging.DEBUG)

# Votre code d'analyse
Mise à jour des données\ 

Pour maintenir la précision des analyses, mettez à jour régulièrement les bases de données :
bash# Script de mise à jour (à créer)
python update_databases.py
# Interprétation des résultats

Risque 1 : Faible   
Risque 2 : Modéré   
Risque 3 : Élevé   
Risque 4 : Critique   
Risque 5 : Très critique   