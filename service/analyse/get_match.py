from service.analyse import utils
from sentence_transformers import SentenceTransformer,util
import os
import  numpy as np

def load_or_generate_embeddings(description,path_embedding,model):
    """
    :param description: description qui décrit l'attaque ou la vulnérabilité
    :param path_embedding: le chemin où on a stocké l'embedding de chaqu'une des descriptions de la base de donnée
    :param model: model utilisé pour traité l'embeding et la vectoristion de notre description
    :return: la liste de tout les éléments embedding à
    """
    embedding = None
    if os.path.exists(path_embedding):
        embedding = np.load(path_embedding)
    else:
        embedding = model.encode(description, batch_size=64, show_progress_bar=True)
        np.save(path_embedding,embedding)
    return embedding

def get_top(query_embedding,embeddings,description,type='MITRE',top_n=3):
    """
    :param query_embedding:
    :param embeddings:
    :param description:
    :param type:
    :param top_n:
    :return:
    """
    scores = util.cos_sim(query_embedding,embeddings)[0].numpy()
    top_id = np.argsort(scores)[::-1][:top_n]
    print()
    return [{
        'source': type,
        'id': description.iloc[i]['id'],
        'name': description.iloc[i]['name'],
        'score': float(scores[i]),
        'description': description.iloc[i]['description']
    } for i in top_id]

def get_top_match(query,desc_mitre,desc_cwe,desc_capec,desc_cve,tec_mitre,tec_capec,tec_cwe,tec_cve,
                  mitre_path='mitre_embedding.npy',capec_path='capec_embedding.npy',cwe_path='cwe_embedding.npy',cve_path='cve_embedding.npy',
                  model_name="all-mpnet-base-v2",top_value=3):
    model = SentenceTransformer(model_name)
    embeddings_mitre = load_or_generate_embeddings(desc_mitre,mitre_path,model)
    embeddings_capec = load_or_generate_embeddings(desc_capec,capec_path,model)
    embeddings_cwe = load_or_generate_embeddings(desc_cwe,cwe_path,model)
    embeddings_cve = load_or_generate_embeddings(desc_cve,cve_path,model)

    query_embedding = model.encode(query, batch_size=64, show_progress_bar=True)

    mitre_top = get_top(query_embedding,embeddings_mitre,tec_mitre,'MITRE',top_value)
    cwe_top = get_top(query_embedding,embeddings_cwe,tec_cwe,'CWE',top_value)
    capec_top = get_top(query_embedding,embeddings_capec,tec_capec,'CAPEC',top_value)
    cve_top = get_top(query_embedding,embeddings_cve,tec_cve,'CVE',top_value)
    return mitre_top + capec_top + cwe_top + cve_top



