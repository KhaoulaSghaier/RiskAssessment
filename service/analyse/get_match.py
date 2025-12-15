from service.analyse import utils
from sentence_transformers import SentenceTransformer, util
import os
import numpy as np

def load_or_generate_embeddings(description, path_embedding, model):
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
        np.save(path_embedding, embedding)
    return embedding

def get_top(query_embedding, embeddings, description, type='MITRE', top_n=3):
    """
    Get top N matches with confidence scores
    :param query_embedding: embedding of the query
    :param embeddings: embeddings of the database
    :param description: dataframe with descriptions
    :param type: source type (MITRE, CWE, CAPEC, CVE)
    :param top_n: number of top matches to return
    :return: list of top matches with confidence scores
    """
    scores = util.cos_sim(query_embedding, embeddings)[0].numpy()
    top_indices = np.argsort(scores)[::-1][:top_n]
    
    results = []
    for rank, idx in enumerate(top_indices, start=1):
        confidence = float(scores[idx])
        results.append({
            'source': type,
            'id': description.iloc[idx]['id'],
            'name': description.iloc[idx]['name'],
            'description': description.iloc[idx]['description'],
            'confidence': confidence,
            'rank': rank,
            'similarity_score': confidence  # Alias for clarity
        })
    
    return results

def get_top_match(query, desc_mitre, desc_cwe, desc_capec, desc_cve, tec_mitre, tec_capec, tec_cwe, tec_cve,
                  mitre_path='mitre_embedding.npy', capec_path='capec_embedding.npy', 
                  cwe_path='cwe_embedding.npy', cve_path='cve_embedding.npy',
                  model_name="all-mpnet-base-v2", top_value=3):
    """
    Get top matches from all databases with confidence scores
    :param query: threat description
    :param desc_mitre, desc_cwe, desc_capec, desc_cve: descriptions from databases
    :param tec_mitre, tec_capec, tec_cwe, tec_cve: technique dataframes
    :param mitre_path, capec_path, cwe_path, cve_path: embedding cache paths
    :param model_name: sentence transformer model name
    :param top_value: number of top matches per database (default: 3)
    :return: dictionary with top matches per database
    """
    model = SentenceTransformer(model_name)
    
    # Load or generate embeddings
    embeddings_mitre = load_or_generate_embeddings(desc_mitre, mitre_path, model)
    embeddings_capec = load_or_generate_embeddings(desc_capec, capec_path, model)
    embeddings_cwe = load_or_generate_embeddings(desc_cwe, cwe_path, model)
    embeddings_cve = load_or_generate_embeddings(desc_cve, cve_path, model)

    # Encode query
    query_embedding = model.encode(query, batch_size=64, show_progress_bar=True)

    # Get top matches from each database
    mitre_top = get_top(query_embedding, embeddings_mitre, tec_mitre, 'MITRE', top_value)
    capec_top = get_top(query_embedding, embeddings_capec, tec_capec, 'CAPEC', top_value)
    cwe_top = get_top(query_embedding, embeddings_cwe, tec_cwe, 'CWE', top_value)
    cve_top = get_top(query_embedding, embeddings_cve, tec_cve, 'CVE', top_value)
    
    # Return structured results
    return {
        'mitre': mitre_top,
        'capec': capec_top,
        'cwe': cwe_top,
        'cve': cve_top,
        # For backwards compatibility, also return as flat list with top match first
        'top_matches': [mitre_top[0], capec_top[0], cwe_top[0], cve_top[0]]
    }


def calculate_overall_confidence(matches_dict):
    """
    Calculate overall confidence score based on all top matches
    :param matches_dict: dictionary from get_top_match()
    :return: overall confidence score (0-1)
    """
    all_confidences = []
    for source in ['mitre', 'capec', 'cwe', 'cve']:
        if source in matches_dict:
            # Use top match confidence with higher weight
            all_confidences.append(matches_dict[source][0]['confidence'] * 2)  # Top match weighted
            # Add other matches with lower weight
            for match in matches_dict[source][1:]:
                all_confidences.append(match['confidence'])
    
    if not all_confidences:
        return 0.0
    
    # Weighted average favoring top matches
    return sum(all_confidences) / len(all_confidences)


def get_confidence_level(confidence_score):
    """
    Map confidence score to level
    :param confidence_score: float between 0-1
    :return: tuple (level, description)
    """
    if confidence_score >= 0.85:
        return ('HIGH', 'High confidence - strong semantic match')
    elif confidence_score >= 0.70:
        return ('MEDIUM', 'Medium confidence - good semantic match')
    elif confidence_score >= 0.50:
        return ('LOW', 'Low confidence - weak semantic match')
    else:
        return ('VERY_LOW', 'Very low confidence - poor semantic match')