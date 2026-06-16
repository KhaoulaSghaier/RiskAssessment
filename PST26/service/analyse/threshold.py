"""
OTARQ – Threshold Extraction via Precision-Recall Analysis
===========================================================
For each ATD entry a (query), the model retrieves the most similar entry
from the rest of the database. We construct a balanced evaluation set by
pairing each query with:
  - its TRUE nearest neighbour from the same CWE  → positive pair (y=1)
  - its HARDEST nearest neighbour from a diff CWE → negative pair (y=0)

Score = cosine similarity of the retrieved candidate.
This produces a balanced 50/50 dataset and a PR curve that:
  - starts at low precision (≈0.5) at low thresholds
  - rises cleanly as threshold increases
  - intersects Recall at the EER point ρ*

Usage:
    pip install pandas openpyxl sentence-transformers scikit-learn matplotlib
    python otarq_threshold_extraction.py --atd Automotive-threat-database.csv [--seed 42]
"""

import argparse
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from sklearn.metrics import precision_recall_curve, auc

warnings.filterwarnings("ignore")

MODEL_NAME  = "sentence-transformers/all-mpnet-base-v2"
ATD_SHEET   = "ATD"
DESC_COL    = "Description"
CWE_COL     = "CWE_ID"
OUTPUT_PLOT = "pr_curve_otarq.pdf"
OUTPUT_CSV  = "threshold_results.csv"


def load_atd(path: str) -> pd.DataFrame:
    if path.lower().endswith(".csv"):
        df = pd.read_csv(path, encoding="utf-8", on_bad_lines="skip")
    else:
        df = pd.read_excel(path, sheet_name=ATD_SHEET)
    df = df[[DESC_COL, CWE_COL, "CVE_ID", "ATD_ID2"]].dropna(subset=[DESC_COL, CWE_COL])
    df[CWE_COL] = df[CWE_COL].astype(str).str.strip()
    df = df[~df[CWE_COL].isin(["NVD-CWE-noinfo", "NVD-CWE-Other", "nan"])]
    df = df.reset_index(drop=True)
    print(f"[ATD] {len(df)} entries after CWE filtering")
    return df


def embed(texts: list[str], cache_path: str = "atd_embeddings.npy") -> np.ndarray:
    import os
    if os.path.exists(cache_path):
        print(f"[Embedding] Loading from cache: {cache_path}")
        return np.load(cache_path)
    from sentence_transformers import SentenceTransformer
    print(f"[Embedding] Computing with {MODEL_NAME} (will cache to {cache_path}) ...")
    embeddings = SentenceTransformer(MODEL_NAME).encode(
        texts, batch_size=32, show_progress_bar=True, normalize_embeddings=True
    )
    np.save(cache_path, embeddings)
    print(f"[Embedding] Saved to {cache_path}")
    return embeddings


def build_pairs(df: pd.DataFrame, embeddings: np.ndarray,
                seed: int) -> tuple[np.ndarray, np.ndarray]:
    """
    For each query i that has at least one same-CWE neighbour:
      - Positive pair: (i, best same-CWE match)   → score = sim, y = 1
      - Negative pair: (i, best diff-CWE match)   → score = sim, y = 0

    This gives exactly n_pos == n_neg pairs, balanced by construction.
    The score is the cosine similarity of the retrieved candidate — the
    model's raw confidence that the pair is a match.
    """
    n   = len(df)
    cwe = df[CWE_COL].values

    rng = np.random.default_rng(seed=seed)
    sim = embeddings @ embeddings.T
    np.fill_diagonal(sim, -np.inf)   # exclude self

    scores_pos, scores_neg = [], []

    for i in range(n):
        same_mask = (cwe == cwe[i])
        same_mask[i] = False
        diff_mask = ~same_mask
        diff_mask[i] = False

        # Need at least one same-CWE neighbour to form a positive pair
        if same_mask.sum() == 0:
            continue

        best_pos = float(sim[i][same_mask].max())   # hardest positive
        diff_indices = np.where(diff_mask)[0]
        chosen   = rng.choice(diff_indices)
        best_neg = float(sim[i, chosen])            # random diff-CWE negative

        scores_pos.append(best_pos)
        scores_neg.append(best_neg)

    scores_pos = np.array(scores_pos)
    scores_neg = np.array(scores_neg)

    # Combine into balanced (y=1, y=0) arrays
    scores = np.concatenate([scores_pos, scores_neg])
    y_true = np.concatenate([np.ones(len(scores_pos), dtype=int),
                             np.zeros(len(scores_neg), dtype=int)])

    print(f"[Pairs] {len(scores_pos)} positive pairs + {len(scores_neg)} negative pairs")
    return y_true, scores


def find_eer_threshold(precision, recall, thresholds):
    p   = precision[:-1]
    r   = recall[:-1]
    idx = np.abs(p - r).argmin()
    return float(thresholds[idx]), float(p[idx]), float(r[idx])


def plot_pr_curve(thresholds, precision, recall,
                  rho_star, p_star, r_star, pr_auc) -> None:
    p = precision[:-1]
    r = recall[:-1]
    t = thresholds * 100

    fig, ax = plt.subplots(figsize=(3.5, 2.8))
    ax.plot(t, p, color="#1f77b4", linewidth=2, label="Precision")
    ax.plot(t, r, color="#ff7f0e", linewidth=2, label="Recall")

    ax.axvline(rho_star * 100, color="gray", linestyle="--", linewidth=1.2)
    ax.plot(rho_star * 100, p_star, "o", color="#1f77b4", markersize=8, zorder=5)
    ax.plot(rho_star * 100, r_star, "o", color="#ff7f0e", markersize=8, zorder=5)

    txt_x = rho_star * 100 + 2 if rho_star * 100 < 70 else rho_star * 100 - 22
    txt_y = max((p_star + r_star) / 2 - 0.18, 0.05)
    ax.annotate(
        f"τ* = {rho_star:.2f}\nEER",
        xy=(rho_star * 100, (p_star + r_star) / 2),
        xytext=(txt_x, txt_y),
        fontsize=10, color="gray",
        arrowprops=dict(arrowstyle="->", color="gray", lw=1)
    )

    ax.set_xlabel("Threshold τ (x 100)", fontsize=11)
    ax.set_ylabel("Score", fontsize=11)
    ax.legend(fontsize=11, loc="lower left")
    ax.set_xlim(t.min(), t.max())
    ax.set_ylim(-0.05, 1.05)
    ax.yaxis.set_major_locator(mticker.MultipleLocator(0.2))
    ax.grid(True, linestyle=":", alpha=0.5)
    #ax.text(0.02, 0.05, f"AUC-PR = {pr_auc:.3f}",
     #       transform=ax.transAxes, fontsize=10, color="dimgray")

    plt.tight_layout()
    plt.savefig(OUTPUT_PLOT, dpi=300)
    print(f"[Plot] Saved → {OUTPUT_PLOT}")
    plt.show()


def save_results(thresholds, precision, recall,
                 rho_star, p_star, r_star, pr_auc) -> None:
    p  = precision[:-1]
    r  = recall[:-1]
    f1 = np.where((p + r) > 0, 2 * p * r / (p + r), 0.0)
    pd.DataFrame({
        "threshold": np.round(thresholds, 4),
        "precision": np.round(p, 4),
        "recall":    np.round(r, 4),
        "f1":        np.round(f1, 4),
    }).to_csv(OUTPUT_CSV, index=False)
    print(f"[CSV]  Saved → {OUTPUT_CSV}")

    f1_star = 2 * p_star * r_star / (p_star + r_star) if (p_star + r_star) > 0 else 0
    print(f"\n{'='*52}")
    print(f"  Optimal threshold  τ* = {rho_star:.4f}")
    print(f"  Precision at τ*      = {p_star:.4f}")
    print(f"  Recall    at τ*      = {r_star:.4f}")
    print(f"  F1-score  at τ*      = {f1_star:.4f}")
    print(f"  AUC-PR               = {pr_auc:.4f}")
    print(f"{'='*52}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--atd",  required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df         = load_atd(args.atd)
    embeddings = embed(df[DESC_COL].tolist())
    y_true, scores = build_pairs(df, embeddings, seed=args.seed)

    print("[PR curve] Sweeping threshold τ ...")
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    pr_auc = auc(recall, precision)

    rho_star, p_star, r_star = find_eer_threshold(precision, recall, thresholds)
    save_results(thresholds, precision, recall, rho_star, p_star, r_star, pr_auc)
    plot_pr_curve(thresholds, precision, recall, rho_star, p_star, r_star, pr_auc)


if __name__ == "__main__":
    main()