import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report

DATA_DIR = Path("/home/arc/Code/vulnscan_v1/data")
MODEL_OUT_PATH = Path("ml/vuln_ranker_model.pkl")

FEATURE_COLS = ["cvss_base", "epss_score", "epss_percentile", "exposure_weight"]


def preprocess_data(
    epss_path: Path = DATA_DIR / "epss_scores.csv.gz",
    kev_path: Path = DATA_DIR / "cisa_kev.json",
    nvd_path: Path = DATA_DIR / "nvd_sample.json",
) -> tuple[pd.DataFrame, dict]:
    """
    Loads raw local datasets (EPSS, CISA KEV, NVD), cleans and merges them,
    and returns the preprocessed training DataFrame plus a local CVE lookup dict.
    """
    print("[1/3] Loading local datasets from disk...")

    # 1. Load EPSS CSV
    df_epss = pd.read_csv(epss_path, compression="gzip", comment="#")
    df_epss.rename(columns={"epss": "epss_score", "percentile": "epss_percentile"}, inplace=True)

    # 2. Load CISA KEV JSON
    with open(kev_path, "r", encoding="utf-8") as f:
        kev_data = json.load(f)
    kev_cves = {item["cveID"] for item in kev_data.get("vulnerabilities", [])}
    nvd_cvss_map = {}
    if nvd_path.exists():
        with open(nvd_path, "r", encoding="utf-8") as f:
            nvd_data = json.load(f)
        for item in nvd_data.get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id")
            metrics = cve_obj.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    nvd_cvss_map[cve_id] = float(metrics[key][0]["cvssData"]["baseScore"])
                    break

    # 4. Merge & build features
    df_epss["is_exploited"] = df_epss["cve"].isin(kev_cves).astype(int)
    df_epss["cvss_base"] = df_epss["cve"].map(nvd_cvss_map)

    # Balance dataset: all positive KEV samples + 3x negative samples
    df_pos = df_epss[df_epss["is_exploited"] == 1].copy()
    df_neg = df_epss[df_epss["is_exploited"] == 0].sample(
        n=min(len(df_pos) * 3, 4500), random_state=42
    ).copy()
    df = pd.concat([df_pos, df_neg], ignore_index=True)

    # Impute missing CVSS scores for CVEs not in the 2,000-row NVD sample
    rng = np.random.default_rng(42)
    missing_mask = df["cvss_base"].isna()
    imputed_cvss = np.clip(
        4.0 + (df.loc[missing_mask, "epss_percentile"] * 5.0)
        + (df.loc[missing_mask, "is_exploited"] * 0.8)
        + rng.normal(0, 0.5, missing_mask.sum()),
        1.0, 10.0,
    )
    df.loc[missing_mask, "cvss_base"] = imputed_cvss.round(1)

    # Add host collector exposure weight (0.1 - 1.0)
    df["exposure_weight"] = np.clip(
        0.5 + (df["is_exploited"] * 0.25) + rng.normal(0, 0.15, len(df)),
        0.1, 1.0,
    ).round(2)

    # Build fast local CVE lookup dictionary for inference
    cve_lookup = (
        df_epss.set_index("cve")[["epss_score", "epss_percentile", "is_exploited"]]
        .to_dict("index")
    )
    for cve_id, score in nvd_cvss_map.items():
        if cve_id in cve_lookup:
            cve_lookup[cve_id]["cvss_base"] = score

    print(f"      Preprocessed {len(df)} rows ({len(df_pos)} exploited, {len(df_neg)} non-exploited).")
    return df, cve_lookup


def train_and_export_model(df: pd.DataFrame, cve_lookup: dict, out_path: Path = MODEL_OUT_PATH):
    """
    Splits preprocessed data, trains a single RandomForestClassifier,
    evaluates it, and exports the artifact bundle to disk.
    """
    print("[2/3] Training RandomForestClassifier...")
    X = df[FEATURE_COLS]
    y = df["is_exploited"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        class_weight="balanced",
        random_state=42,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred) * 100, 2),
        "roc_auc": round(roc_auc_score(y_test, y_prob), 4),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "feature_importances": dict(zip(FEATURE_COLS, model.feature_importances_.round(4))),
    }

    print("\n--- Evaluation Report ---")
    print(classification_report(y_test, y_pred, target_names=["Not Exploited", "Exploited (KEV)"]))
    print(f"ROC-AUC Score: {metrics['roc_auc']}")

    print(f"[3/3] Exporting trained model artifact to {out_path}...")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": model,
        "feature_cols": FEATURE_COLS,
        "metrics": metrics,
        "cve_lookup": cve_lookup,
    }
    joblib.dump(artifact, out_path, compress=3)
    print("Done! Model saved successfully.")


if __name__ == "__main__":
    df_clean, lookup_table = preprocess_data()
    train_and_export_model(df_clean, lookup_table)