"""Phase 4: scan history, drift detection and anomaly detection (scikit-learn, no deep learning)."""
MIN_SNAPSHOTS = 30      # IsolationForest is not trained or reported below this (see ml/anomaly.py)
MIN_Z_SNAPSHOTS = 8     # per-feature robust z-scores need at least this much history
MAX_SCAN_SPREAD_MIN = 60   # collector outputs further apart than this are not one 'scan'
