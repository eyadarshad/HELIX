"""
online_learner.py — Two-track online learning: stable inference + incremental updates

DESIGN:
    Track A (INFERENCE)   → pre-trained RandomForest from best_model.pkl
                            Never changes unless you retrain manually.
                            STABLE. Won't flip on one user input.

    Track B (LEARNING)    → SGDClassifier, updated via partial_fit
                            Buffers user corrections. Only applies update
                            when buffer reaches MIN_BATCH_SIZE samples.
                            After enough updates, blends with Track A.

This fixes the "flips on every label" problem:
  - Scanning notepad.exe twice in a row → same verdict both times
  - Labeling "correct" once → no change (buffered, not yet applied)
  - Labeling 10+ times → model subtly shifts, not dramatically flips

Usage:
    from ml.online_learner import OnlineLearner
    learner = OnlineLearner()

    score  = learner.predict_proba(feature_vector)  # 0.0–1.0 threat
    label  = learner.predict(feature_vector)         # "malware" / "benign"
    learner.update_from_dict(features_dict, "malware")  # buffered
"""

from __future__ import annotations

import os
import pickle
import numpy as np
from sklearn.linear_model  import SGDClassifier
from sklearn.preprocessing import StandardScaler

from features.extractor import FEATURE_NAMES

# ── Paths ──────────────────────────────────────────────────────────────────────
WORKSPACE    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR   = os.path.join(WORKSPACE, "ml", "models")
ONLINE_PATH  = os.path.join(MODELS_DIR, "online_model.pkl")
BEST_PATH    = os.path.join(MODELS_DIR, "best_model.pkl")

CLASSES = np.array([0, 1])   # 0 = benign, 1 = malware

# Minimum user labels to collect before applying an SGD update
MIN_BATCH_SIZE = 10

# Weight of online SGD blended into final prediction
MAX_ONLINE_WEIGHT = 0.35   # caps at 35% influence even after many updates

# Conservative threshold — avoids false-positives on benign files.
# 0.55 is the sweet spot: stricter than 0.50 (reduces FP on benign)
# but more sensitive than 0.65 (still catches real malware at 0.60+).
MALWARE_THRESHOLD = 0.52   # balanced: stricter than 0.50, avoids FP on borderline benign apps


class OnlineLearner:
    """
    Stable malware classifier with incremental feedback learning.

    Track A — Inference (stable):
        Uses the pre-trained RandomForest/GBT from ml.train.
        Never changes mid-session. Gives consistent verdicts.

    Track B — Learning (buffered):
        SGDClassifier updated via partial_fit.
        Collects user labels in a buffer.
        Only applies updates in MIN_BATCH_SIZE batches.
        Gradually blended into final prediction over time.
    """

    def __init__(self):
        os.makedirs(MODELS_DIR, exist_ok=True)
        self._stable_model  = None   # Track A: pre-trained RF
        self._stable_scaler = None
        self._online_model  = None   # Track B: SGD online learner
        self._online_scaler = None
        self._label_encoder = None

        # Buffer for pending user corrections (not yet applied to SGD)
        self._buffer_X: list[list[float]] = []
        self._buffer_y: list[int]         = []

        # Total confirmed updates applied (used for online_weight calc)
        self._applied_updates: int = 0

        self._load()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load(self):
        """Load stable model from best_model.pkl, and online state if available."""
        # Track A: stable pre-trained model
        if os.path.exists(BEST_PATH):
            with open(BEST_PATH, "rb") as f:
                bundle = pickle.load(f)
            self._stable_model  = bundle["model"]
            self._stable_scaler = bundle["scaler"]
            self._label_encoder = bundle.get("label_encoder")
            print(f"[OnlineLearner] Stable model loaded: {type(self._stable_model).__name__}")
        else:
            print("[OnlineLearner] WARNING: no best_model.pkl found. Run ml.train first.")

        # Track B: online SGD state (if previously saved)
        if os.path.exists(ONLINE_PATH):
            try:
                with open(ONLINE_PATH, "rb") as f:
                    state = pickle.load(f)

                # ── Version guard: discard if feature count changed ────────────
                saved_scaler = state.get("scaler")
                saved_n_feats = (
                    saved_scaler.n_features_in_
                    if saved_scaler and hasattr(saved_scaler, "n_features_in_")
                    else None
                )
                if saved_n_feats is not None and saved_n_feats != len(FEATURE_NAMES):
                    print(f"[OnlineLearner] Feature count changed "
                          f"({saved_n_feats} → {len(FEATURE_NAMES)}). "
                          f"Discarding stale online state and reinitialising.")
                    os.remove(ONLINE_PATH)
                    self._init_online_model()
                    return

                self._online_model    = state.get("model")
                self._online_scaler   = state.get("scaler", self._stable_scaler)
                self._applied_updates = state.get("applied_updates", 0)
                self._buffer_X        = state.get("buffer_X", [])
                self._buffer_y        = state.get("buffer_y", [])

                # Secondary guard: drop any buffered vectors with wrong length
                expected = len(FEATURE_NAMES)
                before = len(self._buffer_X)
                self._buffer_X, self._buffer_y = zip(
                    *[(x, y) for x, y in zip(self._buffer_X, self._buffer_y)
                      if len(x) == expected]
                ) if self._buffer_X else ([], [])
                self._buffer_X = list(self._buffer_X)
                self._buffer_y = list(self._buffer_y)
                dropped = before - len(self._buffer_X)
                if dropped:
                    print(f"[OnlineLearner] Dropped {dropped} stale buffer entries "
                          f"(wrong feature count).")

                print(f"[OnlineLearner] Online state restored "
                      f"(applied: {self._applied_updates}, buffered: {len(self._buffer_X)})")
            except Exception as e:
                print(f"[OnlineLearner] Failed to load online state ({e}). Reinitialising.")
                self._init_online_model()
        else:
            self._init_online_model()

    def _init_online_model(self):
        """Create fresh SGD online model (warm-started from stable model)."""
        self._online_scaler = self._stable_scaler
        self._online_model  = SGDClassifier(
            loss="log_loss",
            alpha=0.01,          # strong regularisation → less volatile
            eta0=0.001,          # very small learning rate
            learning_rate="constant",
            max_iter=1000,
            random_state=42,
        )
        # Warm-start with stable model predictions on dummy data
        if self._stable_model and self._stable_scaler:
            rng   = np.random.RandomState(42)
            n     = 40
            X_w   = rng.randn(n, len(FEATURE_NAMES))
            X_ws  = self._stable_scaler.transform(X_w)
            y_w   = self._stable_model.predict(X_ws)
            if len(set(y_w)) < 2:          # ensure both classes present
                y_w[:n//2] = 0
                y_w[n//2:] = 1
            self._online_model.partial_fit(X_ws, y_w, classes=CLASSES)

        self._applied_updates = 0
        self._buffer_X = []
        self._buffer_y = []
        self._save()

    # ── Public API ────────────────────────────────────────────────────────────

    def predict_proba(self, feature_vector: list[float] | np.ndarray) -> float:
        """
        Return threat probability (0.0 = safe, 1.0 = malware).

        Uses stable model (Track A) as primary, blends with SGD (Track B)
        only after enough user corrections have been applied.
        """
        X = np.array(feature_vector, dtype=float).reshape(1, -1)

        # Track A: stable prediction (always available)
        if self._stable_model and self._stable_scaler:
            Xs = self._stable_scaler.transform(X)
            try:
                stable_prob = float(self._stable_model.predict_proba(Xs)[0][1])
            except Exception:
                stable_prob = float(self._stable_model.predict(Xs)[0])
        else:
            stable_prob = 0.5

        # Track B: online model — only blend in after MIN_BATCH_SIZE updates
        online_prob   = stable_prob
        online_weight = 0.0

        if self._online_model and self._applied_updates >= MIN_BATCH_SIZE:
            try:
                Xo = self._online_scaler.transform(X)
                online_prob   = float(self._online_model.predict_proba(Xo)[0][1])
                # Weight grows slowly, capped at MAX_ONLINE_WEIGHT
                online_weight = min(
                    MAX_ONLINE_WEIGHT,
                    (self._applied_updates / (MIN_BATCH_SIZE * 10)) * MAX_ONLINE_WEIGHT
                )
            except Exception:
                pass

        return float(stable_prob * (1 - online_weight) + online_prob * online_weight)

    def predict(self, feature_vector: list[float] | np.ndarray) -> str:
        """Predict class label: 'malware' or 'benign'.
        Uses MALWARE_THRESHOLD (0.65) not 0.5 — reduces false positives
        on benign system files that share some patterns with malware."""
        prob = self.predict_proba(feature_vector)
        return "malware" if prob >= MALWARE_THRESHOLD else "benign"

    def update_from_dict(self, features: dict, label: str) -> str:
        """
        Buffer a user-provided label for the current sample.

        The label is NOT immediately applied to the model —
        it goes into a buffer. When the buffer reaches MIN_BATCH_SIZE
        samples, partial_fit is applied and the buffer clears.

        Returns:
            "buffered" — stored, not yet applied
            "updated"  — batch applied, model updated
        """
        vec   = [features.get(f, 0.0) for f in FEATURE_NAMES]
        y_int = 1 if label == "malware" else 0

        self._buffer_X.append(vec)
        self._buffer_y.append(y_int)

        if len(self._buffer_X) >= MIN_BATCH_SIZE:
            self._apply_buffer()
            self._save()
            return "updated"

        self._save()   # save buffered state
        return "buffered"

    def update(self, feature_vectors, labels: list[int]) -> str:
        """Batch update from API/server — applies immediately."""
        X = np.array(feature_vectors, dtype=float)
        y = np.array(labels, dtype=int)

        if self._online_scaler:
            Xo = self._online_scaler.transform(X)
        else:
            Xo = X

        self._online_model.partial_fit(Xo, y, classes=CLASSES)
        self._applied_updates += len(labels)
        self._save()
        return "updated"

    # ── Internal ──────────────────────────────────────────────────────────────

    def _apply_buffer(self):
        """Apply buffered labels to the SGD model."""
        X = np.array(self._buffer_X, dtype=float)
        y = np.array(self._buffer_y, dtype=int)

        if self._online_scaler:
            X = self._online_scaler.transform(X)

        self._online_model.partial_fit(X, y, classes=CLASSES)
        self._applied_updates += len(self._buffer_y)

        print(f"[OnlineLearner] Batch applied: {len(self._buffer_y)} samples "
              f"(total applied: {self._applied_updates})")

        self._buffer_X = []
        self._buffer_y = []

    def _save(self):
        state = {
            "model":          self._online_model,
            "scaler":         self._online_scaler,
            "applied_updates": self._applied_updates,
            "buffer_X":       self._buffer_X,
            "buffer_y":       self._buffer_y,
        }
        with open(ONLINE_PATH, "wb") as f:
            pickle.dump(state, f)

    def save(self):
        self._save()
        print(f"[OnlineLearner] Saved (applied: {self._applied_updates}, "
              f"buffered: {len(self._buffer_X)})")

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def update_count(self) -> int:
        """Total confirmed updates + pending buffer count."""
        return self._applied_updates + len(self._buffer_X)

    @property
    def buffered_count(self) -> int:
        return len(self._buffer_X)

    @property
    def applied_count(self) -> int:
        return self._applied_updates

    @property
    def model_version(self) -> str:
        return f"v0.{self._applied_updates // MIN_BATCH_SIZE}"

    # ── Server sync (distributed online learning) ─────────────────────────────

    @staticmethod
    def _get_server_url() -> str | None:
        """Load SERVER_URL from config.json. Returns None if not configured."""
        import json
        cfg_path = os.path.join(WORKSPACE, "config.json")
        try:
            with open(cfg_path) as f:
                url = json.load(f).get("server_url", "").strip()
            return url if url and url != "http://YOUR_SERVER_IP:5000" else None
        except Exception:
            return None

    @staticmethod
    def _get_server_headers() -> dict:
        """Build auth + ngrok headers from config.json."""
        import json
        hdrs = {"ngrok-skip-browser-warning": "1"}
        cfg_path = os.path.join(WORKSPACE, "config.json")
        try:
            with open(cfg_path) as f:
                key = json.load(f).get("server_api_key", "").strip()
            if key:
                hdrs["X-Helix-Key"] = key
        except Exception:
            pass
        return hdrs

    def push_correction_to_server(
        self,
        sha256: str,
        feature_vector: list[float],
        label: int,          # 0=benign, 1=malware
        client_id: str = "",
    ) -> bool:
        """
        Send a user correction to the central HELIX server (non-blocking).
        The server accumulates corrections and retrains when it has enough.

        Returns True if queued successfully, False if server not configured or unavailable.
        """
        server_url = self._get_server_url()
        if not server_url:
            return False   # server not configured — local-only learning

        import threading, socket, json as json_lib

        payload = {
            "sha256":    sha256,
            "features":  [float(x) for x in feature_vector],
            "label":     int(label),
            "client_id": client_id or socket.gethostname(),
        }

        def _do_push():
            try:
                import requests
                hdrs = self._get_server_headers()
                resp = requests.post(
                    f"{server_url}/api/correct",
                    json=payload,
                    headers=hdrs,
                    timeout=6,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    print(f"[OnlineLearner] Correction pushed to server. "
                          f"Status: {data.get('status')} | "
                          f"Retrain in: {data.get('retrain_in', '?')} corrections")
                elif resp.status_code == 401:
                    print("[OnlineLearner] Server rejected push: unauthorized (check server_api_key)")
                elif resp.status_code == 429:
                    print("[OnlineLearner] Server rejected push: daily rate limit reached")
            except Exception as e:
                print(f"[OnlineLearner] Server push failed (offline?): {e}")

        threading.Thread(target=_do_push, daemon=True).start()
        return True

    def check_model_update(self) -> bool:
        """
        Polls the central server for a newer model.
        If the server has a newer version, downloads and reloads it.
        Called automatically on startup.

        Returns True if model was updated, False otherwise.
        """
        server_url = self._get_server_url()
        if not server_url:
            return False

        try:
            import requests
            hdrs = self._get_server_headers()
            resp = requests.get(f"{server_url}/api/model/info", headers=hdrs, timeout=4)
            if resp.status_code != 200:
                return False

            remote_mtime = resp.json().get("mtime", 0)
            local_mtime  = (
                os.path.getmtime(BEST_PATH)
                if os.path.exists(BEST_PATH) else 0
            )

            if remote_mtime <= local_mtime:
                return False    # local model is up to date

            # Download the newer model
            print("[OnlineLearner] Newer model available — downloading...")
            dl = requests.get(f"{server_url}/api/model/download", headers=hdrs, timeout=30)
            if dl.status_code != 200:
                return False

            # Write to temp then atomically replace
            tmp_path = BEST_PATH + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(dl.content)
            os.replace(tmp_path, BEST_PATH)

            # Reload stable model
            with open(BEST_PATH, "rb") as f:
                bundle = pickle.load(f)
            self._stable_model  = bundle["model"]
            self._stable_scaler = bundle["scaler"]
            self._label_encoder = bundle.get("label_encoder")

            print("[OnlineLearner] Model updated from server.")
            return True

        except Exception as e:
            print(f"[OnlineLearner] Model update check failed: {e}")
            return False
