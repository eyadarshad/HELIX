"""
helix_server.py — HELIX Central Learning Server (Hardened v2)

A lightweight Flask server with API key authentication and rate limiting:
    1. Clients POST feature corrections → validated with API key → stored in SQLite
    2. When 50+ new corrections accumulate → background retrain triggers
    3. Clients GET latest model info → download updated model if authenticated

SECURITY (Fix 3):
    - All endpoints except /api/health require X-Helix-Key header
    - HMAC comparison (timing-safe) against SERVER_API_KEY env var
    - Per-device rate limiting: max 10 corrections per 24h per device_id
    - Model download requires authentication (prevents model theft)

SETUP:
    SET HELIX_API_KEY=my-secret-key-here
    python server/helix_server.py

    Or set "server_api_key" in config.json on each client.
"""
from __future__ import annotations
import os, sys, json, time, pickle, hashlib, hmac, threading, sqlite3
from datetime import datetime
from collections import defaultdict, deque
from functools import wraps

WORKSPACE   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKSPACE)

DB_PATH     = os.path.join(WORKSPACE, "server", "corrections.db")
MODEL_PATH  = os.path.join(WORKSPACE, "ml",     "models", "best_model.pkl")
RETRAIN_AT  = 50

# ── API Key from environment or config.json ───────────────────────────────────
_cfg_path = os.path.join(WORKSPACE, "config.json")
try:
    with open(_cfg_path) as f:
        _cfg = json.load(f)
except Exception:
    _cfg = {}

API_KEY = os.environ.get("HELIX_API_KEY", _cfg.get("server_api_key", ""))

# ── Rate limiting ─────────────────────────────────────────────────────────────
MAX_CORRECTIONS_PER_DAY = 10
_rate_limits: dict[str, deque] = defaultdict(deque)  # {device_id: deque[timestamps]}

# ── Lazy Flask import ─────────────────────────────────────────────────────────
try:
    from flask import Flask, request, jsonify, send_file, abort
except ImportError:
    print("[!] Flask not installed. Run:  pip install flask")
    sys.exit(1)

app = Flask(__name__)
_retrain_lock          = threading.Lock()
_model_mtime           = 0.0
_pending_since_retrain = 0


# ── Auth decorator ────────────────────────────────────────────────────────────

def require_auth(f):
    """Decorator: require X-Helix-Key header matching SERVER_API_KEY."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_KEY:
            # No key configured = open mode (backwards compatible)
            return f(*args, **kwargs)

        client_key = request.headers.get("X-Helix-Key", "")
        if not client_key or not hmac.compare_digest(client_key, API_KEY):
            return jsonify({"error": "unauthorized", "hint": "set server_api_key in config.json"}), 401
        return f(*args, **kwargs)
    return decorated


def _check_rate_limit(device_id: str) -> bool:
    """Returns True if this device is within its daily correction quota."""
    now       = time.time()
    window    = 24 * 3600  # 24 hours
    timestamps = _rate_limits[device_id]

    # Purge entries older than 24h
    while timestamps and now - timestamps[0] > window:
        timestamps.popleft()

    if len(timestamps) >= MAX_CORRECTIONS_PER_DAY:
        return False  # rate limited

    timestamps.append(now)
    return True


# ── Database setup ────────────────────────────────────────────────────────────

def _init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS corrections (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sha256    TEXT,
            features  TEXT,
            label     INTEGER,
            client_id TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS model_versions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            accuracy  REAL,
            n_samples INTEGER,
            filepath  TEXT
        )
    """)
    con.commit()
    con.close()


def _save_correction(sha256: str, features: list, label: int, client_id: str):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO corrections (timestamp, sha256, features, label, client_id) "
        "VALUES (?, ?, ?, ?, ?)",
        (datetime.utcnow().isoformat(), sha256,
         json.dumps(features), int(label), client_id)
    )
    con.commit()
    con.close()


def _count_pending() -> int:
    try:
        con = sqlite3.connect(DB_PATH)
        n   = con.execute("SELECT COUNT(*) FROM corrections").fetchone()[0]
        con.close()
        return n
    except Exception:
        return 0


def _load_all_corrections():
    con  = sqlite3.connect(DB_PATH)
    rows = con.execute("SELECT features, label FROM corrections").fetchall()
    con.close()
    X = [json.loads(r[0]) for r in rows]
    y = [r[1]             for r in rows]
    return X, y


# ── Background retrain ────────────────────────────────────────────────────────

def _retrain_in_background():
    global _model_mtime, _pending_since_retrain

    with _retrain_lock:
        print(f"\n[Server] Starting retrain with all corrections...")
        try:
            from sklearn.ensemble import HistGradientBoostingClassifier
            from sklearn.calibration import CalibratedClassifierCV
            from features.extractor import FEATURE_NAMES
            import numpy as np
            import pandas as pd

            csv_path = os.path.join(WORKSPACE, "dataset", "behavioral_dataset.csv")
            df = pd.read_csv(csv_path)
            X_base = df[FEATURE_NAMES].values.astype(float)
            y_base = (df["label"] == "malware").astype(int).values

            X_corr, y_corr = _load_all_corrections()
            if X_corr:
                X_corr = np.array(X_corr)
                y_corr = np.array(y_corr)
                X_all = np.vstack([X_base, np.tile(X_corr, (3, 1))])
                y_all = np.concatenate([y_base, np.tile(y_corr, 3)])
            else:
                X_all, y_all = X_base, y_base

            with open(MODEL_PATH, "rb") as f:
                bundle = pickle.load(f)
            scaler = bundle["scaler"]
            X_scaled = scaler.transform(X_all)

            hgb = HistGradientBoostingClassifier(
                max_iter=200, max_depth=6, learning_rate=0.05,
                l2_regularization=0.1, early_stopping=True,
                n_iter_no_change=20, random_state=42,
                class_weight="balanced",
            )
            calibrated = CalibratedClassifierCV(hgb, method="sigmoid", cv=5)
            calibrated.fit(X_scaled, y_all)

            bundle["model"] = calibrated
            with open(MODEL_PATH, "wb") as f:
                pickle.dump(bundle, f)

            _model_mtime           = os.path.getmtime(MODEL_PATH)
            _pending_since_retrain = 0

            print(f"[Server] Retrain complete. Model updated. "
                  f"Trained on {len(X_all)} samples.")
        except Exception as e:
            print(f"[Server] Retrain FAILED: {e}")


# ── API Routes ────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    """Health check — no auth required (used for connectivity test)."""
    return jsonify({
        "status": "ok",
        "server": "HELIX Learning Server v2",
        "corrections": _count_pending(),
        "auth_required": bool(API_KEY),
    })


@app.route("/api/correct", methods=["POST"])
@require_auth
def receive_correction():
    """Receive a user correction from an authenticated client."""
    global _pending_since_retrain

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "expected JSON body"}), 400

    sha256    = data.get("sha256", "")
    features  = data.get("features", [])
    label     = data.get("label", -1)
    client_id = data.get("client_id", "unknown")

    if not features or label not in (0, 1):
        return jsonify({"error": "invalid payload"}), 400

    # Rate limit check
    if not _check_rate_limit(client_id):
        return jsonify({
            "error": "rate_limited",
            "message": f"Max {MAX_CORRECTIONS_PER_DAY} corrections per day per device.",
        }), 429

    _save_correction(sha256, features, label, client_id)
    _pending_since_retrain += 1

    if _pending_since_retrain >= RETRAIN_AT:
        t = threading.Thread(target=_retrain_in_background, daemon=True)
        t.start()
        return jsonify({"status": "saved", "retrain": "triggered"})

    remaining = RETRAIN_AT - _pending_since_retrain
    return jsonify({"status": "saved", "retrain_in": remaining})


@app.route("/api/model/info", methods=["GET"])
@require_auth
def model_info():
    """Return model version metadata so clients can decide whether to update."""
    try:
        stat = os.stat(MODEL_PATH)
        return jsonify({"mtime": stat.st_mtime, "size": stat.st_size})
    except Exception:
        return jsonify({"error": "model not found"}), 404


@app.route("/api/model/download", methods=["GET"])
@require_auth
def model_download():
    """Send the latest best_model.pkl to an authenticated client."""
    if not os.path.exists(MODEL_PATH):
        abort(404)
    return send_file(MODEL_PATH, as_attachment=True,
                     download_name="best_model.pkl",
                     mimetype="application/octet-stream")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _init_db()
    if os.path.exists(MODEL_PATH):
        _model_mtime = os.path.getmtime(MODEL_PATH)

    print("=" * 60)
    print("  HELIX Learning Server v2 (Hardened)")
    print("=" * 60)
    print(f"  DB              : {DB_PATH}")
    print(f"  Model           : {MODEL_PATH}")
    print(f"  Retrain at      : every {RETRAIN_AT} corrections")
    print(f"  Auth            : {'ENABLED (key set)' if API_KEY else 'DISABLED (no key)'}")
    print(f"  Rate limit      : {MAX_CORRECTIONS_PER_DAY} corrections/day/device")
    print(f"  Endpoints       :")
    print(f"    GET  /api/health            ← no auth needed")
    print(f"    POST /api/correct           ← requires X-Helix-Key")
    print(f"    GET  /api/model/info        ← requires X-Helix-Key")
    print(f"    GET  /api/model/download    ← requires X-Helix-Key")
    print("=" * 60)
    if not API_KEY:
        print("  ⚠  No API key set. Running in OPEN mode.")
        print("     Set HELIX_API_KEY env var or server_api_key in config.json")
    print(f"\n  Running on http://0.0.0.0:5000  (Ctrl+C to stop)\n")

    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
