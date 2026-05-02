"""
vt_check.py — VirusTotal Hash Lookup (Free API, 4 req/min)

Queries the VirusTotal v3 API for a SHA256 hash before running local ML.
If the hash is a known confirmed threat, returns instantly without ML inference.

Configure your API key in config.json:
    { "virustotal_api_key": "YOUR_KEY_HERE" }

Get a FREE key at: https://www.virustotal.com/gui/join-us

If no key is configured, or the request fails, returns None (skip VT, use ML).
"""
from __future__ import annotations
import hashlib, json, os, time
import threading

try:
    import requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

WORKSPACE   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(WORKSPACE, "config.json")

# Rate limiter: free tier = 4 lookups / minute
_rate_lock     = threading.Lock()
_last_req_time = 0.0
_MIN_INTERVAL  = 15.1   # seconds between requests (4/min = 1 per 15s)

VT_URL = "https://www.virustotal.com/api/v3/files/{hash}"


def _get_api_key() -> str | None:
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f).get("virustotal_api_key")
    except Exception:
        return None


def sha256_of_file(filepath: str) -> str:
    """Compute SHA-256 of a file in chunks (handles large files)."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception:
        pass
    return h.hexdigest()


def check_hash(filepath: str) -> dict | None:
    """
    Looks up the SHA256 of the file on VirusTotal.

    Returns:
        {
            "sha256":        str,
            "vt_malicious":  int,    # number of AV engines flagging as malware
            "vt_total":      int,    # total AV engines that scanned it
            "vt_verdict":    str,    # "malware" | "suspicious" | "clean" | "unknown"
            "vt_score":      float,  # vt_malicious / vt_total (0.0 – 1.0)
        }
        None  — if VT check skipped (no key, rate-limited, network error)
    """
    global _last_req_time

    if not _REQUESTS_OK:
        return None

    api_key = _get_api_key()
    if not api_key or api_key == "YOUR_KEY_HERE":
        return None

    sha = sha256_of_file(filepath)

    # Rate-limit enforcement
    with _rate_lock:
        elapsed = time.time() - _last_req_time
        if elapsed < _MIN_INTERVAL:
            time.sleep(_MIN_INTERVAL - elapsed)
        _last_req_time = time.time()

    try:
        resp = requests.get(
            VT_URL.format(hash=sha),
            headers={"x-apikey": api_key},
            timeout=3,   # reduced from 8s — fast fail keeps scan responsive
        )
    except Exception:
        return None

    if resp.status_code == 404:
        # Hash not in VT database — new file, rely on ML
        return {"sha256": sha, "vt_malicious": 0, "vt_total": 0,
                "vt_verdict": "unknown", "vt_score": 0.0}

    if resp.status_code != 200:
        return None

    try:
        data  = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        mal   = stats.get("malicious",  0)
        sus   = stats.get("suspicious", 0)
        total = sum(stats.values())

        score = (mal + sus * 0.5) / total if total > 0 else 0.0

        if mal >= 5:
            verdict = "malware"
        elif mal >= 2 or sus >= 5:
            verdict = "suspicious"
        elif mal == 0 and sus == 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        return {
            "sha256":       sha,
            "vt_malicious": mal,
            "vt_total":     total,
            "vt_verdict":   verdict,
            "vt_score":     round(score, 4),
        }
    except Exception:
        return None


def vt_verdict_to_score(vt: dict | None) -> float | None:
    """
    Convert VT result to a threat score (0.0 – 1.0).
    Returns None if VT check was skipped or hash is unknown.
    Returns a confident score only if >= 5 engines flagged it.
    """
    if vt is None or vt["vt_verdict"] == "unknown":
        return None
    if vt["vt_verdict"] == "clean":
        return 0.02    # very likely safe
    if vt["vt_verdict"] == "malware":
        return min(0.5 + vt["vt_malicious"] / vt["vt_total"] * 0.5, 0.99)
    return 0.55        # suspicious
