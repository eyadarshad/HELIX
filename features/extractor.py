"""
extractor.py — Combined Feature Engine (36 features = 14 behavioral + 22 PE static)

Combines:
    - features/pe_extractor.py  : 22 static PE analysis features (primary signal)
    - Behavioral trace from sandbox : 14 instruction-level features (secondary signal)

The PE features are much more discriminative — they detect WHAT the program
imports (which dangerous APIs), HOW its binary is structured (entropy, sections),
and WHAT strings it contains (URLs, IPs, suspicious commands).

Features 1–22: Static PE (from pe_extractor.py)
Features 23–36: Behavioral sandbox (from trace_summary)
"""

from __future__ import annotations
from features.pe_extractor import PE_FEATURE_NAMES, extract_pe_features   # noqa: F401

# ── Behavioral feature names (14) ─────────────────────────────────────────────
BEHAVIORAL_FEATURE_NAMES = [
    "register_volatility",
    "stack_anomaly_score",
    "max_stack_depth",
    "control_flow_entropy",
    "memory_write_density",
    "int_frequency",
    "self_modify_detected",
    "unique_opcodes",
    "call_ret_imbalance",
    "avg_flag_change_rate",
    "loop_density",
    "nop_sled_ratio",
    "cpuid_frequency",
    "rdtsc_check",
]

# ── Combined feature names (36) — this is what the ML model sees ──────────────
FEATURE_NAMES = PE_FEATURE_NAMES + BEHAVIORAL_FEATURE_NAMES


def extract_features(trace_summary: dict, filepath: str | None = None) -> dict:
    """
    Extract all 36 features.

    Args:
        trace_summary : dict from bridge.trace_parser (behavioral features)
                        Pass {} if sandbox was skipped (PE features still work).
        filepath      : path to the PE file (for static PE features).
                        Pass None to get only behavioral features.

    Returns:
        dict with all 36 feature names as keys.
    """
    # ── Part 1: Static PE features ────────────────────────────────────────────
    if filepath:
        pe_feats = extract_pe_features(filepath)
    else:
        pe_feats = {f: 0.0 for f in PE_FEATURE_NAMES}

    # ── Part 2: Behavioral features ───────────────────────────────────────────
    if trace_summary and trace_summary.get("_steps", 0) > 0:
        n = trace_summary["_steps"]
        beh_feats = {
            "register_volatility":  round(float(trace_summary.get("register_volatility",  0)), 4),
            "stack_anomaly_score":  round(float(trace_summary.get("stack_anomaly_score",  0)), 4),
            "max_stack_depth":      round(float(trace_summary.get("max_stack_depth",       0)), 4),
            "control_flow_entropy": round(float(trace_summary.get("control_flow_entropy",  0)), 4),
            "memory_write_density": round(float(trace_summary.get("memory_write_density",  0)), 4),
            "int_frequency":        round(float(trace_summary.get("int_frequency",         0)), 4),
            "self_modify_detected": round(float(trace_summary.get("self_modify_detected",  0)), 4),
            "unique_opcodes":       round(float(trace_summary.get("unique_opcodes",        0)), 4),
            "call_ret_imbalance":   round(float(
                trace_summary.get("call_ret_imbalance", 0) / max(n, 1)
            ), 4),
            "avg_flag_change_rate": round(float(trace_summary.get("avg_flag_change_rate",  0)), 4),
            "loop_density":         round(float(trace_summary.get("loop_density",          0)), 4),
            "nop_sled_ratio":       round(float(trace_summary.get("nop_sled_ratio",        0)), 4),
            "cpuid_frequency":      round(float(trace_summary.get("cpuid_frequency",       0)), 4),
            "rdtsc_check":          round(float(trace_summary.get("rdtsc_check",           0)), 4),
        }
    else:
        beh_feats = {f: 0.0 for f in BEHAVIORAL_FEATURE_NAMES}

    return {**pe_feats, **beh_feats}


def features_to_vector(features: dict) -> list[float]:
    """Return features as a fixed-order list matching FEATURE_NAMES."""
    return [features[name] for name in FEATURE_NAMES]
