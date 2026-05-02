"""
trace_parser.py — Convert sandbox DLL state into a structured trace

After each instruction executes through the sandbox:
  1. sandbox_bridge.py updates DLL state (regs, flags, stack, memory, counters)
  2. trace_parser.snapshot_step() captures the current state as a dict
  3. At the end, build_trace_summary() computes the final behavioral profile

The trace_summary dict feeds directly into features/extractor.py.
"""

from __future__ import annotations
from bridge.sandbox_bridge import SandboxBridge


# ── Per-step snapshot ─────────────────────────────────────────────────────────

def snapshot_step(sb: SandboxBridge, opcode: str, raw_op: str = "") -> dict:
    """
    Capture a single instruction's CPU state snapshot from the DLL.

    Args:
        sb:      Live SandboxBridge instance (wraps the DLL)
        opcode:  Mnemonic of the instruction just executed ("MOV", "PUSH" …)
        raw_op:  Full operand string for context ("rbx, rcx" etc.)

    Returns:
        A dict representing one row in the execution trace.
    """
    return {
        "opcode":      opcode.upper(),
        "raw":         f"{opcode} {raw_op}".strip(),

        # Register state (16-bit values)
        "AX": sb.get_reg(0),
        "BX": sb.get_reg(1),
        "CX": sb.get_reg(2),
        "DX": sb.get_reg(3),
        "SP": sb.get_reg(4),
        "BP": sb.get_reg(5),

        # Flag state
        "ZF": sb.zf,
        "CF": sb.cf,
        "SF": sb.sf,
        "OF": sb.of,

        # Stack at this moment
        "stack_depth": sb.stack_depth,
    }


# ── Final trace summary ───────────────────────────────────────────────────────

def build_trace_summary(sb: SandboxBridge,
                         steps: list[dict]) -> dict:
    """
    Build the complete behavioral profile from the sandbox final state.

    This is what features/extractor.py will consume to compute the
    14 ML features.

    Args:
        sb:    SandboxBridge after all instructions have been executed.
        steps: List of per-step snapshots from snapshot_step().

    Returns:
        A single dict with all behavioral counters and statistics.
    """
    n = len(steps)
    if n == 0:
        return _empty_summary()

    # ── Register volatility: how often did reg values change? ────────────────
    reg_changes = 0
    prev = {k: 0 for k in ("AX", "BX", "CX", "DX")}
    for step in steps:
        for reg in ("AX", "BX", "CX", "DX"):
            if step[reg] != prev[reg]:
                reg_changes += 1
                prev[reg] = step[reg]
    register_volatility = round(reg_changes / n, 4)

    # ── Flag change rate: how often did any flag flip? ───────────────────────
    flag_changes = 0
    prev_flags = {"ZF": 0, "CF": 0, "SF": 0, "OF": 0}
    for step in steps:
        for f in ("ZF", "CF", "SF", "OF"):
            if step[f] != prev_flags[f]:
                flag_changes += 1
                prev_flags[f] = step[f]
    avg_flag_change_rate = round(flag_changes / n, 4)

    # ── Stack anomaly: PUSH/POP imbalance ──────────────────────────────────
    # FIX: Partial PE emulation always sees function prologues (PUSH RBP,
    #      PUSH R12, PUSH R13 ...) without the matching POPs at RET.
    #      Only flag as anomalous if we've seen BOTH enough pushes AND pops.
    #      If pop_count < 5 we likely just hit a function prologue, not malware.
    push_count  = sb.push_count
    pop_count   = sb.pop_count
    total_stack = push_count + pop_count
    if total_stack < 20 or pop_count < 5:
        # Not enough stack activity to judge — return neutral 0.0
        stack_anomaly_score = 0.0
    else:
        imbalance = abs(push_count - pop_count)
        stack_anomaly_score = round(min(imbalance / total_stack, 1.0), 4)

    # ── Control flow entropy: variety of opcode types ────────────────────────
    from math import log2
    opcode_counts: dict[str, int] = {}
    for step in steps:
        op = step["opcode"]
        opcode_counts[op] = opcode_counts.get(op, 0) + 1
    entropy = 0.0
    for cnt in opcode_counts.values():
        p = cnt / n
        if p > 0:
            entropy -= p * log2(p)
    control_flow_entropy = round(entropy, 4)

    # ── Loop density: backward jumps per instruction ──────────────────────────
    loop_density = round(sb.backward_jump_count / n, 4)

    # ── Memory write density: writes per instruction ─────────────────────────
    memory_write_density = round(sb.write_count / n, 4)

    # ── INT frequency: INT instructions per 100 steps ────────────────────────
    int_frequency = round(sb.int_count / n * 100, 4)

    # ── CALL/RET imbalance ────────────────────────────────────────────────────
    call_ret_imbalance = abs(sb.call_count - sb.ret_count)

    # ── NOP sled ratio ────────────────────────────────────────────────────────
    nop_sled_ratio = round(sb.nop_count / n, 4)

    # ── Anti-evasion: CPUID and RDTSC usage ──────────────────────────────────
    cpuid_frequency   = round(sb.cpuid_count / n * 100, 4)
    rdtsc_check       = 1 if sb.rdtsc_count > 0 else 0

    # ── Unique opcodes used ───────────────────────────────────────────────────
    unique_opcodes = len(opcode_counts)

    return {
        # --- Core behavioral features (14 total) ----------------------------
        "register_volatility":   register_volatility,
        "stack_anomaly_score":   stack_anomaly_score,
        "max_stack_depth":       sb.max_stack_depth,
        "control_flow_entropy":  control_flow_entropy,
        "memory_write_density":  memory_write_density,
        "int_frequency":         int_frequency,
        "self_modify_detected":  0,          # requires runtime comparison (Phase 3+)
        "unique_opcodes":        unique_opcodes,
        "call_ret_imbalance":    call_ret_imbalance,
        "avg_flag_change_rate":  avg_flag_change_rate,
        "loop_density":          loop_density,
        "nop_sled_ratio":        nop_sled_ratio,
        "cpuid_frequency":       cpuid_frequency,    # NEW: antievasion feature #13
        "rdtsc_check":           rdtsc_check,        # NEW: antievasion feature #14

        # --- Raw counters (for debugging / extended analysis) ---------------
        "_steps":          n,
        "_push_count":     push_count,
        "_pop_count":      pop_count,
        "_write_count":    sb.write_count,
        "_jump_count":     sb.jump_count,
        "_back_jumps":     sb.backward_jump_count,
        "_int_count":      sb.int_count,
        "_call_count":     sb.call_count,
        "_ret_count":      sb.ret_count,
        "_nop_count":      sb.nop_count,
        "_cpuid_count":    sb.cpuid_count,
        "_rdtsc_count":    sb.rdtsc_count,
        "_unique_opcodes": unique_opcodes,
    }


def _empty_summary() -> dict:
    """Return a zeroed summary for empty/unreadable programs."""
    keys = [
        "register_volatility", "stack_anomaly_score", "max_stack_depth",
        "control_flow_entropy", "memory_write_density", "int_frequency",
        "self_modify_detected", "unique_opcodes", "call_ret_imbalance",
        "avg_flag_change_rate", "loop_density", "nop_sled_ratio",
        "cpuid_frequency", "rdtsc_check",
    ]
    return {k: 0 for k in keys}
