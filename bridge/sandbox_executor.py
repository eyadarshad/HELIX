"""
sandbox_executor.py — Drive the sandbox DLL through an EXE's opcode stream

This is the ENGINE of Phase 2. It:
  1. Takes a list of (mnemonic, op_str, address) from disassembler.py
  2. Feeds each opcode into the NASM sandbox DLL via sandbox_bridge.py
  3. Simulates register/flag/stack/memory effects for each instruction
  4. Records a step snapshot via trace_parser.py after each instruction
  5. Returns (trace_summary, opcode_sequence) ready for the ML pipeline

Usage:
    from bridge.sandbox_executor import run_exe
    summary, opcodes = run_exe("notepad.exe")
    # summary = {"register_volatility": 0.42, "int_frequency": 0.0, ...}
    # opcodes = ["MOV", "PUSH", "ADD", ...]
"""

from __future__ import annotations
import os

from bridge.disassembler   import disassemble_exe
from bridge.sandbox_bridge import SandboxBridge, AX, BX, CX, DX, SP, BP
from bridge.trace_parser   import snapshot_step, build_trace_summary

# ── Register name → ID mapping ───────────────────────────────────────────────
_REG_MAP = {
    # 64-bit names (from Capstone on 64-bit EXEs)
    "rax": AX, "rbx": BX, "rcx": CX, "rdx": DX, "rsp": SP, "rbp": BP,
    # 32-bit names
    "eax": AX, "ebx": BX, "ecx": CX, "edx": DX, "esp": SP, "ebp": BP,
    # 16-bit names
    "ax":  AX, "bx":  BX, "cx":  CX, "dx":  DX, "sp":  SP, "bp":  BP,
}

# ── Immediate value parser ────────────────────────────────────────────────────
def _parse_imm(token: str) -> int | None:
    """Parse a hex (0x...) or decimal immediate string to int, or None."""
    token = token.strip().rstrip(",")
    try:
        return int(token, 0)   # handles 0x prefix or plain decimal
    except ValueError:
        return None


def _get_reg_id(token: str) -> int | None:
    """Return register ID (0-5) from a register name string, or None."""
    return _REG_MAP.get(token.strip().lower().rstrip(","))


# ── Sandbox execution loop ────────────────────────────────────────────────────

def run_exe(filepath: str,
            max_instructions: int = 5000
            ) -> tuple[dict, list[str]]:
    """
    Full pipeline: EXE file → behavioral trace summary + opcode sequence.

    Args:
        filepath:         Path to a PE binary (.exe or .dll)
        max_instructions: Instruction processing limit (default 5000)

    Returns:
        (trace_summary, opcode_sequence)
          trace_summary  — 14-feature dict for ML classification
          opcode_sequence — list of mnemonic strings for sequence model
    """
    # Step 1: Disassemble
    instructions = disassemble_exe(filepath, max_instructions)
    if not instructions:
        from bridge.trace_parser import _empty_summary
        return _empty_summary(), []

    # Step 2: Initialize sandbox DLL
    sb = SandboxBridge()
    sb.init()

    # Step 3: Execute each instruction through the sandbox
    steps      = []
    opcode_seq = []
    ip         = 0          # instruction index (used for jump logging)

    for mnem, op_str, addr in instructions:
        opcode = mnem.upper()
        opcode_seq.append(opcode)

        # Simulate the instruction's effect on CPU state
        _execute_instruction(sb, opcode, op_str, ip)

        # Record counter for instruction type
        sb.record(opcode)

        # Capture snapshot AFTER execution
        steps.append(snapshot_step(sb, opcode, op_str))
        ip += 1

    # Step 4: Build behavioral summary from final DLL state
    summary = build_trace_summary(sb, steps)
    return summary, opcode_seq


# ── Instruction simulator ─────────────────────────────────────────────────────

def _execute_instruction(sb: SandboxBridge,
                          opcode: str,
                          op_str: str,
                          ip: int):
    """
    Simulate the behavioral effect of one instruction on the sandbox.

    We don't simulate EVERY opcode precisely — we focus on the ones
    that produce behavioral signals relevant to malware detection:
    register changes, flag updates, stack changes, memory writes.

    Unknown opcodes are silently skipped (their presence is still counted).
    """
    parts = [p.strip() for p in op_str.split(",")]
    dst   = parts[0] if len(parts) > 0 else ""
    src   = parts[1] if len(parts) > 1 else ""

    dst_reg = _get_reg_id(dst)
    src_reg = _get_reg_id(src)
    src_imm = _parse_imm(src) if src_reg is None else None

    # ── Data transfer ────────────────────────────────────────────────────────
    if opcode in ("MOV", "MOVZX", "MOVSX", "LEA", "XCHG"):
        if dst_reg is not None:
            if src_reg is not None:
                val = sb.get_reg(src_reg)
            elif src_imm is not None:
                val = src_imm & 0xFFFF
            else:
                val = 0
            sb.set_reg(dst_reg, val)

    # ── Arithmetic (updates flags) ────────────────────────────────────────────
    elif opcode in ("ADD", "ADC"):
        if dst_reg is not None:
            a = sb.get_reg(dst_reg)
            b = sb.get_reg(src_reg) if src_reg is not None else (src_imm or 0)
            result = (a + b) & 0xFFFF
            sb.set_reg(dst_reg, result)
            sb.update_flags_add(a, b & 0xFFFF)

    elif opcode in ("SUB", "SBB", "CMP"):
        if dst_reg is not None:
            a = sb.get_reg(dst_reg)
            b = sb.get_reg(src_reg) if src_reg is not None else (src_imm or 0)
            sb.update_flags_sub(a, b & 0xFFFF)
            if opcode != "CMP":   # CMP doesn't store result
                sb.set_reg(dst_reg, (a - b) & 0xFFFF)

    elif opcode == "INC":
        if dst_reg is not None:
            val = (sb.get_reg(dst_reg) + 1) & 0xFFFF
            sb.set_reg(dst_reg, val)
            sb.update_flags_add(val - 1, 1)

    elif opcode == "DEC":
        if dst_reg is not None:
            val = (sb.get_reg(dst_reg) - 1) & 0xFFFF
            sb.set_reg(dst_reg, val)
            sb.update_flags_sub(val + 1, 1)

    elif opcode in ("IMUL", "MUL"):
        if dst_reg is not None:
            a = sb.get_reg(AX)
            b = sb.get_reg(src_reg) if src_reg is not None else (src_imm or 1)
            result = (a * b) & 0xFFFF
            sb.set_reg(AX, result)
            sb.set_reg(DX, ((a * b) >> 16) & 0xFFFF)

    elif opcode in ("XOR",):
        if dst_reg is not None:
            a = sb.get_reg(dst_reg)
            b = sb.get_reg(src_reg) if src_reg is not None else (src_imm or 0)
            result = (a ^ b) & 0xFFFF
            sb.set_reg(dst_reg, result)
            sb.update_flags_and(result)

    elif opcode in ("AND",):
        if dst_reg is not None:
            a = sb.get_reg(dst_reg)
            b = sb.get_reg(src_reg) if src_reg is not None else (src_imm or 0)
            result = (a & b) & 0xFFFF
            sb.set_reg(dst_reg, result)
            sb.update_flags_and(result)

    elif opcode in ("OR",):
        if dst_reg is not None:
            a = sb.get_reg(dst_reg)
            b = sb.get_reg(src_reg) if src_reg is not None else (src_imm or 0)
            result = (a | b) & 0xFFFF
            sb.set_reg(dst_reg, result)
            sb.update_flags_and(result)

    # ── Stack ─────────────────────────────────────────────────────────────────
    elif opcode == "PUSH":
        val = sb.get_reg(dst_reg) if dst_reg is not None else (
              _parse_imm(dst) or 0)
        sb.push(val & 0xFFFF)

    elif opcode == "POP":
        try:
            val = sb.pop()
            if dst_reg is not None:
                sb.set_reg(dst_reg, val)
        except RuntimeError:
            pass   # underflow: ignore

    # ── Control flow (record jumps) ───────────────────────────────────────────
    elif opcode in ("JMP", "JE", "JZ", "JNE", "JNZ",
                    "JG", "JL", "JA", "JB", "JGE", "JLE", "JAE", "JBE",
                    "JS", "JNS", "JO", "JNO", "JP", "JNP"):
        # We log all jumps; backward = loop detection
        # Target address parsing is approximate (we use ip-1 as a proxy)
        tgt_imm = _parse_imm(dst)
        to_ip   = tgt_imm if tgt_imm is not None else ip - 1
        sb.record_jump(ip, to_ip)

    elif opcode == "CALL":
        sb.push((ip + 1) & 0xFFFF)   # push return address

    elif opcode == "RET":
        try:
            sb.pop()
        except RuntimeError:
            pass

    # ── Memory writes (simplified: reg → mem) ────────────────────────────────
    elif opcode in ("MOV", "MOVS", "STOS", "STOSB", "STOSW", "STOSD"):
        if dst.startswith("[") or dst.startswith("byte") or \
           dst.startswith("word") or dst.startswith("qword"):
            addr = sb.get_reg(BX) if sb.get_reg(BX) > 0 else 0
            val  = sb.get_reg(AX)
            if addr < 4096:
                sb.mem_write(addr, val)

    # ── Antievasion instructions ──────────────────────────────────────────────
    # CPUID and RDTSC are counted via sb.record() called by the main loop
    # Nothing extra to simulate for these — their presence IS the signal

    # ── Everything else: skip (NOP, HLT, etc.) ────────────────────────────────
    # NOP, HLT, LEAVE, etc. are counted by sb.record() in the main loop


# ── CLI test ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, json

    target = sys.argv[1] if len(sys.argv) > 1 else \
             r"C:\Windows\System32\notepad.exe"

    print(f"\n[Sandbox Executor] Scanning: {target}")
    print("─" * 60)

    try:
        summary, opcodes = run_exe(target, max_instructions=2000)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    print(f"\n  Instructions processed : {summary['_steps']}")
    print(f"  Unique opcodes         : {summary['unique_opcodes']}")
    print(f"  First 15 opcodes       : {opcodes[:15]}")
    print()
    print("  ── Behavioral Features ──────────────────────────────")
    ml_features = {k: v for k, v in summary.items() if not k.startswith("_")}
    for feat, val in ml_features.items():
        bar = "█" * int(min(val * 20, 20)) if isinstance(val, float) else ""
        print(f"  {feat:<28} {str(val):<10} {bar}")
    print()
