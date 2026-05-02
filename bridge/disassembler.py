"""
disassembler.py — EXE/DLL → ordered opcode stream using Capstone

Phase 2 Component: reads real PE binary files, extracts the .text
(code) section, disassembles it to x86/x64 instructions, and
returns a clean list of opcodes for the sandbox to process.

Usage:
    from bridge.disassembler import disassemble_exe
    opcodes = disassemble_exe("C:/Windows/System32/notepad.exe")
    # → [("MOV", "rcx, qword ptr [rip + 0x...]"), ("PUSH", "rbx"), ...]
"""

import os
import pefile
import capstone


# ── Constants ────────────────────────────────────────────────────────────────

# Max instructions to extract per file (prevents huge files blocking ML)
MAX_INSTRUCTIONS = 5000

# Opcodes our sandbox tracks with counters (used for feature extraction later)
TRACKED_OPCODES = {
    "nop", "int", "call", "ret", "push", "pop",
    "cpuid", "rdtsc", "hlt", "jmp",
    "je", "jz", "jne", "jnz", "jg", "jl", "ja", "jb",
    "jge", "jle", "jae", "jbe",
}


# ── Main API ─────────────────────────────────────────────────────────────────

def disassemble_exe(filepath: str,
                    max_instructions: int = MAX_INSTRUCTIONS
                    ) -> list[tuple[str, str, int]]:
    """
    Disassemble a PE binary and return its instruction stream.
    Handles packed/encrypted EXEs gracefully:
      - Tries all executable sections if .text gives 0 instructions
      - Tries 32-bit mode if 64-bit gives 0 instructions
      - Raises PackedBinaryError (not ValueError) if truly unreadable
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    sections, bits = _get_all_code_sections(filepath)
    if not sections:
        raise ValueError(f"No executable sections in: {filepath}")

    # Try each executable section, both bitnesses
    for raw_bytes, base_addr in sections:
        for b in ([bits, 32] if bits == 64 else [bits, 64]):
            instrs = _disassemble_bytes(raw_bytes, base_addr, b, max_instructions)
            if instrs:
                return instrs

    # All sections returned 0 instructions — binary is packed/encrypted
    raise PackedBinaryError(
        f"No disassemblable instructions found in: {os.path.basename(filepath)}\n"
        "Binary appears packed or encrypted (UPX, Themida, etc.). "
        "Packed binaries score as suspicious (threat ≈ 0.70)."
    )


def get_opcode_sequence(filepath: str,
                         max_instructions: int = MAX_INSTRUCTIONS
                         ) -> list[str]:
    """
    Convenience wrapper — returns ONLY the mnemonic names (uppercase).
    Used by the sequence ML model and the sandbox executor loop.

        ["MOV", "PUSH", "ADD", "JNZ", "INT", "RET", ...]
    """
    instrs = disassemble_exe(filepath, max_instructions)
    return [mnem.upper() for mnem, _, _ in instrs]


# ── Internal helpers ─────────────────────────────────────────────────────────

def _get_all_code_sections(filepath: str) -> tuple[list[tuple[bytes, int]], int]:
    """
    Returns (list of (raw_bytes, base_addr), bitness).
    Includes .text first, then all other executable sections as fallbacks.
    """
    try:
        pe = pefile.PE(filepath, fast_load=False)
    except pefile.PEFormatError as e:
        raise ValueError(f"Not a valid PE file: {filepath}\n{e}")

    bits = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32
    imgbase = pe.OPTIONAL_HEADER.ImageBase

    sections = []
    text_section = None

    for section in pe.sections:
        name = section.Name.decode(errors="replace").strip("\x00").lower()
        is_exec = bool(section.Characteristics & 0x20000000)
        if not is_exec and name not in (".text", "code", ".code"):
            continue
        entry = (section.get_data(), imgbase + section.VirtualAddress)
        if name in (".text", "code", ".code"):
            text_section = entry
        else:
            sections.append(entry)

    # Prioritise .text section
    if text_section:
        sections.insert(0, text_section)

    pe.close()
    return sections, bits


# Keep old helper for backward-compat imports
def _extract_code_section(filepath: str) -> tuple[bytes, int, int]:
    sections, bits = _get_all_code_sections(filepath)
    if not sections:
        raise ValueError(f"No executable code section found in: {filepath}")
    raw, base = sections[0]
    return raw, base, bits


def _disassemble_bytes(raw_bytes: bytes,
                        base_addr: int,
                        bits: int,
                        max_instructions: int) -> list[tuple[str, str, int]]:
    """
    Use Capstone to disassemble raw bytes into instructions.

    Returns list of (mnemonic, op_str, address).
    """
    if bits == 64:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    md.detail = False   # we only need mnemonic + op_str, not full decode tree

    results = []
    count   = 0

    for instr in md.disasm(raw_bytes, base_addr):
        results.append((instr.mnemonic, instr.op_str, instr.address))
        count += 1
        if count >= max_instructions:
            break

    return results


# ── CLI test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else \
             r"C:\Windows\System32\notepad.exe"

    print(f"\nDisassembling: {target}")
    print("─" * 60)

    try:
        instrs = disassemble_exe(target, max_instructions=50)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    for mnem, ops, addr in instrs:
        print(f"  {addr:#010x}   {mnem:<8} {ops}")

    print(f"\n  ... ({len(instrs)} instructions shown)")

    seq = get_opcode_sequence(target, max_instructions=200)
    print(f"\nOpcode sequence (first 20): {seq[:20]}")
    print(f"Total opcodes extracted:    {len(seq)}")
