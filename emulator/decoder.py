"""
decoder.py – Instruction decoder for the 16-bit assembly sandbox.

Supported syntax (case-insensitive):
    MOV  dst, src        ; register-to-register or immediate
    ADD  dst, src
    SUB  dst, src
    MUL  dst, src
    DIV  dst, src
    AND  dst, src
    OR   dst, src
    XOR  dst, src
    NOT  dst
    CMP  op1, op2
    PUSH src
    POP  dst
    JMP  label/address
    JZ   label/address
    JNZ  label/address
    JG   label/address
    JL   label/address
    CALL label/address
    RET
    INT  code
    NOP
    HLT

Operand types decoded:
    - Register  (AX, BX, CX, DX, SP, BP)
    - Immediate (decimal integer literal)
    - Memory    [address]  – simple direct addressing
    - Label     (string, resolved at load time)
"""

import re

REGISTERS = {"AX", "BX", "CX", "DX", "SP", "BP"}

ONE_OPERAND_OPS  = {"NOT", "PUSH", "POP", "JMP", "JZ", "JNZ", "JG", "JL",
                    "CALL", "INT"}
TWO_OPERAND_OPS  = {"MOV", "ADD", "SUB", "MUL", "DIV", "AND", "OR", "XOR",
                    "CMP"}
ZERO_OPERAND_OPS = {"RET", "NOP", "HLT"}


class Operand:
    """
    Represents a decoded operand.

    kind : str  – 'register' | 'immediate' | 'memory' | 'label'
    value       – register name (str), integer, or label string
    """
    def __init__(self, kind: str, value):
        self.kind = kind
        self.value = value

    def __repr__(self):
        return f"Operand({self.kind}, {self.value!r})"


class Instruction:
    """
    Fully decoded instruction.

    opcode  : str        – uppercase mnemonic
    operands: list[Operand]
    raw     : str        – original source line
    """
    def __init__(self, opcode: str, operands: list, raw: str = ""):
        self.opcode   = opcode
        self.operands = operands
        self.raw      = raw

    def __repr__(self):
        ops = ", ".join(repr(o) for o in self.operands)
        return f"Instruction({self.opcode}, [{ops}])"


def _parse_operand(token: str) -> Operand:
    """Convert a raw token string into an Operand object."""
    token = token.strip()

    # Memory: [addr] or [register]
    m = re.fullmatch(r'\[(.+)\]', token)
    if m:
        inner = m.group(1).strip().upper()
        if inner in REGISTERS:
            return Operand("memory_reg", inner)
        try:
            return Operand("memory", int(inner, 0))
        except ValueError:
            return Operand("memory_label", inner)

    # Register
    upper = token.upper()
    if upper in REGISTERS:
        return Operand("register", upper)

    # Immediate (decimal or hex 0x...)
    try:
        return Operand("immediate", int(token, 0))
    except ValueError:
        pass

    # Label / address string
    return Operand("label", token.upper())


def decode_line(line: str) -> Instruction | None:
    """
    Decode a single source line into an Instruction.

    Returns None for blank lines and comment-only lines.
    Labels (e.g. 'LOOP:') are returned as Instruction('LABEL', ...).
    """
    # Strip inline comments
    line = re.sub(r';.*$', '', line).strip()
    if not line:
        return None

    # Label definition (e.g. "LOOP:" or "START:")
    if re.fullmatch(r'[A-Za-z_]\w*:', line):
        return Instruction("LABEL", [Operand("label", line[:-1].upper())], raw=line)

    # Split mnemonic from operands
    parts = line.split(None, 1)   # max split = 1
    mnemonic = parts[0].upper()
    operand_str = parts[1] if len(parts) > 1 else ""

    if mnemonic in ZERO_OPERAND_OPS:
        return Instruction(mnemonic, [], raw=line)

    # Parse comma-separated operands
    raw_ops = [t.strip() for t in operand_str.split(',')]
    operands = [_parse_operand(tok) for tok in raw_ops if tok]

    return Instruction(mnemonic, operands, raw=line)


def decode_program(source: list[str]) -> tuple[list[Instruction], dict[str, int]]:
    """
    Decode an entire program.

    Returns
    -------
    instructions : list[Instruction]
        Decoded instructions (labels stripped out).
    label_map : dict[str, int]
        Mapping of label name → instruction index.
    """
    instructions: list[Instruction] = []
    label_map: dict[str, int] = {}

    for line in source:
        instr = decode_line(line)
        if instr is None:
            continue
        if instr.opcode == "LABEL":
            label_name = instr.operands[0].value
            label_map[label_name] = len(instructions)
        else:
            instructions.append(instr)

    return instructions, label_map
