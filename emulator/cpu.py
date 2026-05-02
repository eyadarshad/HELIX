"""
cpu.py – Core CPU state: registers, flags, and memory model.

This is the heart of the COAL sandbox. It simulates a 16-bit x86-like
CPU with AX, BX, CX, DX, SP, BP, IP, and a FLAGS register.

Memory is divided into three logical segments:
  - Code  segment: stores instruction strings (index = address)
  - Data  segment: 64KB word-addressable memory (dict)
  - Stack segment: 256 word slots (index from STACK_BASE downward)
"""

STACK_BASE = 0xFFFF  # Stack starts at top of memory, grows downward
MEM_SIZE   = 0x10000  # 64K words

class FLAGS:
    """Bit-field flags register."""
    ZF: int = 0   # Zero Flag
    CF: int = 0   # Carry Flag
    SF: int = 0   # Sign Flag
    OF: int = 0   # Overflow Flag

    def reset(self):
        self.ZF = self.CF = self.SF = self.OF = 0

    def update_arithmetic(self, result: int, bit_width: int = 16):
        """Set ZF, SF, CF based on an arithmetic result."""
        mask = (1 << bit_width) - 1
        self.ZF = 1 if (result & mask) == 0 else 0
        self.SF = 1 if (result >> (bit_width - 1)) & 1 else 0
        self.CF = 1 if result > mask or result < 0 else 0

    def as_dict(self) -> dict:
        return {"ZF": self.ZF, "CF": self.CF, "SF": self.SF, "OF": self.OF}


class CPU:
    """
    Simulated 16-bit CPU.

    Attributes
    ----------
    registers : dict
        General-purpose registers: AX, BX, CX, DX, SP, BP.
    IP : int
        Instruction pointer (program counter).
    flags : FLAGS
        CPU flags object.
    memory : dict
        Word-addressable data memory {address: value}.
    code : list[str]
        Loaded assembly instructions (one per line).
    stack : list[int]
        Runtime stack (push appends, pop removes from end).
    halted : bool
        True when HLT or fatal error encountered.
    trace : list[dict]
        Full execution trace — one entry per instruction executed.
    """

    REGISTERS = ["AX", "BX", "CX", "DX", "SP", "BP"]

    def __init__(self):
        self.registers: dict[str, int] = {r: 0 for r in self.REGISTERS}
        self.IP: int = 0
        self.flags: FLAGS = FLAGS()
        self.memory: dict[int, int] = {}  # data segment
        self.code: list[str] = []         # code segment
        self.stack: list[int] = []        # value stack
        self.halted: bool = False
        self.trace: list[dict] = []       # execution log

    # ------------------------------------------------------------------
    # Register helpers
    # ------------------------------------------------------------------

    def get_reg(self, name: str) -> int:
        name = name.upper()
        if name not in self.registers:
            raise ValueError(f"Unknown register: {name}")
        return self.registers[name]

    def set_reg(self, name: str, value: int):
        name = name.upper()
        if name not in self.registers:
            raise ValueError(f"Unknown register: {name}")
        self.registers[name] = value & 0xFFFF  # keep 16-bit

    # ------------------------------------------------------------------
    # Memory helpers
    # ------------------------------------------------------------------

    def mem_read(self, address: int) -> int:
        return self.memory.get(address & 0xFFFF, 0)

    def mem_write(self, address: int, value: int):
        self.memory[address & 0xFFFF] = value & 0xFFFF

    # ------------------------------------------------------------------
    # Stack helpers
    # ------------------------------------------------------------------

    def stack_push(self, value: int):
        self.stack.append(value & 0xFFFF)
        self.registers["SP"] = (self.registers["SP"] - 1) & 0xFFFF

    def stack_pop(self) -> int:
        if not self.stack:
            raise RuntimeError("Stack underflow")
        self.registers["SP"] = (self.registers["SP"] + 1) & 0xFFFF
        return self.stack.pop()

    # ------------------------------------------------------------------
    # Snapshot helper (for tracing)
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        return {
            "IP": self.IP,
            "regs": dict(self.registers),
            "flags": self.flags.as_dict(),
            "stack_depth": len(self.stack),
        }

    # ------------------------------------------------------------------
    # Load program
    # ------------------------------------------------------------------

    def load(self, instructions: list[str]):
        """Load a list of assembly instruction strings into code segment."""
        self.code = [line.strip() for line in instructions if line.strip()]
        self.IP = 0

    def reset(self):
        """Full CPU reset."""
        self.registers = {r: 0 for r in self.REGISTERS}
        self.IP = 0
        self.flags.reset()
        self.memory.clear()
        self.code.clear()
        self.stack.clear()
        self.halted = False
        self.trace.clear()
