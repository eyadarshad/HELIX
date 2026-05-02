"""
sandbox_bridge.py — Python ctypes interface to sandbox_core.dll

This module loads sandbox_core.dll (compiled from NASM x64 assembly)
and exposes all its functions as clean Python calls.

Usage:
    from bridge.sandbox_bridge import SandboxBridge
    sb = SandboxBridge()
    sb.init()
    sb.set_reg(0, 42)       # AX = 42
    print(sb.get_reg(0))    # → 42
    sb.push(100)
    print(sb.pop())         # → 100
"""

import ctypes
import os

# Register ID constants
AX, BX, CX, DX, SP, BP = 0, 1, 2, 3, 4, 5

# Flag ID constants
ZF, CF, SF, OF = 0, 1, 2, 3

# Opcode constants (used by executor to select counter)
OP_INT   = "INT"
OP_CALL  = "CALL"
OP_RET   = "RET"
OP_NOP   = "NOP"
OP_PUSH  = "PUSH"
OP_POP   = "POP"
OP_CPUID = "CPUID"
OP_RDTSC = "RDTSC"


class SandboxBridge:
    """
    Python wrapper around sandbox_core.dll.

    All arithmetic uses the assembly flag engine.
    Stack, memory, and control flow are managed by the DLL.
    Python (Capstone) drives the execution loop —
    the DLL maintains the CPU state.
    """

    DLL_NAME = "sandbox_core.dll"

    def __init__(self, dll_dir: str = None):
        if dll_dir is None:
            dll_dir = os.path.join(
                os.path.dirname(__file__), "..", "sandbox_core"
            )
        dll_path = os.path.abspath(os.path.join(dll_dir, self.DLL_NAME))

        if not os.path.exists(dll_path):
            raise FileNotFoundError(
                f"sandbox_core.dll not found at: {dll_path}\n"
                f"Run sandbox_core/build.bat first."
            )

        self._lib = ctypes.CDLL(dll_path)
        self._configure_types()

    def _configure_types(self):
        """Set argtypes and restype for every exported function."""
        lib = self._lib
        U = ctypes.c_uint64
        I = ctypes.c_int64

        lib.init_sandbox.argtypes = []
        lib.init_sandbox.restype  = ctypes.c_int

        lib.set_reg.argtypes = [U, U]
        lib.set_reg.restype  = ctypes.c_int

        lib.get_reg.argtypes = [U]
        lib.get_reg.restype  = U

        lib.update_flags_add.argtypes = [U, U]
        lib.update_flags_add.restype  = ctypes.c_int

        lib.update_flags_sub.argtypes = [U, U]
        lib.update_flags_sub.restype  = ctypes.c_int

        lib.update_flags_and.argtypes = [U]
        lib.update_flags_and.restype  = ctypes.c_int

        lib.get_flag.argtypes = [U]
        lib.get_flag.restype  = U

        lib.asm_push.argtypes = [U]
        lib.asm_push.restype  = ctypes.c_int

        lib.asm_pop.argtypes  = []
        lib.asm_pop.restype   = I   # signed: -1 on underflow

        lib.get_stack_depth.argtypes    = []
        lib.get_stack_depth.restype     = U
        lib.get_max_stack_depth.argtypes = []
        lib.get_max_stack_depth.restype  = U
        lib.get_push_count.argtypes     = []
        lib.get_push_count.restype      = U
        lib.get_pop_count.argtypes      = []
        lib.get_pop_count.restype       = U

        lib.mem_write.argtypes = [U, U]
        lib.mem_write.restype  = ctypes.c_int

        lib.mem_read.argtypes = [U]
        lib.mem_read.restype  = U

        lib.get_write_count.argtypes = []
        lib.get_write_count.restype  = U

        lib.record_jump.argtypes = [U, U]
        lib.record_jump.restype  = ctypes.c_int

        lib.get_jump_count.argtypes          = []
        lib.get_jump_count.restype           = U
        lib.get_backward_jump_count.argtypes = []
        lib.get_backward_jump_count.restype  = U

        for fn in ("record_int", "record_call", "record_ret",
                   "record_nop", "record_cpuid", "record_rdtsc",
                   "increment_step"):
            getattr(lib, fn).argtypes = []
            getattr(lib, fn).restype  = ctypes.c_int

        for fn in ("get_int_count", "get_call_count", "get_ret_count",
                   "get_nop_count", "get_cpuid_count", "get_rdtsc_count",
                   "get_step_count"):
            getattr(lib, fn).argtypes = []
            getattr(lib, fn).restype  = U

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def init(self):
        """Reset all CPU state. Call before each new program scan."""
        self._lib.init_sandbox()

    # Registers --------------------------------------------------------

    def set_reg(self, reg_id: int, value: int):
        self._lib.set_reg(reg_id, value & 0xFFFF)

    def get_reg(self, reg_id: int) -> int:
        return int(self._lib.get_reg(reg_id))

    # Flags ------------------------------------------------------------

    def update_flags_add(self, a: int, b: int):
        self._lib.update_flags_add(a & 0xFFFF, b & 0xFFFF)

    def update_flags_sub(self, a: int, b: int):
        self._lib.update_flags_sub(a & 0xFFFF, b & 0xFFFF)

    def update_flags_and(self, result: int):
        self._lib.update_flags_and(result & 0xFFFF)

    def get_flag(self, flag_id: int) -> int:
        return int(self._lib.get_flag(flag_id))

    @property
    def zf(self): return self.get_flag(ZF)
    @property
    def cf(self): return self.get_flag(CF)
    @property
    def sf(self): return self.get_flag(SF)
    @property
    def of(self): return self.get_flag(OF)

    # Stack ------------------------------------------------------------

    def push(self, value: int) -> bool:
        return self._lib.asm_push(value & 0xFFFF) == 0

    def pop(self) -> int:
        result = int(self._lib.asm_pop())
        if result == -1:
            raise RuntimeError("Stack underflow")
        return result & 0xFFFF

    @property
    def stack_depth(self) -> int:
        return int(self._lib.get_stack_depth())

    @property
    def max_stack_depth(self) -> int:
        return int(self._lib.get_max_stack_depth())

    @property
    def push_count(self) -> int:
        return int(self._lib.get_push_count())

    @property
    def pop_count(self) -> int:
        return int(self._lib.get_pop_count())

    # Memory -----------------------------------------------------------

    def mem_write(self, addr: int, value: int):
        return self._lib.mem_write(addr, value & 0xFFFF)

    def mem_read(self, addr: int) -> int:
        return int(self._lib.mem_read(addr))

    @property
    def write_count(self) -> int:
        return int(self._lib.get_write_count())

    # Control flow -----------------------------------------------------

    def record_jump(self, from_ip: int, to_ip: int):
        self._lib.record_jump(from_ip, to_ip)

    @property
    def jump_count(self) -> int:
        return int(self._lib.get_jump_count())

    @property
    def backward_jump_count(self) -> int:
        return int(self._lib.get_backward_jump_count())

    # Instruction counters ---------------------------------------------

    def record(self, opcode: str):
        """Record an opcode execution for counter tracking."""
        op = opcode.upper()
        if   op == "INT":   self._lib.record_int()
        elif op == "CALL":  self._lib.record_call()
        elif op == "RET":   self._lib.record_ret()
        elif op == "NOP":   self._lib.record_nop()
        elif op == "CPUID": self._lib.record_cpuid()
        elif op == "RDTSC": self._lib.record_rdtsc()
        self._lib.increment_step()

    @property
    def int_count(self):   return int(self._lib.get_int_count())
    @property
    def call_count(self):  return int(self._lib.get_call_count())
    @property
    def ret_count(self):   return int(self._lib.get_ret_count())
    @property
    def nop_count(self):   return int(self._lib.get_nop_count())
    @property
    def cpuid_count(self): return int(self._lib.get_cpuid_count())
    @property
    def rdtsc_count(self): return int(self._lib.get_rdtsc_count())
    @property
    def step_count(self):  return int(self._lib.get_step_count())

    # Snapshot ---------------------------------------------------------

    def snapshot(self) -> dict:
        """Return full CPU state as a Python dict (for feature extraction)."""
        return {
            "regs": {
                "AX": self.get_reg(AX), "BX": self.get_reg(BX),
                "CX": self.get_reg(CX), "DX": self.get_reg(DX),
                "SP": self.get_reg(SP), "BP": self.get_reg(BP),
            },
            "flags": {"ZF": self.zf, "CF": self.cf,
                      "SF": self.sf, "OF": self.of},
            "stack_depth":          self.stack_depth,
            "max_stack_depth":      self.max_stack_depth,
            "push_count":           self.push_count,
            "pop_count":            self.pop_count,
            "write_count":          self.write_count,
            "jump_count":           self.jump_count,
            "backward_jump_count":  self.backward_jump_count,
            "int_count":            self.int_count,
            "call_count":           self.call_count,
            "ret_count":            self.ret_count,
            "nop_count":            self.nop_count,
            "cpuid_count":          self.cpuid_count,
            "rdtsc_count":          self.rdtsc_count,
            "step_count":           self.step_count,
        }
