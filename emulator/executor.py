"""
executor.py – Fetch-Decode-Execute loop for the CPU sandbox.

Implements every supported opcode by mutating the CPU state.
Each executed instruction appends an entry to cpu.trace.

Usage:
    from emulator.cpu import CPU
    from emulator.decoder import decode_program
    from emulator.executor import Executor

    cpu = CPU()
    instructions, labels = decode_program(source_lines)
    ex = Executor(cpu, instructions, labels)
    ex.run(max_steps=10000)
"""

from emulator.cpu import CPU
from emulator.decoder import Instruction, Operand

MAX_STEPS_DEFAULT = 10_000


class Executor:
    """
    Executes a decoded program inside the CPU sandbox.

    Parameters
    ----------
    cpu         : CPU        – the CPU state object
    instructions: list       – list of decoded Instruction objects
    label_map   : dict       – label name → instruction index
    """

    def __init__(self, cpu: CPU, instructions: list, label_map: dict):
        self.cpu          = cpu
        self.instructions = instructions
        self.label_map    = label_map
        self.call_stack   = []   # for CALL/RET return addresses

    # ------------------------------------------------------------------
    # Operand resolution
    # ------------------------------------------------------------------

    def _resolve(self, op: Operand) -> int:
        """Return the integer VALUE of an operand."""
        if op.kind == "register":
            return self.cpu.get_reg(op.value)
        if op.kind == "immediate":
            return op.value
        if op.kind == "memory":
            return self.cpu.mem_read(op.value)
        if op.kind == "memory_reg":
            addr = self.cpu.get_reg(op.value)
            return self.cpu.mem_read(addr)
        if op.kind == "label":
            return self.label_map.get(op.value, 0)
        raise ValueError(f"Cannot resolve operand: {op}")

    def _write(self, op: Operand, value: int):
        """Write a value to the destination operand."""
        if op.kind == "register":
            self.cpu.set_reg(op.value, value)
        elif op.kind == "memory":
            self.cpu.mem_write(op.value, value)
        elif op.kind == "memory_reg":
            addr = self.cpu.get_reg(op.value)
            self.cpu.mem_write(addr, value)
        else:
            raise ValueError(f"Cannot write to operand: {op}")

    # ------------------------------------------------------------------
    # Jump helpers
    # ------------------------------------------------------------------

    def _jump_to(self, op: Operand):
        """Set IP to address resolved from a label or immediate."""
        if op.kind == "label":
            target = self.label_map.get(op.value)
            if target is None:
                raise RuntimeError(f"Undefined label: {op.value}")
            self.cpu.IP = target
        else:
            self.cpu.IP = self._resolve(op)

    # ------------------------------------------------------------------
    # Opcode implementations
    # ------------------------------------------------------------------

    def _exec_mov(self, instr: Instruction):
        val = self._resolve(instr.operands[1])
        self._write(instr.operands[0], val)

    def _exec_add(self, instr: Instruction):
        a = self._resolve(instr.operands[0])
        b = self._resolve(instr.operands[1])
        result = a + b
        self.cpu.flags.update_arithmetic(result)
        self._write(instr.operands[0], result)

    def _exec_sub(self, instr: Instruction):
        a = self._resolve(instr.operands[0])
        b = self._resolve(instr.operands[1])
        result = a - b
        self.cpu.flags.update_arithmetic(result)
        self._write(instr.operands[0], result)

    def _exec_mul(self, instr: Instruction):
        a = self._resolve(instr.operands[0])
        b = self._resolve(instr.operands[1])
        result = a * b
        self.cpu.flags.update_arithmetic(result)
        self._write(instr.operands[0], result)

    def _exec_div(self, instr: Instruction):
        a = self._resolve(instr.operands[0])
        b = self._resolve(instr.operands[1])
        if b == 0:
            raise ZeroDivisionError("DIV by zero")
        result = a // b
        self.cpu.flags.update_arithmetic(result)
        self._write(instr.operands[0], result)

    def _exec_and(self, instr: Instruction):
        a = self._resolve(instr.operands[0])
        b = self._resolve(instr.operands[1])
        result = a & b
        self.cpu.flags.update_arithmetic(result)
        self._write(instr.operands[0], result)

    def _exec_or(self, instr: Instruction):
        a = self._resolve(instr.operands[0])
        b = self._resolve(instr.operands[1])
        result = a | b
        self.cpu.flags.update_arithmetic(result)
        self._write(instr.operands[0], result)

    def _exec_xor(self, instr: Instruction):
        a = self._resolve(instr.operands[0])
        b = self._resolve(instr.operands[1])
        result = a ^ b
        self.cpu.flags.update_arithmetic(result)
        self._write(instr.operands[0], result)

    def _exec_not(self, instr: Instruction):
        a = self._resolve(instr.operands[0])
        result = (~a) & 0xFFFF
        self._write(instr.operands[0], result)

    def _exec_cmp(self, instr: Instruction):
        a = self._resolve(instr.operands[0])
        b = self._resolve(instr.operands[1])
        result = a - b
        self.cpu.flags.update_arithmetic(result)
        # SF additionally used for JG/JL
        self.cpu.flags.SF = 1 if result < 0 else 0

    def _exec_push(self, instr: Instruction):
        val = self._resolve(instr.operands[0])
        self.cpu.stack_push(val)

    def _exec_pop(self, instr: Instruction):
        val = self.cpu.stack_pop()
        self._write(instr.operands[0], val)

    def _exec_jmp(self, instr: Instruction):
        self._jump_to(instr.operands[0])

    def _exec_jz(self, instr: Instruction):
        if self.cpu.flags.ZF:
            self._jump_to(instr.operands[0])
        else:
            self.cpu.IP += 1

    def _exec_jnz(self, instr: Instruction):
        if not self.cpu.flags.ZF:
            self._jump_to(instr.operands[0])
        else:
            self.cpu.IP += 1

    def _exec_jg(self, instr: Instruction):
        if not self.cpu.flags.ZF and not self.cpu.flags.SF:
            self._jump_to(instr.operands[0])
        else:
            self.cpu.IP += 1

    def _exec_jl(self, instr: Instruction):
        if self.cpu.flags.SF:
            self._jump_to(instr.operands[0])
        else:
            self.cpu.IP += 1

    def _exec_call(self, instr: Instruction):
        self.call_stack.append(self.cpu.IP + 1)
        self.cpu.stack_push(self.cpu.IP + 1)
        self._jump_to(instr.operands[0])

    def _exec_ret(self, instr: Instruction):
        ret_addr = self.cpu.stack_pop()
        if self.call_stack:
            self.call_stack.pop()
        self.cpu.IP = ret_addr

    def _exec_int(self, instr: Instruction):
        """
        Simulated interrupt handler.
        INT 0x21 → DOS-like print (no-op in sandbox, just logged).
        INT 0x80 → Linux-like syscall (no-op in sandbox).
        """
        # Actual effect is just tracing (handled in run loop)
        self.cpu.IP += 1

    def _exec_nop(self, instr: Instruction):
        self.cpu.IP += 1

    def _exec_hlt(self, instr: Instruction):
        self.cpu.halted = True

    # ------------------------------------------------------------------
    # Dispatch table
    # ------------------------------------------------------------------

    _HANDLERS = {
        "MOV":  _exec_mov,
        "ADD":  _exec_add,
        "SUB":  _exec_sub,
        "MUL":  _exec_mul,
        "DIV":  _exec_div,
        "AND":  _exec_and,
        "OR":   _exec_or,
        "XOR":  _exec_xor,
        "NOT":  _exec_not,
        "CMP":  _exec_cmp,
        "PUSH": _exec_push,
        "POP":  _exec_pop,
        "JMP":  _exec_jmp,
        "JZ":   _exec_jz,
        "JNZ":  _exec_jnz,
        "JG":   _exec_jg,
        "JL":   _exec_jl,
        "CALL": _exec_call,
        "RET":  _exec_ret,
        "INT":  _exec_int,
        "NOP":  _exec_nop,
        "HLT":  _exec_hlt,
    }

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    def run(self, max_steps: int = MAX_STEPS_DEFAULT) -> list[dict]:
        """
        Execute the loaded program for up to max_steps instructions.

        Returns the execution trace (list of per-step snapshots).
        """
        cpu = self.cpu
        steps = 0

        while not cpu.halted and steps < max_steps:
            if cpu.IP < 0 or cpu.IP >= len(self.instructions):
                break  # fell off the end of the program

            instr = self.instructions[cpu.IP]
            snap  = cpu.snapshot()
            snap["opcode"] = instr.opcode
            snap["raw"]    = instr.raw

            handler = self._HANDLERS.get(instr.opcode)
            if handler is None:
                raise RuntimeError(f"Unknown opcode: {instr.opcode}")

            # Default: advance IP (handlers override for jumps)
            old_ip = cpu.IP
            if instr.opcode not in ("JMP", "JZ", "JNZ", "JG", "JL",
                                    "CALL", "RET", "HLT", "NOP", "INT"):
                handler(self, instr)
                cpu.IP += 1
            else:
                handler(self, instr)

            cpu.trace.append(snap)
            steps += 1

        return cpu.trace
