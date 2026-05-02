"""
test_bridge.py — Smoke test for sandbox_core.dll

Run this AFTER build.bat has compiled sandbox_core.dll:
    python test_bridge.py

All tests should print [PASS].
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bridge.sandbox_bridge import SandboxBridge, AX, BX, CX, DX, ZF, CF, SF

def test(name, result, expected):
    status = "[PASS]" if result == expected else f"[FAIL] expected {expected}, got {result}"
    print(f"  {status}  {name}")
    return result == expected

sb = SandboxBridge(dll_dir=os.path.dirname(__file__))
sb.init()

print("\n── Registers ──────────────────────────────")
sb.set_reg(AX, 0x1234)
test("set/get AX = 0x1234",  sb.get_reg(AX), 0x1234)
sb.set_reg(BX, 0xABCD)
test("set/get BX = 0xABCD",  sb.get_reg(BX), 0xABCD)
test("16-bit mask: set AX = 0x1FFFF → 0xFFFF", (sb.set_reg(AX, 0x1FFFF), sb.get_reg(AX))[1], 0xFFFF)

print("\n── Flags (ADD) ────────────────────────────")
sb.set_reg(AX, 0)
sb.update_flags_add(0, 0)
test("ADD 0+0 → ZF=1",       sb.zf, 1)
sb.update_flags_add(1, 0)
test("ADD 1+0 → ZF=0",       sb.zf, 0)
sb.update_flags_add(0x8000, 1)
test("ADD 0x8000+1 → SF=1",  sb.sf, 1)
sb.update_flags_add(0xFFFF, 1)
test("ADD 0xFFFF+1 → CF=1",  sb.cf, 1)

print("\n── Flags (SUB) ────────────────────────────")
sb.update_flags_sub(5, 5)
test("SUB 5-5 → ZF=1",       sb.zf, 1)
sb.update_flags_sub(3, 5)
test("SUB 3-5 → CF=1 (borrow)", sb.cf, 1)

print("\n── Stack ───────────────────────────────────")
sb.init()
test("Initial stack depth = 0",   sb.stack_depth, 0)
sb.push(100)
sb.push(200)
sb.push(300)
test("After 3 pushes depth = 3",   sb.stack_depth, 3)
test("Max depth = 3",              sb.max_stack_depth, 3)
val = sb.pop()
test("Pop → 300 (LIFO)",           val, 300)
test("After pop depth = 2",        sb.stack_depth, 2)
test("push_count = 3",             sb.push_count, 3)
test("pop_count = 1",              sb.pop_count, 1)

print("\n── Memory ──────────────────────────────────")
sb.mem_write(0, 0xBEEF)
test("mem_write/read addr 0",      sb.mem_read(0), 0xBEEF)
sb.mem_write(100, 42)
test("mem_write/read addr 100",    sb.mem_read(100), 42)
test("write_count = 2",            sb.write_count, 2)

print("\n── Control Flow ────────────────────────────")
sb.record_jump(10, 3)   # backward
sb.record_jump(10, 20)  # forward
sb.record_jump(5, 1)    # backward
test("jump_count = 3",             sb.jump_count, 3)
test("backward_jump_count = 2",    sb.backward_jump_count, 2)

print("\n── Counters ────────────────────────────────")
sb.record("INT")
sb.record("INT")
sb.record("CALL")
sb.record("RET")
sb.record("NOP")
sb.record("NOP")
sb.record("NOP")
test("int_count = 2",              sb.int_count,  2)
test("call_count = 1",             sb.call_count, 1)
test("ret_count = 1",              sb.ret_count,  1)
test("nop_count = 3",              sb.nop_count,  3)
test("step_count = 7",             sb.step_count, 7)

print("\n── Snapshot ────────────────────────────────")
snap = sb.snapshot()
assert "regs" in snap and "flags" in snap
print("  [PASS]  snapshot() returns complete dict")

print("\n────────────────────────────────────────────")
print("  All sandbox_core.dll tests complete!")
print("────────────────────────────────────────────\n")
