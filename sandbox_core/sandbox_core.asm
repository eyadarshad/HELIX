; ============================================================
; sandbox_core.asm  —  NASM x64 Assembly Sandbox Core
; ============================================================
; This file IS the COAL deliverable.
; It simulates a 16-bit CPU (registers, flags, stack, memory)
; in x64 assembly and exports C-callable functions for Python.
;
; Assemble:  nasm -f win64 sandbox_core.asm -o sandbox_core.obj
; Link:      gcc -shared -o sandbox_core.dll sandbox_core.obj
;
; All exported functions use the Windows x64 calling convention:
;   Integer args:  RCX, RDX, R8, R9 (left to right)
;   Return value:  RAX
; ============================================================

global init_sandbox
global set_reg
global get_reg
global update_flags_add
global update_flags_sub
global update_flags_and
global get_flag
global asm_push
global asm_pop
global get_stack_depth
global get_max_stack_depth
global get_push_count
global get_pop_count
global mem_write
global mem_read
global get_write_count
global record_jump
global get_jump_count
global get_backward_jump_count
global record_int
global record_call
global record_ret
global record_nop
global record_cpuid
global record_rdtsc
global get_int_count
global get_call_count
global get_ret_count
global get_nop_count
global get_cpuid_count
global get_rdtsc_count
global get_step_count
global increment_step

section .data

; ============================================================
; CPU REGISTERS — 6 x 64-bit slots (values are 16-bit masked)
;   Index: 0=AX, 1=BX, 2=CX, 3=DX, 4=SP, 5=BP
; ============================================================
cpu_regs:   dq 0, 0, 0, 0, 0, 0   ; 6 x 8 bytes = 48 bytes

; ============================================================
; FLAGS — 4 x 64-bit (0 or 1)
;   Index: 0=ZF, 1=CF, 2=SF, 3=OF
; ============================================================
cpu_zf:     dq 0
cpu_cf:     dq 0
cpu_sf:     dq 0
cpu_of:     dq 0

; ============================================================
; STACK — 512 entries, grows downward
;   cpu_sp starts at STACK_MAX (empty stack)
;   Each push decrements cpu_sp, each pop increments
; ============================================================
%define STACK_MAX 512
cpu_stack:  times STACK_MAX dq 0
cpu_sp:     dq STACK_MAX        ; current stack pointer (index)
max_depth:  dq 0               ; peak stack depth

; ============================================================
; MEMORY — 4096 word-addressable slots
; ============================================================
%define MEM_MAX 4096
cpu_mem:    times MEM_MAX dq 0

; ============================================================
; WRITE LOG — records every memory write address (up to 2048)
; ============================================================
%define WLOG_MAX 2048
write_log:  times WLOG_MAX dq 0
write_cnt:  dq 0

; ============================================================
; JUMP LOG — records (from, to) pairs (up to 2048)
; ============================================================
%define JLOG_MAX 2048
jump_from:  times JLOG_MAX dq 0
jump_to_:   times JLOG_MAX dq 0   ; underscore avoids 'to' keyword
jump_cnt:   dq 0
back_cnt:   dq 0               ; backward jumps (loops)

; ============================================================
; INSTRUCTION COUNTERS
; ============================================================
step_cnt:   dq 0
push_cnt:   dq 0
pop_cnt:    dq 0
int_cnt:    dq 0
call_cnt:   dq 0
ret_cnt:    dq 0
nop_cnt:    dq 0
cpuid_cnt:  dq 0
rdtsc_cnt:  dq 0

section .text

; ============================================================
; init_sandbox()
; Resets ALL CPU state. Call before each program scan.
; ============================================================
init_sandbox:
    ; Zero registers
    lea rax, [rel cpu_regs]
    xorps xmm0, xmm0
    movdqu [rax],      xmm0   ; regs 0,1
    movdqu [rax+16],   xmm0   ; regs 2,3
    movdqu [rax+32],   xmm0   ; regs 4,5

    ; Zero flags
    lea rax, [rel cpu_zf]
    mov qword [rax],    0
    mov qword [rax+8],  0
    mov qword [rax+16], 0
    mov qword [rax+24], 0

    ; Reset stack pointer
    mov rax, STACK_MAX
    mov [rel cpu_sp], rax
    mov qword [rel max_depth], 0

    ; Zero counters
    mov qword [rel write_cnt],  0
    mov qword [rel jump_cnt],   0
    mov qword [rel back_cnt],   0
    mov qword [rel step_cnt],   0
    mov qword [rel push_cnt],   0
    mov qword [rel pop_cnt],    0
    mov qword [rel int_cnt],    0
    mov qword [rel call_cnt],   0
    mov qword [rel ret_cnt],    0
    mov qword [rel nop_cnt],    0
    mov qword [rel cpuid_cnt],  0
    mov qword [rel rdtsc_cnt],  0

    xor eax, eax
    ret

; ============================================================
; set_reg(reg_id, value)
;   RCX = reg_id (0–5)
;   RDX = value  (16-bit, will be masked)
; ============================================================
set_reg:
    cmp rcx, 5
    ja  .bad
    and rdx, 0FFFFh         ; enforce 16-bit range
    lea rax, [rel cpu_regs]
    mov [rax + rcx*8], rdx  ; store at index * 8 bytes
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; ============================================================
; get_reg(reg_id) -> value
;   RCX = reg_id (0–5)
;   Returns: RAX = register value
; ============================================================
get_reg:
    cmp rcx, 5
    ja  .bad
    lea rax, [rel cpu_regs]
    mov rax, [rax + rcx*8]
    and rax, 0FFFFh
    ret
.bad:
    xor eax, eax
    ret

; ============================================================
; update_flags_add(a, b)
;   RCX = operand a,  RDX = operand b  (16-bit values)
;   Computes a + b, updates ZF, CF, SF, OF
; ============================================================
update_flags_add:
    and rcx, 0FFFFh
    and rdx, 0FFFFh
    mov rax, rcx
    add rax, rdx            ; full 64-bit add

    ; ZF — result (masked to 16 bits) is zero?
    mov r8, rax
    and r8, 0FFFFh
    setz cl
    movzx rcx, cl
    mov [rel cpu_zf], rcx

    ; CF — did carry out of bit 15 occur?
    xor rcx, rcx
    cmp rax, 0FFFFh
    setg cl                 ; > 0xFFFF means carry
    mov [rel cpu_cf], rcx

    ; SF — bit 15 of result
    mov r8, rax
    and r8, 0FFFFh
    shr r8, 15
    mov [rel cpu_sf], r8

    ; OF — signed overflow: both inputs positive → negative result
    ;      or both negative → positive — simplified check for 16-bit
    mov r8, rax
    and r8, 0FFFFh
    mov rcx, 0
    cmp r8, 07FFFh
    setg cl                 ; result > 32767 = signed overflow
    mov [rel cpu_of], rcx

    xor eax, eax
    ret

; ============================================================
; update_flags_sub(a, b)
;   RCX = a,  RDX = b   Computes a - b, updates flags
; ============================================================
update_flags_sub:
    and rcx, 0FFFFh
    and rdx, 0FFFFh
    mov rax, rcx
    sub rax, rdx            ; signed subtract

    ; ZF
    mov r8, rax
    and r8, 0FFFFh
    setz cl
    movzx rcx, cl
    mov [rel cpu_zf], rcx

    ; CF (borrow occurred = result negative)
    xor rcx, rcx
    test rax, rax
    sets cl
    mov [rel cpu_cf], rcx

    ; SF (bit 15 of result)
    mov r8, rax
    and r8, 0FFFFh
    shr r8, 15
    mov [rel cpu_sf], r8

    ; OF
    mov r8, rax
    and r8, 0FFFFh
    mov rcx, 0
    cmp r8, 08000h
    setae cl                ; result >= 0x8000 in 16-bit = OF for sub
    mov [rel cpu_of], rcx

    xor eax, eax
    ret

; ============================================================
; update_flags_and(result)
;   RCX = result  CF=0, OF=0 always for AND/OR/XOR
; ============================================================
update_flags_and:
    and rcx, 0FFFFh

    ; ZF
    xor rax, rax
    test rcx, rcx
    setz al
    mov [rel cpu_zf], rax

    ; SF
    mov rax, rcx
    shr rax, 15
    mov [rel cpu_sf], rax

    ; CF = OF = 0 (always for logic ops)
    mov qword [rel cpu_cf], 0
    mov qword [rel cpu_of], 0

    xor eax, eax
    ret

; ============================================================
; get_flag(flag_id) -> 0 or 1
;   RCX = 0=ZF, 1=CF, 2=SF, 3=OF
; ============================================================
get_flag:
    lea rax, [rel cpu_zf]
    cmp rcx, 3
    ja  .bad
    mov rax, [rax + rcx*8]
    ret
.bad:
    xor eax, eax
    ret

; ============================================================
; asm_push(value) -> 0 = ok, -1 = overflow
;   RCX = value to push
; ============================================================
asm_push:
    ; Increment push counter
    inc qword [rel push_cnt]

    ; Check for stack overflow
    mov rax, [rel cpu_sp]
    test rax, rax
    jz  .overflow

    ; Decrement sp, store value
    dec rax
    mov [rel cpu_sp], rax
    and rcx, 0FFFFh
    lea rdx, [rel cpu_stack]
    mov [rdx + rax*8], rcx

    ; Update max depth
    mov rax, STACK_MAX
    sub rax, [rel cpu_sp]       ; depth = STACK_MAX - sp
    mov rdx, [rel max_depth]
    cmp rax, rdx
    jle .done
    mov [rel max_depth], rax
.done:
    xor eax, eax
    ret
.overflow:
    mov eax, -1
    ret

; ============================================================
; asm_pop() -> value, or -1 on underflow
; ============================================================
asm_pop:
    ; Increment pop counter
    inc qword [rel pop_cnt]

    ; Check underflow
    mov rax, [rel cpu_sp]
    cmp rax, STACK_MAX
    jge .underflow

    ; Load value, increment sp
    lea rdx, [rel cpu_stack]
    mov rax, [rdx + rax*8]
    and rax, 0FFFFh
    inc qword [rel cpu_sp]
    ret
.underflow:
    mov eax, -1
    ret

; ============================================================
; get_stack_depth() -> current depth
; ============================================================
get_stack_depth:
    mov rax, STACK_MAX
    sub rax, [rel cpu_sp]
    ret

; ============================================================
; get_max_stack_depth() -> peak depth seen
; ============================================================
get_max_stack_depth:
    mov rax, [rel max_depth]
    ret

; get_push_count
get_push_count:
    mov rax, [rel push_cnt]
    ret

; get_pop_count
get_pop_count:
    mov rax, [rel pop_cnt]
    ret

; ============================================================
; mem_write(addr, value)
;   RCX = address (0..MEM_MAX-1),  RDX = value
; ============================================================
mem_write:
    ; Bounds check
    cmp rcx, MEM_MAX
    jae .bad
    and rdx, 0FFFFh

    ; Write to memory
    lea rax, [rel cpu_mem]
    mov [rax + rcx*8], rdx

    ; Log the write address
    mov rax, [rel write_cnt]
    cmp rax, WLOG_MAX
    jae .done           ; log full, still count

    lea rdx, [rel write_log]
    mov r8, [rel write_cnt]
    mov [rdx + r8*8], rcx   ; log the address

.done:
    inc qword [rel write_cnt]
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; ============================================================
; mem_read(addr) -> value
;   RCX = address
; ============================================================
mem_read:
    cmp rcx, MEM_MAX
    jae .bad
    lea rax, [rel cpu_mem]
    mov rax, [rax + rcx*8]
    and rax, 0FFFFh
    ret
.bad:
    xor eax, eax
    ret

; get_write_count
get_write_count:
    mov rax, [rel write_cnt]
    ret

; ============================================================
; record_jump(from_ip, to_ip)
;   RCX = from instruction index,  RDX = to instruction index
; ============================================================
record_jump:
    ; Log if space available
    mov rax, [rel jump_cnt]
    cmp rax, JLOG_MAX
    jae .count_only

    lea r8, [rel jump_from]
    mov [r8 + rax*8], rcx

    lea r8, [rel jump_to_]
    mov [r8 + rax*8], rdx

.count_only:
    inc qword [rel jump_cnt]

    ; Backward jump? (to_ip < from_ip)
    cmp rdx, rcx
    jl  .backward
    xor eax, eax
    ret
.backward:
    inc qword [rel back_cnt]
    xor eax, eax
    ret

; get_jump_count
get_jump_count:
    mov rax, [rel jump_cnt]
    ret

; get_backward_jump_count
get_backward_jump_count:
    mov rax, [rel back_cnt]
    ret

; ============================================================
; Simple counter recorders — each increments one counter
; ============================================================
record_int:
    inc qword [rel int_cnt]
    xor eax, eax
    ret

record_call:
    inc qword [rel call_cnt]
    xor eax, eax
    ret

record_ret:
    inc qword [rel ret_cnt]
    xor eax, eax
    ret

record_nop:
    inc qword [rel nop_cnt]
    xor eax, eax
    ret

record_cpuid:
    inc qword [rel cpuid_cnt]
    xor eax, eax
    ret

record_rdtsc:
    inc qword [rel rdtsc_cnt]
    xor eax, eax
    ret

increment_step:
    inc qword [rel step_cnt]
    xor eax, eax
    ret

; ============================================================
; Getters for all counters
; ============================================================
get_int_count:
    mov rax, [rel int_cnt]
    ret

get_call_count:
    mov rax, [rel call_cnt]
    ret

get_ret_count:
    mov rax, [rel ret_cnt]
    ret

get_nop_count:
    mov rax, [rel nop_cnt]
    ret

get_cpuid_count:
    mov rax, [rel cpuid_cnt]
    ret

get_rdtsc_count:
    mov rax, [rel rdtsc_cnt]
    ret

get_step_count:
    mov rax, [rel step_cnt]
    ret
