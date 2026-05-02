;============================================================
; BENIGN SAMPLE 4 – Fibonacci sequence (first 8 terms)
; COAL Concept: Register rotation, MOV, ADD, LOOP, memory writes
;============================================================

.MODEL SMALL
.STACK 100h

.DATA
    fib DB 8 DUP(0)        ; store 8 Fibonacci numbers

.CODE
MAIN PROC
    MOV  AX, @DATA
    MOV  DS, AX

    MOV  AX, 0             ; F(0)
    MOV  BX, 1             ; F(1)
    MOV  SI, 0             ; array index
    MOV  CX, 8             ; loop 8 times

FIB_LOOP:
    MOV  fib[SI], AL       ; store current term
    INC  SI
    MOV  DX, BX            ; DX = BX (temp)
    ADD  BX, AX            ; BX = BX + AX (next term)
    MOV  AX, DX            ; AX = old BX
    LOOP FIB_LOOP

    MOV  AH, 4Ch
    INT  21h
MAIN ENDP
END MAIN
