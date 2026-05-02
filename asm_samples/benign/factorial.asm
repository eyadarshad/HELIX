;============================================================
; BENIGN SAMPLE 2 – Factorial of N using CALL/RET
; COAL Concept: Procedures, Stack, CALL/RET, MUL
;============================================================

.MODEL SMALL
.STACK 100h

.DATA
    N      DW 5           ; compute 5! = 120
    result DW 0

.CODE
;------------------------------------------------------------
; FACTORIAL Subroutine
;   Input : CX = N
;   Output: AX = N!
;------------------------------------------------------------
FACTORIAL PROC
    CMP  CX, 1
    JLE  BASE_CASE
    PUSH CX              ; save N on stack
    DEC  CX              ; N-1
    CALL FACTORIAL       ; recursive call
    POP  CX              ; restore N
    MUL  CX              ; AX = AX * CX
    RET
BASE_CASE:
    MOV  AX, 1
    RET
FACTORIAL ENDP

MAIN PROC
    MOV  AX, @DATA
    MOV  DS, AX

    MOV  CX, N
    CALL FACTORIAL
    MOV  result, AX      ; result = 120

    MOV  AH, 4Ch
    INT  21h
MAIN ENDP
END MAIN
