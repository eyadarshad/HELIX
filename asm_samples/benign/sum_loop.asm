;============================================================
; BENIGN SAMPLE 1 – Sum of 1 to 10
; COAL Concept: Loops, Registers, Flags, Arithmetic
; Assemble with: MASM or EMU8086
;============================================================

.MODEL SMALL
.STACK 100h

.DATA
    result DW 0
    msg    DB 'Sum computed$'

.CODE
MAIN PROC
    MOV  AX, @DATA
    MOV  DS, AX

    MOV  CX, 10          ; loop counter
    MOV  AX, 0           ; accumulator

SUM_LOOP:
    ADD  AX, CX          ; AX = AX + CX
    DEC  CX              ; CX--
    JNZ  SUM_LOOP        ; repeat while CX != 0

    MOV  result, AX      ; store result (55)

    ; Print message via INT 21h
    LEA  DX, msg
    MOV  AH, 09h
    INT  21h

    ; Exit
    MOV  AH, 4Ch
    INT  21h
MAIN ENDP
END MAIN
