;============================================================
; BENIGN SAMPLE 3 – Bubble Sort on 5 array elements
; COAL Concept: Arrays, Memory, Nested loops, CMP/JL
;============================================================

.MODEL SMALL
.STACK 100h

.DATA
    arr DB 5, 3, 8, 1, 9   ; unsorted array
    n   EQU 5

.CODE
MAIN PROC
    MOV  AX, @DATA
    MOV  DS, AX

    MOV  CX, n-1           ; outer: n-1 passes

OUTER_LOOP:
    PUSH CX
    MOV  SI, 0             ; index = 0

INNER_LOOP:
    MOV  AL, arr[SI]       ; AL = arr[i]
    MOV  BL, arr[SI+1]     ; BL = arr[i+1]
    CMP  AL, BL
    JLE  SKIP_SWAP         ; if AL <= BL, no swap
    ; swap arr[i] and arr[i+1]
    MOV  arr[SI],   BL
    MOV  arr[SI+1], AL

SKIP_SWAP:
    INC  SI
    CMP  SI, n-1
    JL   INNER_LOOP

    POP  CX
    LOOP OUTER_LOOP        ; CX-- and jump if CX != 0

    MOV  AH, 4Ch
    INT  21h
MAIN ENDP
END MAIN
