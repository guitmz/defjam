.386
.model  flat

extern  WriteFile:proc
extern  ExitProcess:proc

.data
instaddr        db      0ah dup (?)

.code
code_begin      label   near
        mov     esi, offset code_begin
        xor     eax, eax

walk_code       label   near
        add     esi, eax                        ;move to next instruction
        push    0
        push    esp
        push    size instaddr
        mov     edi, offset instaddr
        push    edi
        push    -11                             ;STD_OUTPUT_HANDLE
        call    hex2asc                         ;convert offset to ASCII
        mov     ax, 0a0dh
        stos    word ptr [edi]
        call    WriteFile                       ;print to screen

        call    get_opsize                      ;get length
        jnb     walk_code                       ;stop when hit invalid instruction

        push    0
        call    ExitProcess

hex2asc         proc    near
        mov     edx, esi
        call    dd2asc

dd2asc          proc    near
        call    dw2asc

dw2asc          proc    near
        shld    eax, edx, 8
        shl     edx, 8
        aam     10h
        call    db2asc

db2asc          proc    near
        xchg    ah, al
        cmp     al, 0ah
        sbb     al, 69h
        das
        stos    byte ptr [edi]
        ret
db2asc          endp
dw2asc          endp
dd2asc          endp
hex2asc         endp

include rgblde.asm
        db      0fh, 0bh                        ;ud2 - invalid instruction
end             code_begin
