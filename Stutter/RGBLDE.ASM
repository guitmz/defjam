get_opsize      proc    near                            ;in: esi->buffer
        pop     eax
        _int3z
        push    071h
        _int3z
        push    05E71515Fh
        _int3z
        push    05F710851h
        _int3z
        push    063516157h
        _int3z
        push    061725B61h
        _int3z
        push    051037251h
        _int3z
        push    061510351h
        _int3z
        push    05FA1AF52h
        _int3z
        push    076015364h
        _int3z
        push    0535F5F5Fh
        _int3z
        push    07A065874h
        _int3z
        push    054775976h
        _int3z
        push    002710172h
        _int3z
        push    054520691h
        _int3z
        push    081024201h
        _int3z
        push    0410411C1h
        _int3z
        push    0A2185802h
        _int3z
        push    012540211h
        _int3z
        push    002210131h
        _int3z
        push    0F1615201h
        _int3z
        push    02162A818h
        _int3z
        push    006A11104h
        _int3z
        push    02405C10Ah
        _int3z
        push    05C62F161h
        _int3z
        push    0111f0461h
        _int3z
        push    011F1A144h
        _int3z
        push    052050f0fh
        _int3z
        push    041A11154h
        _int3z
        push    00141A111h
        _int3z
        push    0540141A1h
        _int3z
        push    011540141h
        _int3z
        push    0A1115402h
        _int3z
        push    0A1115402h
        _int3z
        push    0A1115441h
        _int3z
        push    001A11154h
        _int3z
        push    002A11154h
        _int3z
        push    eax
        _int3z
        pushad
        _int3z
        push    15
        _int3z
        pop     ecx
        _int3z
        push    8
        _int3z
        pop     edx
        _int3z
        lea     edi, dword ptr [esp + 24h]
        _int3z

get_opcode      label   near
        push    edi
        _int3z
        mov     bl, byte ptr [esi]                      ;get opcode
        _int3z

find_opcode     label   near
        mov     al, byte ptr [edi]                      ;get table entry
        _int3z
        inc     edi
        _int3z
        aam     10h                                     ;separate group count and magic bits
        _int3z
        sub     bl, al
        _int3z
        _jnb    find_opcode
        pop     edi
        _int3z
        lods    byte ptr [esi]                          ;get opcode again, increment esi now
        _int3z
        xchg    ah, al
        _int3z
        cmp     al, 4                                   ;prefix
        _int3z
        _jne    valid_op
        cmp     ah, 0fh                                 ;extend
        _int3z
        _jne    check_over
        add     edi, 5bh                                ;select other table
        _int3z

check_over      label   near
        sub     ah, 65h
        _int3z
        cmp     ah, 2
        _int3z
        _jnbe   loop_prefix
        or      dh, ah                                  ;1=operand size, 2=address size
        _int3z

loop_prefix     label   near
        dec     ecx
        _int3   get_opcode

check_abs       label   near
        cmp     bl, 40h
        _int3z
        _jnb    add_memoff
        cmp     ah, 6                                   ;special case if ebp
        _int3z
        _jne    add_memoff
        mov     bl, 80h                                 ;force use of immediate
        _int3z

add_memoff      label   near
        shr     bl, 6                                   ;get extra byte count
        _int3z
        _jpe    check_gotop                             ;skip if no immediate or register mode
        add     al, bl
        _int3z

check_mova      label   near
        sub     ah, 0a0h
        _int3z
        cmp     ah, 3                                   ;handle a0-a3
        _int3z
        _jnbe   check_gotop
        xor     dl, 8
        _int3z
        _je     return_len
        shr     dh, 1                                   ;replace operand size with address size
        _int3z

check_gotop     label   near
        test    dx, 108h                                ;check for 16-bit overrides
        _int3z
        _jne    return_len
        inc     eax
        _int3z
        inc     eax
        _int3z

return_len      label   near
        sub     al, cl
        _int3z
        add     al, 16
        _int3z
        movzx   eax, al
        _int3z
        mov     dword ptr [esp + 1ch], eax              ;eax in pushad
        _int3z
        popad
        _int3z
        ret     90h                                     ;out: eax->instruction length
        _int3z

valid_op        label   near
        xor     dl, al                                  ;remember if override affects size
        _int3z
        cmp     al, 9
        _int3z
        _jbe    check_modrm
        and     al, 7
        _int3z

check_modrm     label   near
        cmp     al, 5
        _int3z
        _jb     check_mova
        mov     ebx, dword ptr [esi]
        _int3z
        dec     ecx
        _int3z
        cmp     al, 8
        _int3z
        sbb     al, 4
        _int3z
        test    al, 4
        _int3z
        _je     check_gotad
        sub     al, 3
        _int3z
        test    bl, 30h                                 ;handle f6-f7 xx001xxx like xx000xxx
        _int3z
        _je     fix_opaff
        xor     al, al
        _int3z

fix_opaff       label   near
        cmp     al, 2                                   ;handle f6-f7
        _int3z
        _je     check_gotad
        mov     dl, 8                                   ;f6 size is not affected by override
        _int3z

check_gotad     label   near
        mov     ah, 7
        _int3z
        and     ah, bl
        _int3z
        test    dh, 2                                   ;handle 16-bit absolute addressing
        _int3z
        _jne    check_abs
        and     bl, 0c0h
        _int3z
        _jns    check_sib
        _jpe    check_gotop                             ;handle register mode
        inc     eax
        _int3z
        inc     eax
        _int3z

check_sib       label   near
        cmp     ah, 4                                   ;handle SIB mode
        _int3z
        _jne    check_esp
        inc     eax
        _int3z
        mov     ah, 7
        _int3z
        and     ah, bh
        _int3z

check_esp       label   near
        test    bl, bl
        _int3z
        _jne    add_memoff
        cmp     ah, 5                                   ;handle SIB absolute addressing
        _int3z
        _jne    add_memoff
        add     al, 4
        _int3   add_memoff
get_opsize      endp
