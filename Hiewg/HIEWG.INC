tebProcessEnvironmentBlock      equ     30h

pebImageBaseAddress             equ     8
pebLdr                          equ     0ch

ldrInLoadOrderModuleList        equ     0ch

mlDllBase                       equ     18h

e_lfanew                        equ     3ch

MAX_PATH                        equ     260

FILE_ATTRIBUTE_DIRECTORY        equ     00000010h

CREATE_ALWAYS                   equ     2
OPEN_EXISTING                   equ     3

FILE_SHARE_READ                 equ     1
FILE_SHARE_WRITE                equ     2

GENERIC_WRITE                   equ     40000000h
GENERIC_READ                    equ     80000000h

IMAGE_FILE_EXECUTABLE_IMAGE     equ     0002h
IMAGE_FILE_32BIT_MACHINE        equ     0100h
IMAGE_FILE_SYSTEM               equ     1000h
IMAGE_FILE_DLL                  equ     2000h
IMAGE_FILE_UP_SYSTEM_ONLY       equ     4000h

IMAGE_SUBSYSTEM_WINDOWS_GUI     equ     2
IMAGE_SUBSYSTEM_WINDOWS_CUI     equ     3

IMAGE_SCN_MEM_EXECUTE           equ     20000000h
IMAGE_SCN_MEM_WRITE             equ     80000000h

HEM_FILENAME_MAXLEN             equ     260

HEM_SHORTNAME_SIZE              equ     16
HEM_NAME_SIZE                   equ     60
HEM_ABOUT_SIZE                  equ     48

HEM_SDK_VERSION_MAJOR           equ     0
HEM_SDK_VERSION_MINOR           equ     46
HEM_FLAG_MODEMASK               equ     7
HEM_FLAG_PE                     equ     200h

HIEWGATE_ID_GETDATA             equ     1
HIEWGATE_ID_FILEOPENFORWRITE    equ     5
HIEWGATE_ID_FILEREAD            equ     6
HIEWGATE_ID_FILEWRITE           equ     7

align 1
krncrcstk       struct
        kSfcIsFileProtected     dd      ?       ;appended from other location
        kMultiByteToWideChar    dd      ?
        kLoadLibraryA           dd      ?
krncrcstk       ends
krncrc_count    equ     (size krncrcstk - 4) shr 2

dllcrcstk       struct
        dWriteFile              dd      ?
        dSetFileAttributesA     dd      ?
        dMoveFileA              dd      ?
        dGlobalFree             dd      ?
        dGlobalAlloc            dd      ?
        dGetTempFileNameA       dd      ?
        dGetFileAttributesA     dd      ?
        dDeleteFileA            dd      ?
        dCreateFileA            dd      ?
        dCloseHandle            dd      ?
dllcrcstk       ends
dllcrc_count    equ     size dllcrcstk shr 2

HIEWINFO_TAG            struct
        hicbSize        dd      ?
        hisdkVerMajor   db      ?
        hisdkVerMinor   db      ?
        hihiewVerMajor  db      ?
        hihiewVerMinor  db      ?
        hiHiewGate      dd      ?
        hihemHandle     dd      ?
        hihemFile       db      HEM_FILENAME_MAXLEN dup (?)
        hihemInfo       dd      ?
        hireserved      dd      4 dup (?)
HIEWINFO_TAG            ends

HEMINFO_TAG struct
        hecbSize        dd      ?
        hesizeOfInt     dw      ?
        hereserved1     dw      ?
        heisdkVerMajor  db      ?
        heisdkVerMinor  db      ?
        hehemVerMajor   db      ?
        hehemVerMinor   db      ?
        hehemFlag       dd      ?
        heeserved2      dd      ?
        heEntryPoint    dd      ?
HEMINFO_TAG             ends

HIEWGATE_NULL           struct
        ncbSize         dd      ?
        ncallId         dd      ?
        nhemHandle      dd      ?
HIEWGATE_NULL           ends

HIEWGATE_GETDATA        struct
        gdcbSize        dd      ?
        gdcallId        dd      ?
        gdhemHandle     dd      ?
        gdfilename      db      HEM_FILENAME_MAXLEN dup (?)
        gdfilelength    dq      ?
        gdoffsetCurrent dq      ?
        gdoffsetMark1   dq      ?
        gdoffsetMark2   dq      ?
        gdsizeMark      dq      ?
HIEWGATE_GETDATA        ends

HIEWGATE_FILEOPENFORWRITE       struct
        fofwcbSize              dd      ?
        fofwcallId              dd      ?
        fofwhemHandle           dd      ?
HIEWGATE_FILEOPENFORWRITE       ends

HIEWGATE_FILEREAD       struct
        frcbSize        dd      ?
        frcallId        dd      ?
        frhemHandle     dd      ?
        froffset        dq      ?
        frbuffer        dd      ?
        frbytes         dd      ?
HIEWGATE_FILEREAD       ends

coffhdr                 struct
        pemachine       dw      ?               ;04
        pesectcount     dw      ?               ;06
        petimedate      dd      ?               ;08
        pesymbrva       dd      ?               ;0C
        pesymbcount     dd      ?               ;10
        peopthdrsize    dw      ?               ;14
        peflags         dw      ?               ;16
coffhdr                 ends

pedir                   struct
        dirrva          dd      ?
        dirsize         dd      ?
pedir                   ends

pehdr                   struct
        pesig           dd      ?               ;00
        pecoff          coffhdr <?>
        pemagic         dw      ?               ;18
        pemajorlink     db      ?               ;1A
        peminorlink     db      ?               ;1B
        pecodesize      dd      ?               ;1C
        peidatasize     dd      ?               ;20
        peudatasize     dd      ?               ;24
        peentrypoint    dd      ?               ;28
        pecodebase      dd      ?               ;2C
        pedatabase      dd      ?               ;30
        peimagebase     dd      ?               ;34
        pesectalign     dd      ?               ;38
        pefilealign     dd      ?               ;3C
        pemajoros       dw      ?               ;40
        peminoros       dw      ?               ;42
        pemajorimage    dw      ?               ;44
        peminorimage    dw      ?               ;46
        pemajorsubsys   dw      ?               ;48
        peminorsubsys   dw      ?               ;4A
        pereserved      dd      ?               ;4C
        peimagesize     dd      ?               ;50
        pehdrsize       dd      ?               ;54
        pechksum        dd      ?               ;58
        pesubsys        dw      ?               ;5C
        pedllflags      dw      ?               ;5E
        pestackmax      dd      ?               ;60
        pestacksize     dd      ?               ;64
        peheapmax       dd      ?               ;68
        peheapsize      dd      ?               ;6C
        peldrflags      dd      ?               ;70
        pervacount      dd      ?               ;74
        peexport        pedir   <?>             ;78
        peimport        pedir   <?>             ;80
        persrc          pedir   <?>             ;88
        peexcpt         pedir   <?>             ;90
        pesecurity      pedir   <?>             ;98
        pereloc         pedir   <?>             ;A0
        pedebug         pedir   <?>             ;A8
        pearch          pedir   <?>             ;B0
        peglobal        pedir   <?>             ;B8
        petls           pedir   <?>             ;C0
        peconfig        pedir   <?>             ;C8
        pebound         pedir   <?>             ;D0
        peiat           pedir   <?>             ;D8
        pedelay         pedir   <?>             ;E0
        pecom           pedir   <?>             ;E8
        persrv          pedir   <?>             ;F0
pehdr           ends

peexp           struct
        expflags        dd      ?               ;00
        expdatetime     dd      ?               ;04
        expmajorver     dw      ?               ;08
        expminorver     dw      ?               ;0A
        expdllrva       dd      ?               ;0C
        expordbase      dd      ?               ;10
        expadrcount     dd      ?               ;14
        expnamecount    dd      ?               ;18
        expadrrva       dd      ?               ;1C
        expnamerva      dd      ?               ;20
        expordrva       dd      ?               ;24
peexp           ends

mzhdr           struct
        mzsig           dw      ?               ;00
        mzpagemod       dw      ?               ;02
        mzpagediv       dw      ?               ;04
        mzrelocs        dw      ?               ;06
        mzhdrsize       dw      ?               ;08
        mzminalloc      dw      ?               ;0A
        mzmaxalloc      dw      ?               ;0C
        mzss            dw      ?               ;0E
        mzsp            dw      ?               ;10
        mzchksum        dw      ?               ;12
        mzip            dw      ?               ;14
        mzcs            dw      ?               ;16
        mzreloff        dw      ?               ;18
        mzfiller        db      22h dup (?)     ;1A
        mzlfanew        dd      ?               ;3C
mzhdr           ends

pesect          struct
        sectname        db      8 dup (?)
        sectvirtsize    dd      ?
        sectvirtaddr    dd      ?
        sectrawsize     dd      ?
        sectrawaddr     dd      ?
        sectreladdr     dd      ?
        sectlineaddr    dd      ?
        sectrelcount    dw      ?
        sectlinecount   dw      ?
        sectflags       dd      ?
pesect          ends
align
