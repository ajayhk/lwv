/*++

Copyright (c)  1999 - 2002 Intel Corporation. All rights reserved
This software and associated documentation (if any) is furnished
under a license and may only be used or copied in accordance
with the terms of the license. Except as permitted by such
license, no part of this software or documentation may be
reproduced, stored in a retrieval system, or transmitted in any
form or by any means without the express written consent of
Intel Corporation.

Module Name:

    efi.h

Abstract:

    Public EFI header files



Revision History

--*/

//
// Build flags on input
//  EFI32
//  EFI_DEBUG               - Enable debugging code
//  EFI_NT_EMULATOR         - Building for running under NT
//
#pragma warning ( disable : 4100 )  // Suppress warnings unused variables


#ifndef _EFI_INCLUDE_
#define _EFI_INCLUDE_
/*++

Copyright (c)  1999 - 2003 Intel Corporation. All rights reserved
This software and associated documentation (if any) is furnished
under a license and may only be used or copied in accordance
with the terms of the license. Except as permitted by such
license, no part of this software or documentation may be
reproduced, stored in a retrieval system, or transmitted in any
form or by any means without the express written consent of
Intel Corporation.

Module Name:

    efefind.h

Abstract:

    EFI to compile bindings




Revision History

--*/

#pragma pack()


//
// Basic int types of various widths
//

#if (__STDC_VERSION__ < 199901L )

    // No ANSI C 1999/2000 stdint.h integer width declarations 

    #if _MSC_EXTENSIONS

        // Use Microsoft C compiler integer width declarations 

        typedef unsigned __int64    uint64_t;
        typedef __int64             int64_t;
        typedef unsigned __int32    uint32_t;
        typedef __int32             int32_t;
        typedef unsigned short      uint16_t;
        typedef short               int16_t;
        typedef unsigned char       uint8_t;
        typedef char                int8_t;
    #else             
        #ifdef UNIX_LP64

            // Use LP64 programming model from C_FLAGS for integer width declarations 

            typedef unsigned long       uint64_t;
            typedef long                int64_t;
            typedef unsigned int        uint32_t;
            typedef int                 int32_t;
            typedef unsigned short      uint16_t;
            typedef short               int16_t;
            typedef unsigned char       uint8_t;
            typedef char                int8_t;
        #else

            // Assume P64 programming model from C_FLAGS for integer width declarations 

            typedef unsigned long long  uint64_t;
            typedef long long           int64_t;
            typedef unsigned int        uint32_t;
            typedef int                 int32_t;
            typedef unsigned short      uint16_t;
            typedef short               int16_t;
            typedef unsigned char       uint8_t;
            typedef char                int8_t;
        #endif
    #endif
#endif

//
// Basic EFI types of various widths
//

typedef uint64_t   UINT64;
typedef int64_t    INT64;

#ifndef _BASETSD_H_
    typedef uint32_t   UINT32;
    typedef int32_t    INT32;
#endif

typedef uint16_t   UINT16;
typedef int16_t    INT16;
typedef uint8_t    UINT8;
typedef int8_t     INT8;


#undef VOID
#define VOID    void


typedef int32_t    INTN;
typedef uint32_t   UINTN;


#pragma warning ( disable : 4214 )

typedef UINT16          CHAR16;
typedef UINT8           CHAR8;
typedef UINT8           BOOLEAN;

#ifndef TRUE
    #define TRUE    ((BOOLEAN) 1)
    #define FALSE   ((BOOLEAN) 0)
#endif

#ifndef NULL
    #define NULL    ((VOID *) 0)
#endif

typedef UINTN           EFI_STATUS;
typedef UINT64          EFI_LBA;
typedef UINTN           EFI_TPL;
typedef VOID            *EFI_HANDLE;
typedef VOID            *EFI_EVENT;


//
// Prototype argument decoration for EFI parameters to indicate
// their direction
//
// IN - argument is passed into the function
// OUT - argument (pointer) is returned from the function
// OPTIONAL - argument is optional
//

#ifndef IN
    #define IN
    #define OUT
    #define OPTIONAL
#endif


//
// A GUID
//

typedef struct {          
    UINT32  Data1;
    UINT16  Data2;
    UINT16  Data3;
    UINT8   Data4[8]; 
} EFI_GUID;


//
// Time
//

typedef struct {          
    UINT16      Year;       // 1998 - 20XX
    UINT8       Month;      // 1 - 12
    UINT8       Day;        // 1 - 31
    UINT8       Hour;       // 0 - 23
    UINT8       Minute;     // 0 - 59
    UINT8       Second;     // 0 - 59
    UINT8       Pad1;
    UINT32      Nanosecond; // 0 - 999,999,999
    INT16       TimeZone;   // -1440 to 1440 or 2047
    UINT8       Daylight;
    UINT8       Pad2;
} EFI_TIME;

// Bit definitions for EFI_TIME.Daylight
#define EFI_TIME_ADJUST_DAYLIGHT    0x01
#define EFI_TIME_IN_DAYLIGHT        0x02

// Value definition for EFI_TIME.TimeZone
#define EFI_UNSPECIFIED_TIMEZONE    0x07FF



//
// Networking
//

typedef struct {
    UINT8                   Addr[4];
} EFI_IPv4_ADDRESS;

typedef struct {
    UINT8                   Addr[16];
} EFI_IPv6_ADDRESS;

typedef struct {
    UINT8                   Addr[32];
} EFI_MAC_ADDRESS;

//
// Memory
//

typedef UINT64          EFI_PHYSICAL_ADDRESS;
typedef UINT64          EFI_VIRTUAL_ADDRESS;

typedef enum {
    AllocateAnyPages,
    AllocateMaxAddress,
    AllocateAddress,
    MaxAllocateType
} EFI_ALLOCATE_TYPE;

//Preseve the attr on any range supplied.
//ConventialMemory must have WB,SR,SW when supplied.
//When allocating from ConventialMemory always make it WB,SR,SW
//When returning to ConventialMemory always make it WB,SR,SW
//When getting the memory map, or on RT for runtime types


typedef enum {
    EfiReservedMemoryType,
    EfiLoaderCode,
    EfiLoaderData,
    EfiBootServicesCode,
    EfiBootServicesData,
    EfiRuntimeServicesCode,
    EfiRuntimeServicesData,
    EfiConventionalMemory,
    EfiUnusableMemory,
    EfiACPIReclaimMemory,
    EfiACPIMemoryNVS,
    EfiMemoryMappedIO,
    EfiMemoryMappedIOPortSpace,
    EfiPalCode,
    EfiMaxMemoryType
} EFI_MEMORY_TYPE;

// possible caching types for the memory range
#define EFI_MEMORY_UC           0x0000000000000001
#define EFI_MEMORY_WC           0x0000000000000002
#define EFI_MEMORY_WT           0x0000000000000004
#define EFI_MEMORY_WB           0x0000000000000008
#define EFI_MEMORY_UCE          0x0000000000000010  

// physical memory protection on range 
#define EFI_MEMORY_WP           0x0000000000001000
#define EFI_MEMORY_RP           0x0000000000002000
#define EFI_MEMORY_XP           0x0000000000004000

// range requires a runtime mapping
#define EFI_MEMORY_RUNTIME      0x8000000000000000

#define EFI_MEMORY_DESCRIPTOR_VERSION  1
typedef struct {
    UINT32                          Type;           // Field size is 32 bits followed by 32 bit pad
    EFI_PHYSICAL_ADDRESS            PhysicalStart;  // Field size is 64 bits
    EFI_VIRTUAL_ADDRESS             VirtualStart;   // Field size is 64 bits
    UINT64                          NumberOfPages;  // Field size is 64 bits
    UINT64                          Attribute;      // Field size is 64 bits
} EFI_MEMORY_DESCRIPTOR;

//
// International Language
//

typedef UINT8   ISO_639_2;
#define ISO_639_2_ENTRY_SIZE    3

//
//
//

#define EFI_PAGE_SIZE   4096
#define EFI_PAGE_MASK   0xFFF
#define EFI_PAGE_SHIFT  12

#define EFI_SIZE_TO_PAGES(a)  \
    ( ((a) >> EFI_PAGE_SHIFT) + (((a) & EFI_PAGE_MASK) ? 1 : 0) )

//
// Convert Flat Address to Seg Offset
//
#define _FP_SEG(fp) ((UINT16) (((UINT32)(fp)) >> 4) & 0xf000)
#define _FP_OFF(fp) (((UINT16)(fp)) & 0xffff) 

//
// Defines for Int86() functions
//

#define CARRY_FLAG  0x01

struct _FlagsReg {
    UINT16 CF:1;
    UINT16 Reserved1:1;
    UINT16 PF:1;
    UINT16 Reserved2:1;
    UINT16 AF:1;
    UINT16 Reserved3:1;
    UINT16 ZF:1;
    UINT16 SF:1;
    UINT16 TF:1;
    UINT16 IF:1;
    UINT16 DF:1;
    UINT16 OF:1;
    UINT16 IOPL:2;
    UINT16 NT:1;
    UINT16 Reserved4:1;
};

/* word registers */
struct __WordRegs {
    UINT16           AX;
    UINT16           BX;
    UINT16           CX;
    UINT16           DX;
    UINT16           SI;
    UINT16           DI;
    struct _FlagsReg Flags;
};

struct _WordRegs {
    UINT16           AX;
    UINT16           BX;
    UINT16           CX;
    UINT16           DX;
    UINT16           SI;
    UINT16           DI;
    struct _FlagsReg Flags;
    UINT16           ES;
    UINT16           CS;
    UINT16           SS;
    UINT16           DS;

    UINT16           BP;
};

/* byte registers */

struct _ByteRegs {
    UINT8 AL, AH;
    UINT8 BL, BH;
    UINT8 CL, CH;
    UINT8 DL, DH;
};

/* general purpose registers union -
 *  overlays the corresponding word and byte registers.
 */

union _Regs {
    struct _WordRegs x;
    struct _ByteRegs h;
};

struct _SREGS {
    UINT16 es;
    UINT16 cs;
    UINT16 ss;
    UINT16 ds;
};

/* segment registers */

typedef union _Regs IA32_RegisterSet_t;   
#pragma warning ( default : 4214 )



#ifdef EFI_NT_EMULATOR
    #define POST_CODE(_Data)
#else    
    #ifdef EFI_DEBUG
#define POST_CODE(_Data)    __asm mov eax,(_Data) __asm out 0x80,al
    #else
        #define POST_CODE(_Data)
    #endif  
#endif

#define EFIERR(a)           (0x80000000 | a)
#define EFI_ERROR_MASK      0x80000000
#define EFIERR_OEM(a)       (0xc0000000 | a)      


#define BAD_POINTER         0xFBFBFBFB
#define MAX_ADDRESS         0xFFFFFFFF

#define BREAKPOINT()        __asm { int 3 }

//
// Pointers must be aligned to these address to function
//

#define MIN_ALIGNMENT_SIZE  4

#define ALIGN_VARIABLE(Value ,Adjustment) \
            (UINTN)Adjustment = 0; \
            if((UINTN)Value % MIN_ALIGNMENT_SIZE) \
                (UINTN)Adjustment = MIN_ALIGNMENT_SIZE - ((UINTN)Value % MIN_ALIGNMENT_SIZE); \
            Value = (UINTN)Value + (UINTN)Adjustment


//
// Define macros to build data structure signatures from characters.
//

#define EFI_SIGNATURE_16(A,B)             ((A) | (B<<8))
#define EFI_SIGNATURE_32(A,B,C,D)         (EFI_SIGNATURE_16(A,B)     | (EFI_SIGNATURE_16(C,D)     << 16))
#define EFI_SIGNATURE_64(A,B,C,D,E,F,G,H) (EFI_SIGNATURE_32(A,B,C,D) | ((UINT64)(EFI_SIGNATURE_32(E,F,G,H)) << 32))

//
// EFIAPI - prototype calling convention for EFI function pointers
// BOOTSERVICE - prototype for implementation of a boot service interface
// RUNTIMESERVICE - prototype for implementation of a runtime service interface
// RUNTIMEFUNCTION - prototype for implementation of a runtime function that is not a service
// RUNTIME_CODE - pragma macro for declaring runtime code    
//

#ifndef EFIAPI                  // Forces EFI calling conventions reguardless of compiler options 
    #if _MSC_EXTENSIONS
        #define EFIAPI __cdecl  // Force C calling convention for Microsoft C compiler 
    #else
        #define EFIAPI          // Substitute expresion to force C calling convention 
    #endif
#endif

#define BOOTSERVICE
//#define RUNTIMESERVICE(proto,a)    alloc_text("rtcode",a); proto a
//#define RUNTIMEFUNCTION(proto,a)   alloc_text("rtcode",a); proto a
#define RUNTIMESERVICE
#define RUNTIMEFUNCTION


#define RUNTIME_CODE(a)         alloc_text("rtcode", a)
#define BEGIN_RUNTIME_DATA()    data_seg("rtdata")
#define END_RUNTIME_DATA()      data_seg()

#define VOLATILE    volatile

#define MEMORY_FENCE()    

#ifdef EFI_NO_INTERFACE_DECL
  #define EFI_FORWARD_DECLARATION(x)
  #define EFI_INTERFACE_DECL(x)
#else
  #define EFI_FORWARD_DECLARATION(x) typedef struct _##x x
  #define EFI_INTERFACE_DECL(x) typedef struct x
#endif

#ifdef EFI_NT_EMULATOR

//
// To help ensure proper coding of integrated drivers, they are
// compiled as DLLs.  In NT they require a dll init entry pointer.
// The macro puts a stub entry point into the DLL so it will load.
//

#define EFI_DRIVER_ENTRY_POINT(InitFunction)            \
    EFI_STATUS                                          \
    InitFunction (                                      \
      EFI_HANDLE  ImageHandle,                          \
      EFI_SYSTEM_TABLE  *SystemTable                    \
      );                                                \
                                                        \
    UINTN                                               \
    __stdcall                                           \
    _DllMainCRTStartup (                                \
        UINTN    Inst,                                  \
        UINTN    reason_for_call,                       \
        VOID    *rserved                                \
        )                                               \
    {                                                   \
        return 1;                                       \
    }                                                   \
                                                        \
    int                                                 \
    __declspec( dllexport )                             \
    __cdecl                                             \
    InitializeDriver (                                  \
        void *ImageHandle,                              \
        void *SystemTable                               \
        )                                               \
    {                                                   \
        return InitFunction(ImageHandle, SystemTable);  \
    }


    #define LOAD_INTERNAL_DRIVER(_if, type, name, entry)      \
        (_if)->LoadInternal(type, name, NULL)             

#else // EFI_NT_EMULATOR 

//
// When build similiar to FW, then link everything together as
// one big module.
//

    #define EFI_DRIVER_ENTRY_POINT(InitFunction)

    #define LOAD_INTERNAL_DRIVER(_if, type, name, entry)    \
            (_if)->LoadInternal(type, name, entry)

#endif // EFI_FW_NT 

//
// Some compilers don't support the forward reference construct:
//  typedef struct XXXXX
//
// The following macro provide a workaround for such cases.
//
#ifdef NO_INTERFACE_DECL
#define INTERFACE_DECL(x)
#else
#define INTERFACE_DECL(x) typedef struct x
#endif

#if _MSC_EXTENSIONS
#pragma warning ( disable : 4731 )  // Suppress warnings about modification of EBP
#endif


#define EFI_FIRMWARE_VENDOR         L"INTEL"
#define EFI_FIRMWARE_MAJOR_REVISION 14
#define EFI_FIRMWARE_MINOR_REVISION 62
#define EFI_FIRMWARE_REVISION ((EFI_FIRMWARE_MAJOR_REVISION <<16) | (EFI_FIRMWARE_MINOR_REVISION))


#define EFI_STRINGIZE(a)                #a 
#define EFI_PROTOCOL_DEFINITION(a)      EFI_STRINGIZE(Protocol/a/a.h) 

#define EFI_GUID_DEFINITION(a) EFI_STRINGIZE(Guid/a/a##.h) 
#define EFI_GUID_STRING(guidpointer, shortstring, longstring)

#define INT15_E820_AddressRangeMemory   1
#define INT15_E820_AddressRangeReserved 2
#define INT15_E820_AddressRangeACPI     3
#define INT15_E820_AddressRangeNVS      4

#define EFILDR_LOAD_ADDRESS        (EFILDR_BASE_SEGMENT << 4)
#define EFILDR_HEADER_ADDRESS      (EFILDR_LOAD_ADDRESS+0x2000)

#define EFI_FIRMWARE_BASE_ADDRESS  0x00200000
#define EFI_MAX_STACK_SIZE         0x00020000

#define EFI_DECOMPRESSED_BUFFER_ADDRESS 0x00600000

#define EFIWARN(a)                            (a)
#define EFI_ERROR(a)              (((INTN) a) < 0)


#define EFI_SUCCESS                             0
#define EFI_LOAD_ERROR                  EFIERR(1)
#define EFI_INVALID_PARAMETER           EFIERR(2)
#define EFI_UNSUPPORTED                 EFIERR(3)
#define EFI_BAD_BUFFER_SIZE             EFIERR(4)
#define EFI_BUFFER_TOO_SMALL            EFIERR(5)
#define EFI_NOT_READY                   EFIERR(6)
#define EFI_DEVICE_ERROR                EFIERR(7)
#define EFI_WRITE_PROTECTED             EFIERR(8)
#define EFI_OUT_OF_RESOURCES            EFIERR(9)
#define EFI_VOLUME_CORRUPTED            EFIERR(10)
#define EFI_VOLUME_FULL                 EFIERR(11)
#define EFI_NO_MEDIA                    EFIERR(12)
#define EFI_MEDIA_CHANGED               EFIERR(13)
#define EFI_NOT_FOUND                   EFIERR(14)
#define EFI_ACCESS_DENIED               EFIERR(15)
#define EFI_NO_RESPONSE                 EFIERR(16)
#define EFI_NO_MAPPING                  EFIERR(17)
#define EFI_TIMEOUT                     EFIERR(18)
#define EFI_NOT_STARTED                 EFIERR(19)
#define EFI_ALREADY_STARTED             EFIERR(20)
#define EFI_ABORTED                     EFIERR(21)
#define EFI_ICMP_ERROR                  EFIERR(22)
#define EFI_TFTP_ERROR                  EFIERR(23)
#define EFI_PROTOCOL_ERROR              EFIERR(24)

#define EFI_WARN_UNKOWN_GLYPH           EFIWARN(1)
#define EFI_WARN_DELETE_FAILURE         EFIWARN(2)
#define EFI_WARN_WRITE_FAILURE          EFIWARN(3)
#define EFI_WARN_BUFFER_TOO_SMALL       EFIWARN(4)

UINT8 *Cursor;


void ClearScreen()

{
    UINT32 i;

    Cursor =  (UINT8 *)(0x000b8000 + 160);
    for(i=0;i<80*49;i++) {
        *Cursor = ' ';
        Cursor += 2;
    }
    Cursor =  (UINT8 *)(0x000b8000 + 160);
}


VOID PrintValue(UINT32 Value)

{
    UINT32 i;
    UINT8  ch;

    for(i=0;i<8;i++) {
        ch = (UINT8)((Value >> ((7-i)*4)) & 0x0f) + '0';
        if (ch>'9') {
            ch = ch - '0' -10 + 'A';
        }
        *Cursor = ch;
        Cursor += 2;
    }
}

VOID PrintString(UINT8 *String)

{
    UINT32 i;

    for(i=0;String[i]!=0;i++) {
        if (String[i] == '\n') {
            Cursor = (UINT8 *)(0xb8000 + (((((UINT32)Cursor-0xb8000) + 160) / 160) * 160));
        } else {
            *Cursor = String[i];
            Cursor += 2;
        }
    }
}

VOID Delay (UINT32 Time)

{
    UINT32 i;
    UINT32 j;
	__asm _emit 0x0F
	__asm _emit 0x31
	__asm mov i, edx

	j=i+10;
	for(;;)
	{
		if (j<=i) {
			break;
		} else {
			__asm _emit 0x0F
			__asm _emit 0x31
			__asm mov i, edx
		}
	}

}
#endif
