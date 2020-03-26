/*++

Copyright (c)  2007 Ajay Harikumar. All rights reserved
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

#define EFI_FIRMWARE_VENDOR         L"INTEL"
#define EFI_FIRMWARE_MAJOR_REVISION 14
#define EFI_FIRMWARE_MINOR_REVISION 62
#define EFI_FIRMWARE_REVISION ((EFI_FIRMWARE_MAJOR_REVISION <<16) | (EFI_FIRMWARE_MINOR_REVISION))

#include "efibind.h"
#include "efidef.h"
#include "pe.h"

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

#define EFI_MAX_MEMORY_DESCRIPTORS 64

#define LOADED_IMAGE_SIGNATURE     EFI_SIGNATURE_32('l','d','r','i')


// PE32+ Subsystem type for EFI images

#if !defined(IMAGE_SUBSYSTEM_EFI_APPLICATION)
#define IMAGE_SUBSYSTEM_EFI_APPLICATION             10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER     11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER          12
#endif

// PE32+ Machine type for EFI images

#if !defined(EFI_IMAGE_MACHINE_IA32)
#define EFI_IMAGE_MACHINE_IA32      0x014c
#endif

#if !defined(EFI_IMAGE_MACHINE_IA64)
#define EFI_IMAGE_MACHINE_IA64      0x0200
#endif

#if !defined(EFI_IMAGE_MACHINE_EBC)
#define EFI_IMAGE_MACHINE_EBC       0x0EBC
#endif

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


// Image Entry prototype

typedef 
EFI_STATUS
(EFIAPI *EFI_IMAGE_ENTRY_POINT) (
    IN EFI_HANDLE                   ImageHandle
    );
/*
typedef 
EFI_STATUS
(EFIAPI *EFI_IMAGE_LOAD) (
    IN BOOLEAN                      BootPolicy,
    IN EFI_HANDLE                   ParentImageHandle,
    IN EFI_DEVICE_PATH              *FilePath,
    IN VOID                         *SourceBuffer   OPTIONAL,
    IN UINTN                        SourceSize,
    OUT EFI_HANDLE                  *ImageHandle
    );

typedef 
EFI_STATUS
(EFIAPI *EFI_IMAGE_START) (
    IN EFI_HANDLE                   ImageHandle,
    OUT UINTN                       *ExitDataSize,
    OUT CHAR16                      **ExitData  OPTIONAL
    );

typedef
EFI_STATUS
(EFIAPI *EFI_EXIT) (
    IN EFI_HANDLE                   ImageHandle,
    IN EFI_STATUS                   ExitStatus,
    IN UINTN                        ExitDataSize,
    IN CHAR16                       *ExitData OPTIONAL
    );

typedef 
EFI_STATUS
(EFIAPI *EFI_IMAGE_UNLOAD) (
    IN EFI_HANDLE                   ImageHandle
    );

*/
typedef struct _EFI_TABLE_HEADER {
    UINT64                      Signature;
    UINT32                      Revision;
    UINT32                      HeaderSize;
    UINT32                      CRC32;
    UINT32                      Reserved;
} EFI_TABLE_HEADER;


// Image handle
#define LOADED_IMAGE_PROTOCOL      \
    { 0x5B1B31A1, 0x9562, 0x11d2, 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B }

#define EFI_IMAGE_INFORMATION_REVISION      0x1000
typedef struct {
    UINT32                          Revision;

    // Location of where image was loaded
    VOID                            *ImageBase;
    UINT64                          ImageSize;
    EFI_MEMORY_TYPE                 ImageCodeType;
    EFI_MEMORY_TYPE                 ImageDataType;

} EFI_LOADED_IMAGE;


UINT8 *Cursor;

typedef struct {
    UINTN                       Signature;
    CHAR16                      *Name;          // Displayable name
    UINTN                       Type;

    BOOLEAN                     Started;        // If entrypoint has been called
    VOID                        *StartImageContext;
    // 
    EFI_PHYSICAL_ADDRESS        ImageBasePage;  // Location in memory
    UINTN                       NoPages;        // Number of pages 
    CHAR8                       *ImageBase;     // As a char pointer
    CHAR8                       *ImageEof;      // End of memory image

    // relocate info
    CHAR8                       *ImageAdjust;   // Bias for reloc calculations
    UINTN                       StackAddress;
    CHAR8                       *FixupData;     //  Original fixup data
} EFILDR_LOADED_IMAGE;

EFILDR_LOADED_IMAGE EfiCoreImage;

typedef struct {
    UINT32       CheckSum;
    UINT32       Offset;
    UINT32       Length;
    UINT8        FileName[52];
} EFILDR_IMAGE;

typedef struct {          
    UINT32       Signature;     
    UINT32       HeaderCheckSum;
    UINT32       FileLength;
    UINT32       NumberOfImages;
} EFILDR_HEADER;

typedef struct {          
    UINT32       BaseAddress;
    UINT32       Foo;
    UINT32       Length;
    UINT32       Bar;
    UINT32       Type;
} BIOS_MEMORY_MAP_ENTRY;

typedef struct {          
    UINT32                MemoryMapSize;
    BIOS_MEMORY_MAP_ENTRY MemoryMapEntry[1];
} BIOS_MEMORY_MAP;

EFI_STATUS
EfiAddMemoryDescriptor(
    UINTN                 *NoDesc,
    EFI_MEMORY_DESCRIPTOR *Desc,
    EFI_MEMORY_TYPE       Type,
    EFI_PHYSICAL_ADDRESS  BaseAddress,
    UINTN                 NoPages,
    UINT64                Attribute
    );

void EnablePaging();
void EnableProtection();
UINTN
FindSpace(
    UINTN                       NoPages,
    IN UINT32                   *NumberOfMemoryMapEntries,
    IN EFI_MEMORY_DESCRIPTOR    *EfiMemoryDescriptor
    );

UINT64
EFILDRLShiftU64 (
  IN UINT64   Operand,
  IN UINTN    Count
  );

VOID
EFILDRZeroMem (
    IN VOID     *Buffer,
    IN UINTN    Size
    );

VOID
EFILDRCopyMem (
    IN VOID     *Dest,
    IN VOID     *Src,
    IN UINTN    len
    );

UINTN
EFILDRstrcmpa (
    IN CHAR8    *s1,
    IN CHAR8    *s2
    );

//
//
//

#define LOADED_IMAGE_SIGNATURE     EFI_SIGNATURE_32('l','d','r','i')

/*
#define EFI_PAGE_SIZE   4096
#define EFI_PAGE_MASK   0xFFF
#define EFI_PAGE_SHIFT  12

#define EFI_SIZE_TO_PAGES(a)  \
    ( ((a) >> EFI_PAGE_SHIFT) + ((a) & EFI_PAGE_MASK ? 1 : 0) )
*/

typedef struct {
    UINTN                       Signature;
    CHAR16                      *Name;          // Displayable name
    UINTN                       Type;

    BOOLEAN                     Started;        // If entrypoint has been called
    VOID                        *StartImageContext;

    EFI_IMAGE_ENTRY_POINT       EntryPoint;     // The image's entry point
    EFI_LOADED_IMAGE            Info;           // loaded image protocol

    // 
    EFI_PHYSICAL_ADDRESS        ImageBasePage;  // Location in memory
    UINTN                       NoPages;        // Number of pages 
    CHAR8                       *ImageBase;     // As a char pointer
    CHAR8                       *ImageEof;      // End of memory image

    // relocate info
    CHAR8                       *ImageAdjust;   // Bias for reloc calculations
} LOADED_IMAGE;


EFI_STATUS
EFIAPI
GetInfo (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
  OUT     UINT32  *DstSize,
  OUT     UINT32  *ScratchSize
  );

EFI_STATUS
LoadPeImage (
    IN VOID                     *FHand,
    IN LOADED_IMAGE             *Image,
    IN UINT32                   *NumberOfMemoryMapEntries,
    IN EFI_MEMORY_DESCRIPTOR    *EfiMemoryDescriptor
    );

static
EFI_STATUS
LoadPeRelocate (
    IN LOADED_IMAGE             *Image,
    IN IMAGE_DATA_DIRECTORY     *RelocDir,
    IN UINTN                     Adjust
    );

static
EFI_STATUS
ImageRead (
    IN VOID                 *FHand,
    IN UINTN                Offset,
    IN OUT UINTN            ReadSize,
    OUT VOID                *Buffer
    );

static
VOID *
ImageAddress (
    IN LOADED_IMAGE     *Image,
    IN UINTN            Address
    );

EFI_STATUS
SetImageType (
    IN OUT LOADED_IMAGE             *Image,
    IN UINTN                        ImageType
    );

EFI_STATUS
CheckImageMachineType (
    IN UINTN            MachineType
    );


EFI_STATUS
EfiAddMemoryDescriptor(
    UINTN                 *NoDesc,
    EFI_MEMORY_DESCRIPTOR *Desc,
    EFI_MEMORY_TYPE       Type,
    EFI_PHYSICAL_ADDRESS  BaseAddress,
    UINTN                 NoPages,
    UINT64                Attribute
    )

{
    UINTN i;
    UINTN Temp;
    UINTN Index;

    if (NoPages == 0) {
        return 0;
    }

    //
    // See if the new memory descriptor needs to be carved out of an existing memory descriptor
    //

    Index = *NoDesc;
    for(i=0;i<Index;i++) {

        if (Desc[i].Type == EfiConventionalMemory) {

            Temp = ((UINT32)(BaseAddress - Desc[i].PhysicalStart) / EFI_PAGE_SIZE) + NoPages;

            if (Desc[i].PhysicalStart < BaseAddress && Desc[i].NumberOfPages >= Temp) {
                if (Desc[i].NumberOfPages > Temp) {
                    Desc[*NoDesc].Type          = EfiConventionalMemory;
                    Desc[*NoDesc].PhysicalStart = BaseAddress + (NoPages * EFI_PAGE_SIZE);
                    Desc[*NoDesc].NumberOfPages = Desc[i].NumberOfPages - Temp;
                    Desc[*NoDesc].VirtualStart  = 0;
                    Desc[*NoDesc].Attribute     = Desc[i].Attribute;
                    *NoDesc = *NoDesc + 1;
                }
                Desc[i].NumberOfPages = Temp - NoPages;
            }

            if (Desc[i].PhysicalStart == BaseAddress && Desc[i].NumberOfPages==NoPages) {
                Desc[i].Type      = Type;
                Desc[i].Attribute = Attribute;
                return 0;
            }

            if (Desc[i].PhysicalStart == BaseAddress && Desc[i].NumberOfPages>NoPages) {
                Desc[i].NumberOfPages -= NoPages;
                Desc[i].PhysicalStart += NoPages * EFI_PAGE_SIZE;
            }
        }
    }

    //
    // Add the new memory descriptor
    //

    Desc[*NoDesc].Type          = Type;
    Desc[*NoDesc].PhysicalStart = BaseAddress;
    Desc[*NoDesc].NumberOfPages = NoPages;
    Desc[*NoDesc].VirtualStart  = 0;
    Desc[*NoDesc].Attribute     = Attribute;
    *NoDesc = *NoDesc + 1;

    return(0);
}

UINTN
FindSpace(
    UINTN                       NoPages,
    IN UINT32                   *NumberOfMemoryMapEntries,
    IN EFI_MEMORY_DESCRIPTOR    *EfiMemoryDescriptor
    )
{
    EFI_PHYSICAL_ADDRESS        MaxPhysicalStart;
    UINT64                      MaxNoPages=0;
    UINTN                       Index;

    MaxPhysicalStart = 0;
    for (Index = 0;Index < *NumberOfMemoryMapEntries; Index++) {
        if (EfiMemoryDescriptor[Index].Type == EfiConventionalMemory && 
            EfiMemoryDescriptor[Index].NumberOfPages >= NoPages) {
            if (EfiMemoryDescriptor[Index].PhysicalStart > MaxPhysicalStart) {
		      if (EfiMemoryDescriptor[Index].PhysicalStart + EFILDRLShiftU64(EfiMemoryDescriptor[Index].NumberOfPages, EFI_PAGE_SHIFT) <= 0x100000000) {
                    MaxPhysicalStart = EfiMemoryDescriptor[Index].PhysicalStart;
                    MaxNoPages       = EfiMemoryDescriptor[Index].NumberOfPages;
		      }
		      else if (EfiMemoryDescriptor[Index].PhysicalStart + (NoPages << EFI_PAGE_SHIFT) <= 0x100000000) {
                    MaxPhysicalStart = 0x100000000 - (NoPages << EFI_PAGE_SHIFT);
                    MaxNoPages       = NoPages;
		      }
            }
        }
    }
    if (!MaxPhysicalStart)
        return 0;
    return (UINTN)(MaxPhysicalStart + EFILDRLShiftU64(MaxNoPages - NoPages, EFI_PAGE_SHIFT));
}


UINT64
EFILDRLShiftU64 (
  IN UINT64   Operand,
  IN UINTN    Count
  )
// Left shift 64bit by 32bit and get a 64bit result
{
  UINT64      Result;

  _asm {
    mov     eax, dword ptr Operand[0]
    mov     edx, dword ptr Operand[4]
    mov     ecx, Count
    and     ecx, 63

    shld    edx, eax, cl
    shl     eax, cl

    cmp     ecx, 32
    jc      short ls10

    mov     edx, eax
    xor     eax, eax

ls10:
    mov     dword ptr Result[0], eax
    mov     dword ptr Result[4], edx
  }

  return Result;
}

VOID
EFILDRZeroMem (
    IN VOID     *Buffer,
    IN UINTN    Size
    )
{
    UINT8       *pt;

    pt = Buffer;
    while (Size--) {
        *(pt++) = 0;
    }
}

VOID
EFILDRCopyMem (
    IN VOID     *Dest,
    IN VOID     *Src,
    IN UINTN    len
    )
{
    CHAR8    *d, *s;

    d = Dest;
    s = Src;
    while (len--) {
        *(d++) = *(s++);
    }
}

UINTN
EFILDRstrcmpa (
    IN CHAR8    *s1,
    IN CHAR8    *s2
    )
// compare strings
{
    while (*s1) {
        if (*s1 != *s2) {
            break;
        }

        s1 += 1;
        s2 += 1;
    }

    return *s1 - *s2;
}

VOID ClearScreen()

{
    UINT32 i;

    Cursor =  (UINT8 *)(0x000b8000 + 160);
    for(i=0;i<80*49;i++) {
        *Cursor = ' ';
        Cursor += 2;
    }
    Cursor =  (UINT8 *)(0x000b8000 + 160);
}

VOID ClearHalfScreen()

{
    UINT32 i;

    Cursor =  (UINT8 *)(0x000b8000 + 160*16);
    for(i=0;i<80*29;i++) {
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
void Drawline()
{
	PrintString("--------------------------------------------------------------------------------");
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
/*
#define     BITBUFSIZ         16
#define     WNDBIT            13
#define     WNDSIZ            (1U << WNDBIT)
#define     MAXMATCH          256
#define     THRESHOLD         3
#define     CODE_BIT          16
#define     UINT8_MAX         0xff
#define     BAD_TABLE         -1

//
// C: Char&Len Set; P: Position Set; T: exTra Set
//

#define     NC                (0xff + MAXMATCH + 2 - THRESHOLD)
#define     CBIT              9
#define     NP                (WNDBIT + 1)
#define     NT                (CODE_BIT + 3)
#define     PBIT              4
#define     TBIT              5
#if NT > NP
  #define     NPT               NT
#else
  #define     NPT               NP
#endif


typedef struct {
  UINT8       *mSrcBase;      //Starting address of compressed data
  UINT8       *mDstBase;      //Starting address of decompressed data

  UINT16      mBytesRemain;
  UINT16      mBitCount;
  UINT16      mBitBuf;
  UINT16      mSubBitBuf;
  UINT16      mBufSiz;
  UINT16      mBlockSize;
  UINT32      mDataIdx;
  UINT32      mCompSize;
  UINT32      mOrigSize;
  UINT32      mOutBuf;
  UINT32      mInBuf;

  UINT16      mBadTableFlag;

  UINT8       mBuffer[WNDSIZ];
  UINT16      mLeft[2 * NC - 1];
  UINT16      mRight[2 * NC - 1];
  UINT32      mBuf;
  UINT8       mCLen[NC];
  UINT8       mPTLen[NPT];
  UINT16      mCTable[4096];
  UINT16      mPTTable[256];
} SCRATCH_DATA;
*/
EFI_STATUS
EFIAPI
GetInfo (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
  OUT     UINT32  *DstSize,
  OUT     UINT32  *ScratchSize
  )
/*++

Routine Description:

  The implementation of EFI_DECOMPRESS_PROTOCOL.GetInfo().

Arguments:

  This        - The protocol instance pointer
  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  DstSize     - The size of destination buffer.
  ScratchSize - The size of scratch buffer.

Returns:

  EFI_SUCCESS           - The size of destination buffer and the size of scratch buffer are successull retrieved.
  EFI_INVALID_PARAMETER - The source data is corrupted

--*/
{
  UINT8 *Src;

  *ScratchSize = 51;  // size of ScratchData

  Src = Source;
  if (SrcSize < 8) {
    return EFI_INVALID_PARAMETER;
  }
  
  *DstSize = Src[4] + (Src[5] << 8) + (Src[6] << 16) + (Src[7] << 24);
  return EFI_SUCCESS;
}

typedef struct {
  UINT16  LimitLow;
  UINT16  BaseLow;
  UINT8   BaseMid;
  UINT8   Attribute;
  UINT8   LimitHi;
  UINT8   BaseHi;
} GDT_ENTRY;

typedef struct {
  UINT16  Link;
  UINT16  LinkReserved;
  UINT32  ESP0;
  UINT16  SS0;
  UINT16  SS0Reserved;
  UINT32  ESP1;
  UINT16  SS1;
  UINT16  SS1Reserved;
  UINT32  ESP2;
  UINT16  SS2;
  UINT16  SS2Reserved;
  UINT32  CR3;
  UINT32  EIP;
  UINT32  EFlag;
  UINT32  EAX;
  UINT32  ECX;
  UINT32  EDX;
  UINT32  EBX;
  UINT32  ESP;
  UINT32  EBP;
  UINT32  ESI;
  UINT32  EDI;
  UINT16  ES;
  UINT16  ESReserved;
  UINT16  CS;
  UINT16  CSReserved;
  UINT16  SS;
  UINT16  SSReserved;
  UINT16  DS;
  UINT16  DSReserved;
  UINT16  FS;
  UINT16  FSReserved;
  UINT16  GS;
  UINT16  GSReserved;
  UINT16  LDTSegSelector;
  UINT16  LDTSegSelectorRes;
  UINT16  TrapRegister;
  UINT16  IoMapBase;
} EFI_TASK_STATE;

#define TASK_STATE_SEGMENT_LIMIT  sizeof (EFI_TASK_STATE)

VOID
CreateGdtTssEntry (
  IN GDT_ENTRY                  *GdtEntry,
  IN UINT32                     TssAddress
  )
/*++

Routine Description:

  GC_TODO: Add function description

Arguments:

  GdtEntry    - GC_TODO: add argument description
  TssAddress  - GC_TODO: add argument description

Returns:

  GC_TODO: add return values

--*/
{
  GdtEntry->LimitLow  = TASK_STATE_SEGMENT_LIMIT;
  GdtEntry->BaseLow   = (UINT16) TssAddress;
  GdtEntry->BaseMid   = (UINT8) (TssAddress >> 16);
  GdtEntry->Attribute = 0x89;
  GdtEntry->LimitHi   = 0;
  GdtEntry->BaseHi    = (UINT8) (TssAddress >> 24);
}

/*
BOOLEAN
Int86 (
    IN  UINT8               BiosInt,
    IN  IA32_RegisterSet_t  *Regs
    )
// returns carry flag
{
    UINTN               Status;
    UINT16              *S16;
    BOOLEAN             SavedInterruptState;

    Regs->x.Flags.Reserved1 = 1;
    Regs->x.Flags.Reserved2 = 0;
    Regs->x.Flags.Reserved3 = 0;
    Regs->x.Flags.Reserved4 = 0;
    Regs->x.Flags.IOPL      = 3;
    Regs->x.Flags.NT        = 0;
    Regs->x.Flags.IF        = 1;
    Regs->x.Flags.TF        = 0;

    S16 = (UINT16 *) (IntThunk->Stack + LOW_STACK_SIZE);

    //
    // Copy regs to low memory stack
    //

    S16 -=  sizeof(IA32_RegisterSet_t) / sizeof(UINT16);
    CopyMem (S16, Regs, sizeof(IA32_RegisterSet_t));

    //
    // Provide low stack esp
    //

    IntThunk->LowStack = ((UINT32) S16) - ((UINT32) IntThunk);

    SavedInterruptState = PlSetInterruptState(FALSE);   // insure interrupts are turned off
    PlSetupInterruptControllerMask(INT_CTRLR_BIOSMODE); // Save/Setup interrupt controller mask
    
    //
    // Call the real mode int thunk code
    //

    _asm {
        movzx   ecx, BiosInt
        mov     edx, 0
        mov     eax, IntThunk
        call    eax
        mov     Status, eax

    }

    PlSetupInterruptControllerMask(INT_CTRLR_EFIMODE); // Save/Setup interrupt controller mask
    PlSetInterruptState(SavedInterruptState);          // Restore interrupt flag

    PlGenerateIrq (0);

    //
    // Return the resulting registers
    //

    CopyMem (Regs, S16, sizeof(IA32_RegisterSet_t));

    return Regs->x.Flags.CF ? TRUE : FALSE;
}
*/
#endif
