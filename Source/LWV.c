/*++

Copyright (c)  2007 Ajay Harikumar. All rights reserved
This software and associated documentation (if any) is furnished
under a license and may only be used or copied in accordance
with the terms of the license. Except as permitted by such
license, no part of this software or documentation may be
reproduced, stored in a retrieval system, or transmitted in any
form or by any means without the express written consent of
Ajay Harikumar


Module Name:

    LWV.c
    
Abstract:



Revision History

--*/

#include "efi.h"
#include "vmx.h"
#include "pe.h"
#include "EfiLdrHandoff.h"
#pragma warning ( disable : 4057 )  // Suppress warnings for print
#pragma warning ( disable : 4101 )  // Suppress warnings unreferenced variables

EFI_MEMORY_DESCRIPTOR EfiMemoryDescriptor[EFI_MAX_MEMORY_DESCRIPTORS];
UINT32                NumberOfMemoryMapEntries;

__declspec (naked)  
VOID
EfiLoader (
    UINT32    BiosMemoryMapBaseAddress
    )

{
    BIOS_MEMORY_MAP       *BiosMemoryMap;    
    EFILDR_HEADER         *EFILDRHeader;
    EFILDR_IMAGE          *EFILDRImage;
    UINT32                i;
    EFI_MEMORY_DESCRIPTOR EfiMemoryDescriptor[EFI_MAX_MEMORY_DESCRIPTORS];
    UINT32                NumberOfMemoryMapEntries;
    UINT32                BaseAddress;
    UINT32                Length;
    EFI_MEMORY_TYPE       Type;
    UINTN                 Attr;
    UINT32		  Temp32;
    UINT32		  Temp321;
    UINT64		  VMX_BASIC;
    VMCS_Structure        VmcsStructure;  
    UINT32                VMMEntryPoint;	
    UINT32                ScratchSize;
    EFI_LOADED_IMAGE      *EfiLoadedImage;
    LOADED_IMAGE          Image;
    EFI_STATUS            Status;
    UINT32                DestinationSize;
    UINT32                *mTssBaseAddress;
    GDT_ENTRY             *GdtBase;

    // This function is a 'naked' function, meaning the compiler does not set
    // up the call frame.  Furthermore, we must set up the call frame as if the
    // function was called with a 'near' call, even though it was a 'far' call.
    // The compiler thinks it is a 'NEAR' function and expects only EIP on the
    // stack after the parameters.  Since we made a 'FAR' call to this function,
    // the parameters are 8 bytes into the stack rather than 4.  To fix this,
    // we pop the stack once before setting up the call frame, which leaves the
    // parameters 4 bytes into the stack as expected.  Since we'll never return,
    // there's no worry about what was popped off
    
    // set up call frame since this is a 'naked' function
    __asm pop   eax                 // initial pop to make it look like a 'near' call
    __asm push  ebp
    __asm mov   ebp, esp
    __asm sub   esp, __LOCAL_SIZE

    // *(UINT8 *)(0x000b8000+10) = 'A';

    ClearScreen();
    Drawline();
    Drawline();
    PrintString("-----------------                                            -------------------");
    PrintString("-----------------       Welcome to the Light Weight VMM      -------------------");
    PrintString("-----------------                                            -------------------");
    PrintString("-----------------         implemented as part of the         -------------------");
    PrintString("-----------------                                            -------------------");
    PrintString("-----------------       dissertation for the MS program      -------------------");
    PrintString("-----------------                                            -------------------");
    PrintString("-----------------           of BITS Pilani, India            -------------------");
    PrintString("-----------------                                            -------------------");
    PrintString("-----------------               Ajay Harikumar               -------------------");
    PrintString("-----------------                HZ13069 2005                -------------------");
    PrintString("-----------------                                            -------------------");
    Drawline();
    Drawline();
    Drawline();
    Drawline();
    Drawline();
    Drawline();
    Drawline();
    Drawline();
    Delay(1);
    Delay(1);
    Delay(1);
    Delay(1);
    ClearScreen();
    PrintString("--------------------------------------------------------------------------------");
    PrintString("--------------------------------------------------------------------------------");
    PrintString("--------------------------------------------------------------------------------");
    PrintString("-------------------                                            -----------------");
    PrintString("-------------------   This program is the implementation of    -----------------");
    PrintString("-------------------   a light weight VMM that loads just       -----------------");
    PrintString("-------------------   after the BIOS executes. The LWVMM       -----------------");
    PrintString("-------------------   enables and sets up the Virtualization   -----------------");
    PrintString("-------------------   software on the system. Once done, it    -----------------");
    PrintString("-------------------   loads the OS or the application to be    -----------------");
    PrintString("-------------------   profiled. Once done, every time the OS   -----------------");
    PrintString("-------------------   executes a priviledged instruction the   -----------------");
    PrintString("-------------------   VMM gets control and can maintain the    -----------------");
    PrintString("-------------------   number of exits using counters. Once     -----------------");
    PrintString("-------------------   done the VMM will give a stastical       -----------------");
    PrintString("-------------------   count of the number of times a certain   -----------------");
    PrintString("-------------------   instruction was executed. Similarly the  -----------------");
    PrintString("-------------------   VMM can keep track of interrupts, IO     -----------------");
    PrintString("-------------------   instructions, page faults etc.           -----------------");
    PrintString("-------------------                                            -----------------");
    PrintString("--------------------------------------------------------------------------------");
    PrintString("--------------------------------------------------------------------------------");
    PrintString("--------------------------------------------------------------------------------");
    Delay(1);
    Delay(1);
    Delay(1);
    Delay(1);
    ClearScreen();
    PrintString("--------------------------------------------------------------------------------");
    PrintString("--------------------------------------------------------------------------------");
    PrintString("--------------------------------------------------------------------------------");
    PrintString("-------------------                                            -----------------");
    PrintString("-------------------   The LWVMM is implemented as a bootable   -----------------");
    PrintString("-------------------   USB disk and can be plugged into any     -----------------");
    PrintString("-------------------   platform that has Intel processors that  -----------------");
    PrintString("-------------------   support Intel Virtualization Technology  -----------------");
    PrintString("-------------------   The LWVMM Bootable Disk gets control     -----------------");
    PrintString("-------------------   from the BIOS, sets up the VMM and then  -----------------");
    PrintString("-------------------   loads the OS. Since the VMM is still     -----------------");
    PrintString("-------------------   running, it continues to profile the OS. -----------------");
    PrintString("-------------------   During the next boot, the USB key can    -----------------");
    PrintString("-------------------   be removed and the OS booted normally.   -----------------");
    PrintString("-------------------   Thus the LWVMM can profile the OS        -----------------");
    PrintString("-------------------   without any changes done to the OS.      -----------------");
    PrintString("-------------------   This in summary is the work that is done -----------------");
    PrintString("-------------------   as part of this project.                 -----------------");
    PrintString("-------------------   Hope you find this interesting.....      -----------------");
    PrintString("-------------------                                            -----------------");
    PrintString("--------------------------------------------------------------------------------");
    PrintString("--------------------------------------------------------------------------------");
    PrintString("--------------------------------------------------------------------------------");
    Delay(1);
    Delay(1);
    Delay(1);
    Delay(1);
    ClearScreen();
    PrintString("The program is currently in EFI\n");
    PrintString("Once the EFI Memory Map is set up, we will load the image to be profiled\n");
    PrintString("After that the VMM gets control and starts setting itself up\n");
    PrintString("Once the VMM has set itself up, it gives control to the image to be profiled\n\n");
    Delay(1);
    Delay(1);
    ClearScreen();

    //    PrintString("EFI Loader 0.2\n");   
    //    PrintString("&BiosMemoryMapBaseAddress = ");   
    //    PrintValue((UINT32)(&BiosMemoryMapBaseAddress));
    //    PrintString("\n");
    //    PrintString("  BiosMemoryMapBaseAddress = ");   
    //    PrintValue(BiosMemoryMapBaseAddress);
    //    PrintString("\n");
    //    PrintString("  BIOS MEMORY MAP SIze =");
    //    PrintValue(BiosMemoryMap->MemoryMapSize);
    //    PrintString("\n");

    //    PrintString("  EFILDR_LOAD_ADDRESS =");   // value is 0x20000   
    //    PrintValue(EFILDR_LOAD_ADDRESS);
    //    PrintString("\n");

    //    PrintString("  (EFILDR_HEADER_ADDRESS =");  // value is 0x22000
    //    PrintValue(EFILDR_HEADER_ADDRESS);
    //    PrintString("\n");
    //
    // Add all EfiConventionalMemory descriptors to the table.  If there are partial pages, then
    // round the start address up to the next page, and round the length down to a page boundry.
    //

    BiosMemoryMap = (BIOS_MEMORY_MAP *)(BiosMemoryMapBaseAddress);
    
    NumberOfMemoryMapEntries = 0;

    // *(UINT8 *)(0x000b8000+12) = 'B';
    /*
    // This doesnt work in my home PC but works on the office PC. Need to investigate

    for(i=0;i<BiosMemoryMap->MemoryMapSize / sizeof(BIOS_MEMORY_MAP_ENTRY);i++) {

	*(UINT8 *)(0x000b8000+12+i*2) = 'Z';
        switch(BiosMemoryMap->MemoryMapEntry[i].Type) { 
            case (INT15_E820_AddressRangeMemory):
                Type = EfiConventionalMemory;
                Attr = EFI_MEMORY_WB;
                break;
            case (INT15_E820_AddressRangeReserved):
                Type = EfiReservedMemoryType;
                Attr = EFI_MEMORY_UC;
                break;
            case (INT15_E820_AddressRangeACPI):
                Type = EfiACPIReclaimMemory;
                Attr = EFI_MEMORY_WB;
                break;
            case (INT15_E820_AddressRangeNVS):
                Type = EfiACPIMemoryNVS;
                Attr = EFI_MEMORY_UC;
                break;
            default:
                // We should not get here, according to ACPI 2.0 Spec.
                // BIOS behaviour of the Int15h, E820h
                Type = EfiReservedMemoryType;
                Attr = EFI_MEMORY_UC;
                break;
        }
        if (Type == EfiConventionalMemory) {
            BaseAddress = BiosMemoryMap->MemoryMapEntry[i].BaseAddress;
            Length      = BiosMemoryMap->MemoryMapEntry[i].Length;
            if (BaseAddress & EFI_PAGE_MASK) {
                Length      = Length + (BaseAddress & EFI_PAGE_MASK) - EFI_PAGE_SIZE;
                BaseAddress = ((BaseAddress >> EFI_PAGE_SHIFT) + 1) << EFI_PAGE_SHIFT;
            }
        } else {
            BaseAddress = BiosMemoryMap->MemoryMapEntry[i].BaseAddress;
            Length      = BiosMemoryMap->MemoryMapEntry[i].Length + (BaseAddress & EFI_PAGE_MASK);
            BaseAddress = (BaseAddress >> EFI_PAGE_SHIFT) << EFI_PAGE_SHIFT;
            if (Length & EFI_PAGE_MASK) {
                Length = ((Length >> EFI_PAGE_SHIFT) + 1) << EFI_PAGE_SHIFT;
            }
        }
        EfiAddMemoryDescriptor(&NumberOfMemoryMapEntries,
                               EfiMemoryDescriptor,
                               Type,
                               (EFI_PHYSICAL_ADDRESS)BaseAddress,
                               Length>>EFI_PAGE_SHIFT,
                               Attr);
    }
    */
    // *(UINT8 *)(0x000b8000+14) = 'C';
    //
    // Add a memory descriptor for the Real Mode Interrupt Descriptor Table
    //

    EfiAddMemoryDescriptor(&NumberOfMemoryMapEntries,
                           EfiMemoryDescriptor,
                           EfiBootServicesData,
                           (EFI_PHYSICAL_ADDRESS)0x00000000,
                           1,
                           EFI_MEMORY_WB);

    //
    // Add a memory descriptor for the GDT and IDT used by EFI
    //

    EfiAddMemoryDescriptor(&NumberOfMemoryMapEntries,
                           EfiMemoryDescriptor,
                           EfiBootServicesData,
                           (EFI_PHYSICAL_ADDRESS)EFILDR_LOAD_ADDRESS,
                           (EFILDR_HEADER_ADDRESS - EFILDR_LOAD_ADDRESS + EFI_PAGE_SIZE - 1) >> EFI_PAGE_SHIFT,
                           EFI_MEMORY_WB);

    //
    // Start loading the second image which is the OS loader/OS/application to be profiled into memory
    //
    //
    // Get information on where the image is in memory
    //

    EFILDRZeroMem(&Image,sizeof(Image));
    
    EFILDRHeader = (EFILDR_HEADER *)(EFILDR_HEADER_ADDRESS);
    EFILDRImage  = (EFILDR_IMAGE *)(EFILDR_HEADER_ADDRESS + sizeof(EFILDR_HEADER));
    Temp32 = (EFILDR_HEADER_ADDRESS + EFILDRImage->Offset);
    // PrintString("The first Image address is = \n");
    // PrintValue(Temp32);
    // PrintString("\n");
    // PrintString("The first Image length is = \n");
    // PrintValue( EFILDRImage->Length);
    // PrintString("\n");
    EFILDRImage++;

    //
    // Add a memory descriptor for the remaining portion of the EFILDR file
    //

    EfiAddMemoryDescriptor(&NumberOfMemoryMapEntries,
                           EfiMemoryDescriptor,
                           EfiReservedMemoryType,
                           (EFI_PHYSICAL_ADDRESS)EFILDR_HEADER_ADDRESS,
                           (EFILDRHeader->FileLength + EFI_PAGE_SIZE -1) >> EFI_PAGE_SHIFT,
                           EFI_MEMORY_WB);

    // *(UINT8 *)(0x000b8000+16) = 'D';

    //
    // Decompress the image
    //

    Status = GetInfo(
               (VOID *)(EFILDR_HEADER_ADDRESS + EFILDRImage->Offset),
               EFILDRImage->Length,
               &DestinationSize, 
               &ScratchSize
               );
    if (EFI_ERROR (Status)) {
        PrintString("Error: Error getting info on the Second Image\n");
        for(;;);
    }
    
    //
    // Load and relocate the EFI PE/COFF Firmware Image 
    //
    Temp32 = (EFILDR_HEADER_ADDRESS + EFILDRImage->Offset);
    //  PrintString("The second Image address is = \n");
    //  PrintValue(Temp32);
    //  PrintString("\n");
    //  PrintString("The second Image length is = \n");
    //  PrintValue( EFILDRImage->Length);
    //  PrintString("\n");
    Status = LoadPeImage ((VOID *)((EFILDR_HEADER_ADDRESS + EFILDRImage->Offset)), 
                          &Image, 
                          &NumberOfMemoryMapEntries, 
                          EfiMemoryDescriptor);

    if (EFI_ERROR (Status) ) {
        PrintString("Error: Image to be profiled gave a Load Error\n");
        Delay(1);
        Delay(1);
    } else {
        PrintString("Image to be profiled was loaded successfully!! \n");
        Delay(1);
    }

    // ClearScreen();

    // The VM starts here. Since the VM needs a lot of memory to be allocated, start allcating at 160MB and 
    // add a memory descriptor for 16MB region that will be used by the VMM 
    EfiAddMemoryDescriptor(&NumberOfMemoryMapEntries,
                           EfiMemoryDescriptor,
                           EfiBootServicesData,
                           (EFI_PHYSICAL_ADDRESS)0xA000000,
                           4096,
                           EFI_MEMORY_WB);

    //
    // Check support for Virtualization
    // check if CPUID.1:ECX.VMX[bit 5] =1
    // If it is, then VMM is supported on the processor
    //
    PrintString("Checking Virtualization support on this system\n");  
    Delay(1); 
    __asm mov eax, 0x01
    __asm cpuid 
    __asm mov Temp32, ecx

    // PrintString("CPUID ECX return value = ");   
    // PrintValue((UINT32)(Temp32));  // 0000E3BD
    // PrintString("\n");

    if(Temp32 & 0x020) {
	PrintString("Virtualization supported on this system\n");   
        Delay(1); 
    } else {
	PrintString("Error: Virtualization NOT supported\n");   
	// Halt system
	__asm int 0x03
    }

    //PrintString("\nCR4 value = ");   
    //PrintValue((UINT32)(Temp32));  
    //Delay(1);
    //Delay(1);

    //
    // Virtualization works with only Protected mode and Paging enabled. EFI sets up Protected Flat mode
    // but Paging has to be enabled by us
    //
    
    EnableProtection();

    EnablePaging();
    
    //
    // Set up the host entry for the TSS. This is not done in EFI but is needed for enabling VT
    // 
    __asm
    {
        sgdt gdt_reg
    }

    Temp32 = 0;
    Temp32 = gdt_reg.BaseHi;
    Temp32 <<= 16;
    Temp32 |= gdt_reg.BaseLo;
    GdtBase = Temp32;

    mTssBaseAddress = (UINT32*)0x0BE00000;   // At 190 MB we (hardcode) set the Task descriptor

    //
    // Setting TSS Entry in GDT 
    // The sixth entry is for the host TSS. The first five entries are already used up by EFI for the CS and DS etc.    //
    CreateGdtTssEntry (GdtBase+5, (UINT32)mTssBaseAddress);  

    //
    // Sixth Entry as mentioned above is for the TSS. 
    // So load the Task Register at 0x28 which is got from 5 entries * 8 bytes per entry = 40 = 0x28
    // 
    __asm mov eax, 0x28      
    __asm ltr eax

    __asm
    {
        sgdt gdt_reg
    }

    Temp32 = 0;
    Temp32 = gdt_reg.BaseHi;
    Temp32 <<= 16;
    Temp32 |= gdt_reg.BaseLo;
    GdtBase = Temp32;

    // 
    // Hard coding the Task Descriptor at 194 for the guest
    //
    mTssBaseAddress = (UINT32*)0x0C200000; 
                              
    //
    // Setting TSS Entry in GDT for the Guest TR at the seventh entry 
    //
    CreateGdtTssEntry (GdtBase+6, (UINT32)mTssBaseAddress);  

    __asm
    {
        SGDT	gdt_reg
    }

    Temp32 = 0;
    Temp32 = gdt_reg.BaseHi;
    Temp32 <<= 16;
    Temp32 |= gdt_reg.BaseLo;
    // ClearScreen();
    // PrintValue(*(UINT32*)(Temp32+40));
    // PrintString("\n");
    // PrintValue(*(UINT32*)(Temp32+44));
    // PrintString("\n");
    // PrintString("GDT Address is ");
    // PrintValue(Temp32);
    // PrintString("\n");
    // PrintString("GDT entries are as follows\n");
    // for(i=0;i<10;i+=4) {
    //     PrintValue(*(UINT32*)(Temp32+i));
    //     PrintString("\n");
    // }
    // Delay(1);
    // Delay(1);
    // ClearScreen();
    
    
    //
    // Enable Virtualization
    // set CR4.VMXE[bit 13] = 1
    // This enables virtualization
    //
    __asm {
	   // mov eax, cr4
           _emit 0x0f
           _emit 0x20
           _emit 0xe0
    }
    __asm mov cr4_reg, eax

    cr4_reg.VMXE = 1;

    __asm mov eax, cr4_reg
    // __asm mov cr4, eax
    // 0f 22 e0
    __asm _emit 0x0f
    __asm _emit 0x22
    __asm _emit 0xE0

    //
    // GDT Segment Selector  
    //
    __asm
    {
        SGDT	gdt_reg
    }

    Temp32 = 0;
    Temp32 = gdt_reg.BaseHi;
    Temp32 <<= 16;
    Temp32 |= gdt_reg.BaseLo;
    gdt_base = Temp32;
    // PrintString( "GDT Base = "); // 0x20318
    // PrintValue(gdt_base);
    // PrintString("\n");
    // PrintString( "GDT Limit = ");
    // PrintValue(gdt_reg.Limit);
    // PrintString("\n");
    
    //
    // IDT Segment Selector  
    //
    __asm	SIDT	idt_reg
    
    Temp32 = 0;
    Temp32 = idt_reg.BaseHi;
    Temp32 <<= 16;
    Temp32 |= idt_reg.BaseLo;
    idt_base = Temp32;
    // PrintString( "IDT Base = ");
    // PrintValue(idt_base );
    // PrintString("\n");
    // PrintString( "IDT Limit = ");
    // PrintValue(idt_reg.Limit );
    // PrintString("\n");
    // Delay(1);

    //
    // Enabled Virtualization
    //
    // Before executing VMXON, software should write the VMCS revision identifier (see
    // Section 2.2) to the VMXON region. It need not initialize the VMXON region in any other way.
    // PrintString("Reading MSR value for VMCS revision Identifier \n");   
    // Delay(1);
    // The VMX_BASIC MSR (index 1152) consists of the following fields:
    // • Bits 31:0 contain the 32-bit VMCS revision identifier used by the processor.
    // • Bits 44:32 report the number of bytes that software should allocate for the VMXON region
    // and any VMCS region. It is a value greater than 0 and at most 4096 (bit 44 is set if and
    // only if bits 43:32 are all clear).
    // • Bits 53:50 report the memory type that the processor uses to access the VMCS for
    // VMREAD and VMWRITE and to access the VMCS and data structures referenced by
    // pointers in the VMCS (for example, I/O bitmaps, TPR shadow, etc.) during VM entries,
    // VM exits, and in VMX non-root operation. The first processors to support VMX operation
    // use the write-back type. The values used are given in Table 6-1.
    // Table 6-1. Memory Types Used For VMCS Access
    // Value(s) Field
    // 0 Strong Un	cacheable (UC)
    // 1–5 Not used
    // 6 Write Back (WB)
    // 7–15 Not used
    
    // Software should map all VMCS regions and referenced data structures with the indicated
    // memory type.
    // • The values of bits 49:45 and bits 63:54 are reserved and are read as 0.
    
    //Before executing VMXON, software should allocate a naturally aligned 4KB region of memory
    //that a logical processor may use to support VMX operation.1 This region is called the VMXON
    //region. The physical address of the VMXON region (called the VMXON pointer) is provided
    //in an operand to VMXON. Section 2.10.4 details how software should initialize and access the
    //VMXON region.
    // So assigne a 4 KB region that is alligned, and then call VMXON with that
    //
    
    // PrintString("Checking the VMX features\n");   
    // Delay(1);
    __asm
    {
        mov ecx, IA32_VMX_BASIC_MSR_CODE
        rdmsr
        lea ebx, vmxBasicMsr
        mov [ebx+4], edx
        mov [ebx], eax
        mov ecx, IA32_FEATURE_CONTROL_CODE
        rdmsr
        lea ebx, vmxFeatureControl
        mov [ebx+4], edx
        mov [ebx], eax
    };
    
    // Before executing VMXON, software allocates a region of memory (called the VMXON region)
    // that the logical processor may use to support VMX operation. The physical address of this
    // region (the VMXON pointer) is provided in an operand to VMXON. Like VMCS pointers, the
    // VMXON pointer must be 4KB-aligned (bits 11:0 must be zero); in addition, the pointer must
    // not set any bits beyond the processor’s physical-address width.
    

    //PrintString("VMXON Region Size = "); 
    //PrintValue(vmxBasicMsr.szVmxOnRegion); 
    //PrintString("\n"); 
    //PrintString("VMXON Access Width Bit = "); 
    //PrintValue(vmxBasicMsr.PhyAddrWidth);
    //PrintString("\n"); 
    //PrintString( "      [   1] --> 32-bit\n");
    //PrintString( "      [   0] --> 64-bit\n");
    //PrintString( "VMXON Memory Type = ");
    //PrintValue(vmxBasicMsr.MemType );
    //PrintString("\n");
    //PrintString( "      [   0]  --> Strong Uncacheable\n");
    //PrintString( "      [ 1-5]  --> Unused\n");
    //PrintString( "      [   6]  --> Write Back\n");
    //PrintString( "      [7-15]  --> Unused\n");
    //Delay(1);
    //Delay(1);
    //Delay(1);
    //Delay(1);

    VMXONRegionSize = vmxBasicMsr.szVmxOnRegion;

    //PrintString("Vmxon Region size = ");
    //PrintValue(VMXONRegionSize);  Getting 0x00000400
    //Delay(1);
    //Delay(1);
    //Delay(1);
	
    switch( vmxBasicMsr.MemType )
    {
        case 0:
            PrintString("Error: Unsupported memory type = "); 
	    PrintValue(vmxBasicMsr.MemType);
            for(;;);
            break;
	case 6:
            break;
        default:
            PrintString("Error: Unknown VMXON Region memory type = ");
	    PrintValue(vmxBasicMsr.MemType);
            for(;;);
            break;
    }

    //
    // Feature Control should be locked
    //

    if( vmxFeatureControl.Lock != 1 )
    {
        PrintString("Error: Feature Control Lock Bit != 1.");
        for(;;);
    }

    //
    // Clear up the VMXON region before using it.
    //
    Temp32 = 0x0A000000;
    for(i=0;i<0x1000;i++) {
        *(UINT32 *)(Temp32+i*4) = 0x0;
    }
    /*
    for (i=0;i<0x1000;i++) {
            PrintString("Address = ");
            PrintValue(Temp32+i*4);
            PrintString("        Value = ");
	    PrintValue(*(UINT32 *)(Temp32+i*4));
            PrintString("\n");
	    if(i%32 == 0) 
	    {
		    Delay(1);
		    ClearScreen();
	    }
    }
    */

    //
    // Before executing VMXON, software should write the VMCS revision identifier (see
    // Section 2.2) to the VMXON region. It need not initialize the VMXON region in any other way.
    //
    pVMXONRegion = 0x0A000000; // Vmxon region 4k aligned and hard coded to 160 MB

    *(pVMXONRegion) = vmxBasicMsr.RevId;
	
    // PrintString( "vmxBasicMsr.RevId = "); 
    // PrintValue(vmxBasicMsr.RevId );
    // PrintString( "\n");
    // Delay(1);
    // Delay(1);
    // ClearScreen();

    // 
    // Enable NE. Needed by VT
    //
    __asm
    {
        mov eax, cr0
        mov cr0_reg, eax
    }
    cr0_reg.NE = 1;
    __asm
    {
        mov eax, cr0_reg
        mov cr0, eax
    }


    // Execute VMXON with the physical address of the VMXON region as the
    // operand. Check successful execution of VMXON by checking if
    // RFLAGS.CF=0.
    // PrintString( "Executing VMXON\n");
    // Delay(1);
    __asm
    {
        push dword ptr 0
        push dword ptr pVMXONRegion
	// VMXON [ESP]
        _emit	0xF3
        _emit	0x0F
        _emit	0xC7
        _emit	0x34
        _emit	0x24
        pushfd
        pop eFlags
	add esp, 8
    }

    PrintString("VMXON instruction has been executed\n");
    Delay(1);
    // PrintString( "Executed VMXON\n");
    // Delay(1);

    if( eFlags.CF == 1 )
    {
        PrintString("Error: VMXON failed\n");
	for(;;);
    }
	
    // PrintString("VMXON succeded!\n" );
    PrintString("The VMM is now running!!!\n\n" );
    Delay(1);
    // Delay(1);
	
    //
    // The processor is now in VMX-root
    //
    // Create a VMCS region in non-pageable memory of size specified by
    // the VMX capability MSR IA32_VMX_BASIC and aligned to 4-KBytes.
    // Software should read the capability MSRs to determine width of the 
    // physical addresses that may be used for a VMCS region and ensure
    // the entire VMCS region can be addressed by addresses with that width.
    // The term "guest-VMCS address" refers to the physical address of the
    // new VMCS region for the following steps
    //
    VMCSRegionSize = vmxBasicMsr.szVmxOnRegion;
    
    switch( vmxBasicMsr.MemType )
    {
        case 0:
            PrintString("Error: Unsupported memory type = ");
            PrintValue(vmxBasicMsr.MemType );
            PrintString("\n");
            for(;;);
            break;
        case 6:
            break;
        default:
            PrintString("Error: Unknown VMCS Region memory type\n");
            for(;;);
            break;
    }

    //    
    // Initialize the version identifier in the VMCS (first 32 bits)
    // with the VMCS revision identifier reported by the VMX
    // capability MSR IA32_VMX_BASIC.
    //
    pVMCSRegion = 0x0A001000; // Vmcs region 4k aligned and located at 160 MB + 4K 
    *(pVMCSRegion) = vmxBasicMsr.RevId;
    __asm mov eax, pVMCSRegion
    __asm mov Temp32, eax
    PrintString("VM Control Structure created\n");
    Delay(1);

    // PrintString("VMCS Pointer = ");
    // PrintValue(*pVMCSRegion);
    // PrintString("\n");
    // Delay(1);
    
    //
    // Execute the VMCLEAR instruction by supplying the guest-VMCS address.
    // This will initialize the new VMCS region in memory and set the launch
    // state of the VMCS to "clear". This action also invalidates the
    // working-VMCS pointer register to FFFFFFFF_FFFFFFFFH. Software should
    // verify successful execution of VMCLEAR by checking if RFLAGS.CF = 0
    // and RFLAGS.ZF = 0
    //

    // PrintString( "Going to do VMClear\n" );
    // Delay(1);
    // Delay(1);

    __asm
    {
        push dword ptr 0
	push dword ptr pVMCSRegion
        // VMCLEAR [ESP]
        _emit	0x66
        _emit	0x0F
        _emit	0xc7
        _emit	0x34
        _emit	0x24
	add esp, 0x8
        pushfd
        pop eFlags
    }

    // PrintString( "VMClear done\n" );
    // Delay(1);
    // Delay(1);

    if(eFlags.CF != 0 || eFlags.ZF != 0 )
    {
        PrintString("Error: VMCLEAR failed\n");
	for(;;);
    }

    // PrintString( "SUCCESS : VMCLEAR operation completed\n" );
    // Delay(1);

    //    
    // Execute the VMPTRLD instruction with the VMCS address
    // This initializes the VMCS pointer to the VMCS region
    //

    // PrintString( "Going to do VMPTRLD\n" );
    // Delay(1);
    __asm
    {
        push dword ptr 0
	push dword ptr pVMCSRegion
	// VMPTRLD [ESP]
        _emit	0x0F
        _emit	0xC7
        _emit	0x34
        _emit	0x24
        add esp, 8
    }
    PrintString("VM Control Structure loaded and active \n");
    Delay(1);

    PrintString("Filling up the VM Control Structure \n");
    Delay(1);

     //
     // C.1.1 16-Bit Guest-State Fields
     //
     
     //
     //	Guest ES selector - 00000800H
     //
     
     // ClearScreen();

    __asm mov seg_selector, ES
    seg_selector &= 0xFFFC;
    // PrintString("Guest ES Selector shouldnt be zero = ");
    // PrintValue(seg_selector);
    // PrintString("\n");

    WriteVMCS( 0x00000800, seg_selector );

    // Guest CS selector 00000802H
    __asm mov seg_selector, CS
    seg_selector &= 0xFFFC;
    // PrintString("Guest CS Selector shouldnt be zero = "); 
    // PrintValue(seg_selector);
    // PrintString("\n");

    WriteVMCS( 0x00000802, seg_selector );

    // Guest SS selector 00000804H
    __asm mov seg_selector, SS
    seg_selector &= 0xFFFC;

    // PrintString("Guest SS Selector shouldnt be zero = ");
    // PrintValue(seg_selector);
    // PrintString("\n");

    WriteVMCS( 0x00000804, seg_selector );

    // Guest DS selector 00000806H
    __asm mov seg_selector, DS
    seg_selector &= 0xFFFC;
    // PrintString("Guest DS Selector shouldnt be zero = ");
    // PrintValue(seg_selector);
    // PrintString("\n");
    WriteVMCS( 0x00000806, seg_selector );

    // Guest FS selector 00000808H
    __asm mov seg_selector, FS
    seg_selector &= 0xFFFC;
    // PrintString("Guest FS Selector shouldnt be zero = ");
    // PrintValue(seg_selector);
    // PrintString("\n");
    WriteVMCS( 0x00000808, seg_selector );

    // Guest GS selector 0000080AH
    __asm mov seg_selector, GS
    seg_selector &= 0xFFFC;
    // PrintString("Guest GS Selector shouldnt be zero = ");
    // PrintValue(seg_selector);
    // PrintString("\n");
    WriteVMCS( 0x0000080A, seg_selector );

    // Guest LDTR selector 0000080CH
    WriteVMCS( 0x0000080C, 0x10 );     // Cannot be 0x0, as VT might have a problem with that

    // Guest TR selector 0000080EH
    __asm str seg_selector
    // PrintString("Watch this one - Guest TR Selector = ");
    // PrintValue(seg_selector);
    // PrintString("\n");
    seg_selector &= 0xFFFC;
    seg_selector = 0x30;
    ClearBit( &seg_selector, 2 );  // TI Flag
    // PrintString("After changing Guest TR Selector shouldnt be zero = ");
    // PrintValue(seg_selector);
    // PrintString("\n");
    // Delay(1);
    // ClearScreen();
    WriteVMCS( 0x0000080E, seg_selector );

    // C.1.2 16-Bit Host-State Fields
    
    // Host ES selector	00000C00H

    __asm mov seg_selector, ES
    seg_selector &= 0xFFFC;
    // PrintString("ES Host Selector Field = ");
    // PrintValue(seg_selector);
    // PrintString("\n");
    WriteVMCS( 0x00000C00, seg_selector );
			
    // Host CS selector 00000C02H
    __asm mov seg_selector, CS
    seg_selector &= 0xFFFC;
    WriteVMCS( 0x00000C02, seg_selector );
    // PrintString("CS Host Selector Field = ");
    // PrintValue(seg_selector);
    // PrintString("\n");

    // Host SS selector 00000C04H
    __asm mov seg_selector, SS
    seg_selector &= 0xFFFC;
    WriteVMCS( 0x00000C04, seg_selector );
    // PrintString("SS Host Selector Field = ");
    // PrintValue(seg_selector);
    // PrintString("\n");

    // Host DS selector 00000C06H
    __asm mov seg_selector, DS
    seg_selector &= 0xFFFC;
    // PrintString("DS Host Selector Field = ");
    // PrintValue(seg_selector);
    // PrintString("\n");
    WriteVMCS( 0x00000C06, seg_selector );

    // Host FS selector	00000C08H
    __asm mov seg_selector, FS
    seg_selector &= 0xFFFC;
    WriteVMCS( 0x00000C08, seg_selector );
    // PrintString("FS Host Selector Field = ");
    // PrintValue(seg_selector);
    // PrintString("\n");

    // Host GS selector	00000C0AH
    __asm mov seg_selector, GS
    seg_selector &= 0xFFFC;
    // PrintString("GS Host Selector Field = ");
    // PrintValue(seg_selector);
    // PrintString("\n");
    WriteVMCS( 0x00000C0A, seg_selector );

    // Host TR selector 00000C0CH
    __asm str seg_selector
    // PrintString("WATCH THIS ONE TR Selector Field = ");
    // PrintValue(seg_selector);
    // PrintString("\n");
    // Delay(1);
    // Delay(1);
    seg_selector &= 0xFFFC;
    WriteVMCS( 0x00000C0C, seg_selector );
    //ClearScreen();

    // C-3. Encodings for 64-Bit Control Fields 
    // Field Name Index Encoding
    // I/O bitmap A (full) 000000000B 00002000H
    // I/O bitmap A (high) 000000000B 00002001H
    // I/O bitmap B (full) 000000001B 00002002H
    // I/O bitmap B (high) 000000001B 00002003H
    // VM-exit MSR-store address (full) 000000011B 00002006H
    // VM-exit MSR-store address (high) 000000011B 00002007H
    // VM-exit MSR-load address (full) 000000100B 00002008H
    // VM-exit MSR-load address (high) 000000100B 00002009H
    // VM-entry MSR-load address (full) 000000101B 0000200AH
    // VM-entry MSR-load address (high) 000000101B 0000200BH
    // TSC offset (full) 000001000B 00002010H
    // TSC offset (high) 000001000B 00002011H
    // Virtual-APIC page address (full) 000001001B 00002012H
    // Virtual-APIC page address (high) 000001001B 00002013H
    //

    // C.2.2 64-Bit Guest-State Fields
    // VMCS Link Pointer (full)	00002800H
    Temp32 = 0xFFFFFFFF;
    WriteVMCS( 0x00002800, Temp32 );

    // VMCS link pointer (high)	00002801H
    Temp32 = 0xFFFFFFFF;
    WriteVMCS( 0x00002801, Temp32 );

    // Reserved Bits of IA32_DEBUGCTL MSR must be 0
    // (1D9H)
    ReadMSR( 0x000001D9 );

    // Guest IA32_DEBUGCTL (full) 00002802H
    Temp32 = msr.Lo;
    // PrintString("Debug Ctl Low = ");
    // PrintValue(msr.Lo);
    // PrintString("        Debug Ctl Hi = ");
    // PrintValue(msr.Hi);
    // PrintString("\n");
    // Temp32=0;
    WriteVMCS( 0x00002802, Temp32 );
    // Guest IA32_DEBUGCTL (high) 00002803H
    Temp32 = msr.Hi;
    //Temp32=0;
    WriteVMCS( 0x00002803, Temp32 );
    
    //
    // C.3.1 32-Bit Control Fields
    //
    // Pin-based VM-execution controls 00004000H
    // IA32_VMX_PINBASED_CTLS MSR (index 481H)
    ReadMSR( 0x481 );
    Temp32 = 0;
    Temp32 |= msr.Lo;
    Temp32 &= msr.Hi;
    // PrintString("The reference msr hi = ");
    // PrintValue(msr.Hi);
    
    // PrintString("\n");
    // PrintString("Temp32 should match the msr hi = \n");
    // PrintValue(Temp32);
    // PrintString("\n");
    
    //SetBit( &Temp32, 3 );
    WriteVMCS( 0x00004000, Temp32 );
    // Primary processor-based VM-execution controls 00004002H
    // IA32_VMX_PROCBASED_CTLS MSR (index 482H)
    ReadMSR( 0x482 );
    Temp32 = 0;
    Temp32 |= msr.Lo;
    Temp32 &= msr.Hi;
    WriteVMCS( 0x00004002, Temp32 );
    // Execution Bitmap controls 00004004H
    Temp32 = 0;
    WriteVMCS( 0x00004004, Temp32 );
    
    // Page-fault error-code mask 000000011B 00004006H
    // Page-fault error-code match 000000100B 00004008H
    // CR3-target count 000000101B 0000400AH

    //	Get the CR3-target count, MSR store/load counts, et cetera
    //
    //	IA32_VMX_MISC MSR (index 485H)
    //	ReadMSR( 0x485 );
    //	RtlCopyBytes( &misc_data, &msr.Lo, 4 );
    
    // VM-exit controls	0000400CH
    // IA32_VMX_EXIT_CTLS MSR (index 483H)
    ReadMSR( 0x483 );
    Temp32 = 0;
    Temp32 |= msr.Lo;
    Temp32 &= msr.Hi;
    // SetBit( &Temp32, 15 );								
    // Acknowledge Interrupt On Exit
    WriteVMCS( 0x0000400C, Temp32 );
    // VM-entry controls 00004012H
    // IA32_VMX_ENTRY_CTLS MSR (index 484H)
    ReadMSR( 0x484 );
    Temp32 = 0;
    Temp32 |= msr.Lo;
    Temp32 &= msr.Hi;
    // ClearBit( &Temp32 , 9 );	 // IA-32e Mode Guest Disable
    WriteVMCS( 0x00004012, Temp32 );
    //
    // C.3.3 32-Bit Guest-State Fields
    //
    
    // Guest ES limit 00004800H
    __asm mov seg_selector, ES
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
    WriteVMCS( 0x00004800, 0xFFFFFFFF );
    
    // Guest CS limit 00004802H
    __asm mov seg_selector, CS
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
    WriteVMCS( 0x00004802, 0xFFFFFFFF );
    
    // Guest SS limit 00004804H
    __asm mov seg_selector, SS
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
    WriteVMCS( 0x00004804, 0xFFFFFFFF );
    
    // Guest DS limit 00004806H
    __asm mov seg_selector, DS
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
    WriteVMCS( 0x00004806, 0xFFFFFFFF );
    
    // Guest FS limit 00004808H
    __asm mov seg_selector, FS
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
    WriteVMCS( 0x00004808, 0x00001000 );
    
    // Guest GS limit 0000480AH
    __asm mov seg_selector, GS
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
    WriteVMCS( 0x0000480A, 0xFFFFFFFF );
    
    // Guest TR limit 0000480EH
    __asm
    {
        push eax
        str ax
        mov mLDT, ax
        pop eax
    }

    Temp32 = 0;
    Temp32 = GetSegmentDescriptorLimit( gdt_base, mLDT );
    WriteVMCS( 0x0000480E, Temp32 );
    
    // Guest GDTR limit 00004810H
    WriteVMCS( 0x00004810, gdt_reg.Limit );
    
    // Guest IDTR limit	00004812H
    WriteVMCS( 0x00004812, idt_reg.Limit );
    
    __asm mov seg_selector, CS
    Temp32 = seg_selector;
    Temp32 >>= 3;
    Temp32 *= 8;
    Temp32 += (gdt_base + 5);			// CS Segment Descriptor
    __asm
    {
        pushad
        mov eax, Temp32
        mov ebx, [eax]
        mov Temp32, ebx
        popad
    }
    Temp32 &= 0x0000F0FF;
    WriteVMCS( 0x00004816, Temp32 );
    __asm mov seg_selector, DS
    Temp32 = seg_selector;
    Temp32 >>= 3;
    Temp32 *= 8;
    Temp32 += (gdt_base + 5);			// DS Segment Descriptor
    __asm
    {
        pushad
        mov eax, Temp32
        mov ebx, [eax]
        mov Temp32, ebx
        popad
    }
    Temp32 &= 0x0000F0FF;
    WriteVMCS( 0x0000481A, Temp32 );
    __asm mov seg_selector, ES
    Temp32 = seg_selector;
    Temp32 >>= 3;
    Temp32 *= 8;
    Temp32 += (gdt_base + 5);			// ES Segment Descriptor
    __asm
    {
        pushad 
        mov eax, Temp32
        mov ebx, [eax]
        mov Temp32, ebx
        popad
    }

    Temp32 &= 0x0000F0FF;
    WriteVMCS( 0x00004814, Temp32 );
    
    __asm mov seg_selector, FS
    Temp32 = seg_selector;
    Temp32 >>= 3;
    Temp32 *= 8;
    Temp32 += (gdt_base + 5);			// FS Segment Descriptor
    __asm
    {
        pushad
        mov eax, Temp32
        mov ebx, [eax]
        mov Temp32, ebx
        popad
    }

    Temp32 &= 0x0000F0FF;
    Temp32 &= 0xFFFF7FFF;				// Granularity Bit = 0
    WriteVMCS( 0x0000481C, Temp32 );
    
    __asm mov seg_selector, GS
    Temp32 = seg_selector;
    Temp32 >>= 3;
    Temp32 *= 8;
    Temp32 += (gdt_base + 5);			// GS Segment Descriptor
    __asm
    {
        pushad
        mov eax, Temp32
        mov ebx, [eax]
        mov Temp32, ebx
        popad
    }
    Temp32 &= 0x0000F0FF;
    SetBit( &Temp32, 16 );				// Unusable
    WriteVMCS( 0x0000481E, Temp32 );
    
    __asm mov seg_selector, SS
    Temp32 = seg_selector;
    Temp32 >>= 3;
    Temp32 *= 8;
    Temp32 += (gdt_base + 5);			// SS Segment Descriptor
    __asm
    {
        pushad
        mov eax, Temp32
        mov ebx, [eax]
        mov Temp32, ebx
        popad
    }
    
    Temp32 &= 0x0000F0FF;
    WriteVMCS( 0x00004818, Temp32 );
    
    __asm str seg_selector
    Temp32 = seg_selector;
    Temp32 >>= 3;
    Temp32 *= 8;
    Temp32 += (gdt_base + 5);			// TR Segment Descriptor
    __asm
    {
        pushad
        mov eax, Temp32
	mov ebx, [eax]
	mov Temp32, ebx
	popad
    }
    Temp32 &= 0x0000F0FF;
    WriteVMCS( 0x00004822, Temp32 );
    // Guest LDTR access rights 00004820H
    Temp32 = 0;
    SetBit( &Temp32, 16 );			// Unusable
    WriteVMCS( 0x00004820, Temp32 );
    
    // Guest IA32_SYSENTER_CS 0000482AH
    // (174H)
    ReadMSR( 0x174 );
    WriteVMCS( 0x0000482A, msr.Lo );
    
    //
    // C.3.4 32-Bit Host-State Fields
    //
    
    // Host IA32_SYSENTER_CS 00004C00H
    // (174H)
    ReadMSR( 0x174 );
    WriteVMCS( 0x00004C00, msr.Lo );
    
    //
    // C.4.3 Natural-Width Guest-State Fields
    //
    
    // Guest CR0 00006800H
    __asm
    {
        PUSH	EAX
        MOV	EAX, CR0
        MOV	Temp32, EAX
        POP	EAX
    }
				
    ReadMSR( 0x486 );							// IA32_VMX_CR0_FIXED0
    ReadMSR( 0x487 );							// IA32_VMX_CR0_FIXED1
			
    SetBit( &Temp32, 0 );		// PE
    SetBit( &Temp32, 5 );		// NE
    SetBit( &Temp32, 31 );		// PG
    WriteVMCS( 0x00006800, Temp32 );
    // Guest CR3 00006802H
    __asm
    {
        PUSH	EAX
        _emit	0x0F	// MOV EAX, CR3
        _emit	0x20
        _emit	0xD8
        MOV	Temp32, EAX
        POP	EAX
    }
    WriteVMCS( 0x00006802, Temp32 );

    // Guest CR4 00006804H
    __asm
    {
        PUSH	EAX
        _emit	0x0F	// MOV EAX, CR4
        _emit	0x20
        _emit	0xE0
        MOV	Temp32, EAX
        POP	EAX
    }

    ReadMSR( 0x488 );							// IA32_VMX_CR4_FIXED0
    ReadMSR( 0x489 );							// IA32_VMX_CR4_FIXED1
    SetBit( &Temp32, 13 );		// VMXE
    WriteVMCS( 0x00006804, Temp32 );
    // Guest ES base 00006806H
    __asm mov seg_selector, ES
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
    WriteVMCS( 0x00006806, Temp32 );
    // Guest CS base 00006808H
    __asm	MOV		seg_selector, CS
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
    WriteVMCS( 0x00006808, Temp32 );	
    // Guest SS base 0000680AH
    __asm	MOV		seg_selector, SS
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
    WriteVMCS( 0x0000680A, Temp32 );	
    // Guest DS base 0000680CH
    __asm	MOV		seg_selector, DS
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
    WriteVMCS( 0x0000680C, Temp32 );	
    // Guest FS base 0000680EH
    __asm	MOV		seg_selector, FS
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
    WriteVMCS( 0x0000680E, Temp32 );
    // Guest TR base 00006814H
    __asm
    {
        PUSH	EAX
        STR	AX
        MOV	mLDT, AX
        POP	EAX
    }
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorBase( gdt_base , mLDT );
    WriteVMCS( 0x00006814, Temp32 );
    // Guest GDTR base	00006816H
    __asm
    {
        SGDT	gdt_reg
    }
    Temp32 = 0;
    Temp32 = gdt_reg.BaseHi;
    Temp32 <<= 16;
    Temp32 |= gdt_reg.BaseLo;
    WriteVMCS( 0x00006816, Temp32 );
    // Guest IDTR base 00006818H
    __asm
    {
        SIDT	idt_reg
    }
    Temp32 = 0;
    Temp32 = idt_reg.BaseHi;
    Temp32 <<= 16;
    Temp32 |= idt_reg.BaseLo;
    WriteVMCS( 0x00006818, Temp32 );
    // Guest RFLAGS 00006820H
    __asm
    {
        PUSHAD
        PUSHFD
        MOV	EAX, 0x00006820
        // VMWRITE	EAX, [ESP]
        _emit	0x0F
        _emit	0x79
        _emit	0x04
        _emit	0x24
        POP	eFlags
        POPAD
    }

    // Guest IA32_SYSENTER_ESP 00006824H
    // MSR (175H)
    ReadMSR( 0x175 );
    WriteVMCS( 0x00006824, msr.Lo );
    // Guest IA32_SYSENTER_EIP 00006826H
    // MSR (176H)
    ReadMSR( 0x176 );
    WriteVMCS( 0x00006826, msr.Lo );
    
    //
    // C.4.4 Natural-Width Host-State Fields
    //
    // Host CR0	00006C00H
    __asm
    {
        PUSH	EAX
        MOV	EAX, CR0
        MOV	Temp32, EAX
        POP	EAX
    }
    SetBit( &Temp32, 0 );		// PE
    SetBit( &Temp32, 5 );		// NE
    SetBit( &Temp32, 31 );		// PG
    WriteVMCS( 0x00006C00, Temp32 );
    // Delay(1);
    // Delay(1);
    // ClearScreen();
    // PrintString("HOST CR0 = \n");
    // PrintValue(Temp32);
    // PrintString("\n");
    // Host CR3	00006C02H
    __asm
    {
        PUSH	EAX
        _emit	0x0F	// MOV EAX, CR3
        _emit	0x20
        _emit	0xD8
        MOV	Temp32, EAX
        POP	EAX
    }
    WriteVMCS( 0x00006C02, Temp32 );
    // PrintString("Host CR3 = \n");
    // PrintValue(Temp32);
    // PrintString("\n");
    
    // Host CR4	00006C04H
    __asm
    {
        PUSH	EAX
        _emit	0x0F	// MOV EAX, CR4
        _emit	0x20
        _emit	0xE0
        MOV Temp32, EAX
        POP EAX
    }
    SetBit( &Temp32, 13 );		// VMXE
    WriteVMCS( 0x00006C04, Temp32 );				
    // PrintString("Host CR4 = \n");
    // PrintValue(Temp32);
    // PrintString("\n");
    
    // Host FS base 00006C06H
    __asm MOV seg_selector, FS
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
    // PrintString("Host GDT Base = \n");
    // PrintValue(gdt_base);
    // PrintString("\n");
    // PrintString("Host Segment Selector = \n");
    // PrintValue(seg_selector);
    // PrintString("\n");
    // PrintString("Host fS Base = ");  // 0x240320
    // PrintValue(Temp32);
    // PrintString("\n");
    WriteVMCS( 0x00006C06, Temp32 );
    // Host GS base 00006C08H
    __asm MOV seg_selector, GS
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
    // PrintString("Host GS Base = ");
    // PrintValue(Temp32);
    // PrintString("\n");
    WriteVMCS( 0x00006C08, Temp32 );
    
    // Host TR base 00006C0AH
    __asm
    {
        PUSH	EAX
        STR	AX
        MOV	mLDT, AX
        POP	EAX
    }
    Temp32 = 0;
    Temp32 = GetSegmentDescriptorBase( gdt_base , mLDT );
    // PrintString("Host TR Base = ");
    //Temp32 |= 0x0FFFF;
    // PrintValue(Temp32);
    // PrintString("\n");
    WriteVMCS( 0x00006C0A, Temp32 );
    // Host GDTR base 00006C0CH
    __asm
    {
        SGDT	gdt_reg
    }
    Temp32 = 0;
    Temp32 = gdt_reg.BaseHi;
    Temp32 <<= 16;
    Temp32 |= gdt_reg.BaseLo;
    WriteVMCS( 0x00006C0C, Temp32 );				
    // PrintString("Host GDTR Base = ");
    // PrintValue(Temp32);
    // PrintString("\n");
    // Delay(1);
    // Delay(1);
    // Delay(1);
    // Delay(1);
    // ClearScreen();
    // Host IDTR base 00006C0EH
    __asm
    {
        SIDT	idt_reg
    }
    Temp32 = 0;
    Temp32 = idt_reg.BaseHi;
    Temp32 <<= 16;
    Temp32 |= idt_reg.BaseLo;
    WriteVMCS( 0x00006C0E, Temp32 );
    
    // Host IA32_SYSENTER_ESP 00006C10H
    // MSR (175H)
    ReadMSR( 0x175 );
    WriteVMCS( 0x00006C10, msr.Lo );
    
    // Host IA32_SYSENTER_EIP 00006C12H
    // MSR (176H)
    ReadMSR( 0x176 );
    WriteVMCS( 0x00006C12, msr.Lo );
    PrintString("VM Control Structure has been filled up\n");
    Delay(1);


    // Issue a sequence of VMWRITEs to initialize various host-state area
    // fields in the working VMCS. The initialization sets up the context
    // and entry-points to the VMM VIRTUAL-MACHINE MONITOR PROGRAMMING
    // CONSIDERATIONS upon subsequent VM exits from the guest. Host-state
    // fields include control registers (CR0, CR3 and CR4), selector fields
    // for the segment registers (CS, SS, DS, ES, FS, GS and TR), and base-
    // address fields (for FS, GS, TR, GDTR and IDTR; RSP, RIP and the MSRs
    // that control fast system calls).
    //		
    // Use VMWRITEs to set up the various VM-exit control fields, VM-entry
    // control fields, and VM-execution control fields in the VMCS. Care
    // should be taken to make sure the settings of individual fields match
    // the allowed 0 and 1 settings for the respective controls as reported
    // by the VMX capability MSRs (see Appendix G). Any settings inconsistent
    // with the settings reported by the capability MSRs will cause VM
    // entries to fail.
    // Use VMWRITE to initialize various guest-state area fields in the
    // working VMCS. This sets up the context and entry-point for guest
    // execution upon VM entry. Chapter 22 describes the guest-state loading
    // and checking done by the processor for VM entries to protected and
    // virtual-8086 guest execution.
    //
    // Clear the VMX Abort Error Code prior to VMLAUNCH
    //
    Temp32 = (UINT32)pVMCSRegion+4;
    *(UINT32*)Temp32 = 0x0;
    
    __asm
    {
        PUSHAD
        MOV EAX, 0x00004402
        _emit	0x0F	// VMREAD  EBX, EAX
        _emit	0x78
        _emit	0xC3
        MOV ErrorCode, EBX
        POPAD
    }
    		
    // PrintString( "VM error value is = " );
    // PrintValue(ErrorCode);
    // PrintString("\n");
    
    //
    // Print out the parameters for the Second Image
    //
    
    if (!EFI_ERROR(Status) && Image.EntryPoint!=NULL) {
        EfiLoadedImage = &Image.Info;

    // PrintString("The Second Image entry is at ");
    // PrintValue(Image.EntryPoint);
    // PrintString("\n");
    // PrintString("Start few bytes at entry point are");
    // PrintString("\n");
    // PrintValue(*(UINT32*)Image.EntryPoint);
    // PrintString("\n");
    // PrintValue(*((UINT32*)Image.EntryPoint+4));
    // PrintString("\n");
    // PrintValue(*((UINT32*)Image.EntryPoint+8));
    // PrintString("\n");
    // PrintValue(*((UINT32*)Image.EntryPoint+12));
    // PrintString("\n");
    // Delay(1);
    }

    //
    // Load the parameters for the second image in the VMCS guest register regions (EIP, ESP etc.)
    //

    if (!EFI_ERROR(Status) && Image.EntryPoint!=NULL) {
        UINT32 StackAddress;
        StackAddress = (UINT32)Image.ImageBasePage - 0x10;
        EfiLoadedImage = &Image.Info;
        // PrintString("setting up the VMCS guest registers \n");
        // Delay(1);
        __asm    lea     edx, EfiMemoryDescriptor
        __asm    mov     Temp32, edx
	StackAddress -= 4;
	*((UINT32*)StackAddress) = EfiLoadedImage;
	StackAddress -= 4;
	*((UINT32*)StackAddress) = Temp32;
	StackAddress -= 4;
	*((UINT32*)StackAddress) = NumberOfMemoryMapEntries;
	StackAddress -= 4;
	*((UINT32*)StackAddress) = 0;
        // PrintString("Guest Stack address is ");
	// PrintValue(StackAddress);
	// PrintString("\n");
        // PrintString("Guest IP address is ");
	// PrintValue((UINT32)Image.EntryPoint);
	// PrintString("\n");
 	WriteVMCS( 0x0000681C, (UINT32)StackAddress);
	// Set the guest IP address to the Image's entry point
	WriteVMCS( 0x0000681E, (UINT32)Image.EntryPoint );
    }

    //
    // Setting host EIP to the area where the return should happen when a VM Exit happens 

    __asm mov eax, vmexit_label
    __asm mov Temp32, eax
    VMMEntryPoint = Temp32;
    // PrintString("Setting the VM Exit entry point value to ");
    // PrintValue(Temp32);
    // PrintString("\n");
    // PrintString("The instructions at VM Exit are ");
    // PrintValue(*(UINT32*)Temp32);
    // PrintString("\n");
    // PrintValue(*(UINT32*)(Temp32+4));
    // PrintString("\n");
    // PrintValue(*(UINT32*)(Temp32+8));
    // PrintString("\n");
    //	
    // PrintString("VMM Entry point IP address is ");
    // PrintValue((UINT32)VMMEntryPoint);
    // PrintString("\n");
    WriteVMCS( 0x00006C16, (UINT32)VMMEntryPoint );
    PrintString("\nGoing to launch the Virtual Machine!\n");
    PrintString("Clearing Screen..");
    Delay(1);
    PrintString(".");
    Delay(1);
    ClearScreen();

    __asm
    {
        PUSHAD
        MOV EAX, 0x00004402
        _emit 0x0F	// VMREAD  EBX, EAX
        _emit 0x78
        _emit 0xC3
        MOV ErrorCode, EBX
        POPAD
    }
		
    __asm mov eax, esp	
    __asm mov Temp32, eax
    WriteVMCS( 0x00006C14, ((UINT32)Temp32) );

    //
    // VMLAUNCH  
    //

    __asm
    {
        _emit 0x0F	// VMLAUNCH
        _emit 0x01
        _emit 0xC2
    }

    __asm
    {
        PUSHFD
        POP eFlags
    }

    PrintString("VMLAUNCH Failure\n");

    if( eFlags.CF != 0 || eFlags.ZF != 0 || TRUE)
    {
        //
        //	Get the ERROR number using VMCS field 00004400H
        //
        __asm
        {
            PUSHAD
            MOV	EAX, 0x00004400
            _emit 0x0F	// VMREAD  EBX, EAX
            _emit 0x78
            _emit 0xC3
            MOV	ErrorCode, EBX
            POPAD
        }
    		
        PrintString("VM Instruction Error = ");
        PrintValue(ErrorCode);
    }
    
    // This is where the vmm code gets control on a vmexit. Need to handle the event and return control
    vmexit_label:
    //
    //Find the cause of the VM Exit and then handle it and return control to the VM 
    //
    Cursor =  (UINT8 *)(0x000b8000 + 160*16);  // Print the VM's print messages at the bottom
    PrintString("A VM Exit was encountered\n");
    PrintString("We are back in VMX Root Mode\n");

    __asm
    {
        pushad
        mov eax, 0x00004402
        _emit 0x0F	// VMREAD ebx, eax
        _emit 0x78
        _emit 0xC3
        mov ErrorCode, ebx
	popad
    }
		
    PrintString("VM Exit reason  = ");
    PrintValue(ErrorCode);
    PrintString("\n");

    switch (ErrorCode) {
        case 28:
            PrintString("VM Exit reason was that there was a CR register access \n");
            // Control Register was read
            // Write some value into the guest CR3 
            // Guest CR3 00006802H
            Temp32 = 0;
            __asm
            {
                push eax
	        _emit 0x0F // mov eax, CR3
                _emit 0x20
                _emit 0xD8
                mov Temp32, eax
                pop     eax
            }
            WriteVMCS( 0x00006802, Temp32 );
	    // Update the IP of the guest 
	    // First read the Guest IP value
	    // Then add the opcode length to the IP (here it is 1 byte)
 
            __asm
            {
                pushad
                MOV EAX, 0x0000681E
		_emit 0x0F // VMREAD  EBX, EAX
		_emit 0x78
		_emit 0xC3
		mov Temp32, ebx
		popad
	    }

	    Temp32+=1;
	    WriteVMCS( 0x0000681E,Temp32);

	    break;
	default:
	    PrintString("Unhandled VM exit\n");
	    for(;;);
	    break;
    }
    // Clear the VMX Abort Error Code prior to VMLAUNCH
    //
    Temp32 = (UINT32)pVMCSRegion+4;
    *(UINT32*)Temp32 = 0x0;

    //
    // Clear up the VM Exit reason
    //
    // Temp32 = 0;
    // WriteVMCS( 0x00004402, Temp32 );
    
    __asm
    {
        PUSHAD
        MOV EAX, 0x00004402
        _emit	0x0F	// VMREAD  EBX, EAX
        _emit	0x78
        _emit	0xC3
        MOV ErrorCode, EBX
        POPAD
    }
    Delay(1);
    Delay(1);
    Delay(1);
    Cursor =  (UINT8 *)(0x000b8000 + 160*16);  // Print the VM's print messages at the bottom
    ClearHalfScreen();
    Delay(1);
    Delay(1);

    //
    // VM Resume
    // 
    __asm
    {
        _emit	0x0F	// VMResume
        _emit	0x01
        _emit	0xC3
    }

    *(UINT8 *)(0x000b8000+26) = 'E';
    for(;;);
}


void EnableProtection() {

    //
    // PrintString("Checking if Protected Mode execution is enabled\n");   
    //
    __asm mov eax, cr0
    __asm mov cr0_reg, eax
    if (cr0_reg.PE)
        PrintString("Protected Mode is enabled\n");   
    else {
            PrintString("Error: Protected Mode is disabled\n");   
	    for(;;);
    }
}

void EnablePaging()
{
    UINT32		  Temp32;
    UINT32		  Temp321;
    UINT32                i;

    //
    //PrintString("Checking if Paging enabled\n ");   
    //
    __asm mov eax, cr0
    __asm mov Temp32, eax
    if (Temp32 & 0x80000000) {
	    PrintString("Paging enabled already!!\n");   
    }
    else {
            PrintString("Paging is disabled, needs to be enabled before launching the VMM\n");   
    // Delay(1);
    }
    // Now enable paging. Virtualization doesnt work without paging. 
    // Set the page directory from 256MB onwards 
    // To support 1 GB of 4 K pages, we need 256 directory entries.
    // Each directory entry supports 1024 Page Table Entries. Each Page Table entry supports one 4K page
    // Thus we have 256*1024*4K = 1 GB of memory supported
    //

    // The page directory and page tables are populated here. Start allcating at 256MB and 
    // add a memory descriptor for 16MB region that will be used by the Page tables
    EfiAddMemoryDescriptor(&NumberOfMemoryMapEntries,
                           EfiMemoryDescriptor,
                           EfiBootServicesData,
                           (EFI_PHYSICAL_ADDRESS)0x10000000,
                           4096,
                           EFI_MEMORY_WB);

    Temp32 = 0x10000000;
    Temp321 = 0x10400007;
    for (i=0;i<256;i++) {
        *(UINT32 *)(Temp32+i*4) = Temp321 + i*0x1000;    // First page directory maps to first page table at 260MB
        // PrintString("Address = ");
        // PrintValue(Temp32+i*4);
        // PrintString("        Value = ");
        // PrintValue(*(UINT32 *)(Temp32+i*4));  0x0A0 00 000  0x00 0010 1000  28
        // PrintString("\n");
        // if(i%32 == 0) ClearScreen();
    }

    // Now fill each of the page tables up
 
    Temp32 = 0x10400000;
    Temp321 = 0x07;
    for (i=0;i<(256*1024);i++) {    
        // Do it for each page table containing 1K entries and then do same for 256 page tables
	// First page directory maps to first page table at 260MB
        *(UINT32 *)(Temp32+i*4) = Temp321 + i*0x1000;    
        // PrintString("Address = ");
        // PrintValue(Temp32+i*4);
        // PrintString("        Value = ");
        // PrintValue(*(UINT32 *)(Temp32+i*4));
        // PrintString("\n");
        // Delay(1);
        // if(i%32 == 0) ClearScreen();
    }

    // Now add the page directory base address to CR3 (PDBR)
    // PDBR should be set to 0x10000000
    //

    // PrintString("Page Directory and page tables set up \n");    // From now use the paged addresses
    // PrintString("Going to enable CR3 register with the PDBR Value\n");    // From now use the paged addresses
    // Delay(1);


    Temp32 = 0x10000000;
    __asm mov eax, Temp32
    __asm mov cr3, eax
    __asm mov eax, cr0
    __asm or eax, 0x80000000
    __asm mov cr0, eax

    // Resets possibly because the addressing mappings have changed now and the processor is executing 
    // some other code at some other location as now the same EIP will point to some other memory location
    // Need to find out if that is the case and if so, what to the OS folks do...
    __asm {
        jmp d			/* flush the prefetch-queue */
 
        d:
            nop
            nop
            mov eax, ChangeIP
            jmp eax		/* make sure eip is relocated */
        ChangeIP:

    }

    // PrintString("Checking if Paging enabled\n ");   
    __asm mov eax, cr0
    __asm mov Temp32, eax
    if (Temp32 & 0x80000000) {
        PrintString("Paging has been enabled\n");   
        // Delay(1);
    }
    else {
        PrintString("Paging is still disabled\n");   
        Delay(1);
    }
}


EFI_STATUS
LoadPeImage (
    IN VOID                     *FHand,
    IN LOADED_IMAGE             *Image,
    IN UINT32                   *NumberOfMemoryMapEntries,
    IN EFI_MEMORY_DESCRIPTOR    *EfiMemoryDescriptor
    )
{
    IMAGE_DOS_HEADER            DosHdr;
    IMAGE_NT_HEADERS            PeHdr;
    IMAGE_SECTION_HEADER        *FirstSection;
    IMAGE_SECTION_HEADER        *Section;
    UINTN                       Index;
    EFI_STATUS                  Status;
    CHAR8                       *Base, *End;
    EFI_PHYSICAL_ADDRESS        MaxPhysicalStart;
    UINT64                      MaxNoPages;
    IMAGE_DATA_DIRECTORY        *DirectoryEntry;
    UINTN                       DirCount;
    IMAGE_DEBUG_DIRECTORY_ENTRY TempDebugEntry;
    IMAGE_DEBUG_DIRECTORY_ENTRY *DebugEntry;
    UINTN                       CodeViewSize;
    UINTN                       CodeViewOffset;
    UINTN                       CodeViewFileOffset=0;

    EFILDRZeroMem (&DosHdr, sizeof(DosHdr));
    EFILDRZeroMem (&PeHdr, sizeof(PeHdr));

    //
    // Read image headers
    //

    ImageRead (FHand, 0, sizeof(IMAGE_DOS_HEADER), &DosHdr);
    if (DosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        PrintString("LoadPeImage: Dos header signature not found\n");
        *(UINT8 *)(0x000b8000+20) = 'F';
        return EFI_UNSUPPORTED;
    }

    ImageRead (FHand, DosHdr.e_lfanew, sizeof(IMAGE_NT_HEADERS), &PeHdr);

    if (PeHdr.Signature != IMAGE_NT_SIGNATURE) {
        PrintString("LoadPeImage: PE image header signature not found\n");
        *(UINT8 *)(0x000b8000+22) = 'G';
        return EFI_UNSUPPORTED;
    }
    
    //
    // Set the image subsystem type
    //

    Status = SetImageType (Image, PeHdr.OptionalHeader.Subsystem);
    if (EFI_ERROR(Status)) {
        PrintString("LoadPeImage: Subsystem type not known\n");
        *(UINT8 *)(0x000b8000+24) = 'H';
        return Status;
    }

    //
    // Verify machine type
    //

    Status = CheckImageMachineType (PeHdr.FileHeader.Machine);
    if (EFI_ERROR(Status)) {
        PrintString("LoadPeImage: Incorrect machine type\n");
        *(UINT8 *)(0x000b8000+26) = 'I';
        return Status;
    }

    //
    // Compute the amount of memory needed to load the image and 
    // allocate it.  This will include all sections plus the codeview debug info.
    // Since the codeview info is actually outside of the image, we calculate
    // its size seperately and add it to the total.
    //
    // Memory starts off as data
    //

    CodeViewSize = 0;
    DirectoryEntry = (IMAGE_DATA_DIRECTORY *)&(PeHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]);
    for (DirCount = 0; 
         (DirCount < DirectoryEntry->Size / sizeof (IMAGE_DEBUG_DIRECTORY_ENTRY)) && CodeViewSize == 0; 
         DirCount++) {
      Status = ImageRead (FHand, 
                        DirectoryEntry->VirtualAddress + DirCount * sizeof (IMAGE_DEBUG_DIRECTORY_ENTRY),
                        sizeof (IMAGE_DEBUG_DIRECTORY_ENTRY),
                        &TempDebugEntry);
      if (!EFI_ERROR (Status)) {
        if (TempDebugEntry.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
          CodeViewSize = TempDebugEntry.SizeOfData;
          CodeViewFileOffset = TempDebugEntry.FileOffset;
        }
      }
    }
    
    CodeViewOffset = PeHdr.OptionalHeader.SizeOfImage + PeHdr.OptionalHeader.SectionAlignment;
    Image->NoPages = EFI_SIZE_TO_PAGES (CodeViewOffset + CodeViewSize);


    //
    // Compute the amount of memory needed to load the image and 
    // allocate it.  Memory starts off as data
    //
    MaxPhysicalStart = 0xB400000;        // Load it at 0xB400000   180 MB for now
    MaxNoPages = 10;
    if (MaxPhysicalStart == 0) {
      PrintString("MaxPhysicalStart = 0\n");
      return EFI_OUT_OF_RESOURCES;
    }

    Image->ImageBasePage = MaxPhysicalStart + (((UINT32)MaxNoPages - (Image->NoPages + 1)) << EFI_PAGE_SHIFT);

    //
    // Add a memory descriptor for the EFI Core Firmware
    //
    EfiAddMemoryDescriptor(
      NumberOfMemoryMapEntries,
      EfiMemoryDescriptor,
      EfiRuntimeServicesCode,
      (EFI_PHYSICAL_ADDRESS)(Image->ImageBasePage),
      Image->NoPages,
      EFI_MEMORY_WB
      );

    //
    // Add a memory descriptor for the EFI Firmware Stack
    //
    EfiAddMemoryDescriptor(
      NumberOfMemoryMapEntries,
      EfiMemoryDescriptor,
      EfiBootServicesData,
      (EFI_PHYSICAL_ADDRESS)(Image->ImageBasePage-EFI_MAX_STACK_SIZE),
      EFI_MAX_STACK_SIZE/EFI_PAGE_SIZE,
      EFI_MEMORY_WB
      );

    if (EFI_ERROR(Status)) {
        *(UINT8 *)(0x000b8000+28) = 'J';
        return Status;
    }

//    DEBUG((D_LOAD, "LoadPe: new image base %lx\n", Image->ImageBasePage));
    Image->Info.ImageBase = (VOID *) Image->ImageBasePage;
    Image->Info.ImageSize = (Image->NoPages << EFI_PAGE_SHIFT) - 1;
    Image->ImageBase = (CHAR8 *) Image->ImageBasePage;
    Image->ImageEof  = Image->ImageBase + Image->Info.ImageSize;
    Image->ImageAdjust = Image->ImageBase;

    //
    // Copy the Image header to the base location
    //
    Status = ImageRead (
                FHand, 
                0, 
                PeHdr.OptionalHeader.SizeOfHeaders, 
                Image->ImageBase
                );

    if (EFI_ERROR(Status)) {
        *(UINT8 *)(0x000b8000+30) = 'K';
        PrintString("Error in ImageRead\n");
        return Status;
    }

    //
    // Load each directory of the image into memory... 
    //  Save the address of the Debug directory for later
    //
    DebugEntry = NULL;
    for (Index = 0; Index < PeHdr.OptionalHeader.NumberOfRvaAndSizes; Index++) {
      if (PeHdr.OptionalHeader.DataDirectory[Index].VirtualAddress != 0 &&
          PeHdr.OptionalHeader.DataDirectory[Index].Size != 0 ) {
        Status = ImageRead (
                    FHand,
                    PeHdr.OptionalHeader.DataDirectory[Index].VirtualAddress,
                    PeHdr.OptionalHeader.DataDirectory[Index].Size,
                    Image->ImageBase + PeHdr.OptionalHeader.DataDirectory[Index].VirtualAddress
                    );
        if (EFI_ERROR(Status)) {
          return Status;
        }
        if (Index == IMAGE_DIRECTORY_ENTRY_DEBUG) {
          DebugEntry = (IMAGE_DEBUG_DIRECTORY_ENTRY *) (Image->ImageBase + PeHdr.OptionalHeader.DataDirectory[Index].VirtualAddress);
        }
      }
    }

    //
    // Load each section of the image
    //

    // BUGBUG: change this to use the in memory copy

    FirstSection = (IMAGE_SECTION_HEADER *) (
                        Image->ImageBase +
                        DosHdr.e_lfanew + 
                        sizeof(PeHdr) + 
                        PeHdr.FileHeader.SizeOfOptionalHeader - 
                        sizeof (IMAGE_OPTIONAL_HEADER)
                        );

    Section = FirstSection;
    for (Index=0; Index < PeHdr.FileHeader.NumberOfSections; Index += 1) {

        //
        // Compute sections address
        //

        Base = ImageAddress(Image, Section->VirtualAddress);
        End = ImageAddress(Image, Section->VirtualAddress + Section->Misc.VirtualSize);
        
        if (EFI_ERROR(Status) || !Base  ||  !End) {
            PrintString("LoadPe: Section  was not loaded\n");
            *(UINT8 *)(0x000b8000+32) = 'L';
            return EFI_LOAD_ERROR;
        }

        //
        // Read the section
        //
 
        if (Section->SizeOfRawData) {
            Status = ImageRead (FHand, Section->PointerToRawData, Section->SizeOfRawData, Base);
            if (EFI_ERROR(Status)) {
                PrintString("Image Read error \n");
                *(UINT8 *)(0x000b8000+34) = 'M';
                return Status;
            }
        }

        //
        // If raw size is less then virt size, zero fill the remaining
        //

        if (Section->SizeOfRawData < Section->Misc.VirtualSize) {
            EFILDRZeroMem (
                Base + Section->SizeOfRawData, 
                Section->Misc.VirtualSize - Section->SizeOfRawData
                );
        }

        //
        // Next Section
        //

        Section += 1;
    }

    //
    // Copy in CodeView information if it exists
    //
    if (CodeViewSize != 0) {
      Status = ImageRead (FHand, CodeViewFileOffset, CodeViewSize, Image->ImageBase + CodeViewOffset);
      DebugEntry->RVA = (UINT32) (CodeViewOffset);
    }

    //
    // Apply relocations only if needed
    //
    if((UINTN)(Image->ImageBase) != (UINTN) (PeHdr.OptionalHeader.ImageBase)) {
        Status = LoadPeRelocate (
                Image,
                &PeHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC],
                (UINTN) Image->ImageBase - PeHdr.OptionalHeader.ImageBase
                );

        if (EFI_ERROR(Status)) {
            PrintString("Load PE Relocate\n");
            *(UINT8 *)(0x000b8000+36) = 'N';
            return Status;
        }
    }

    //
    // Use exported EFI specific interface if present, else use the image's entry point
    //
    Image->EntryPoint = (EFI_IMAGE_ENTRY_POINT) 
                            (ImageAddress(
                                Image, 
                                PeHdr.OptionalHeader.AddressOfEntryPoint
                                ));

    return Status;
}


static
EFI_STATUS
LoadPeRelocate (
    IN LOADED_IMAGE             *Image,
    IN IMAGE_DATA_DIRECTORY     *RelocDir,
    IN UINTN                     Adjust
    )
{
    IMAGE_BASE_RELOCATION       *RelocBase, *RelocBaseEnd;
    UINT16                      *Reloc, *RelocEnd;
    CHAR8                       *Fixup, *FixupBase;

    //
    // Find the relocation block
    //

    RelocBase = ImageAddress(Image, RelocDir->VirtualAddress);
    RelocBaseEnd = ImageAddress(Image, RelocDir->VirtualAddress + RelocDir->Size);
    if (!RelocBase || !RelocBaseEnd) {
        *(UINT8 *)(0x000b8000+22) = 'O';
        return EFI_LOAD_ERROR;
    }

    //
    // Run the whole relocation block
    //

    while (RelocBase < RelocBaseEnd) {
           
        Reloc = (UINT16 *) ((CHAR8 *) RelocBase + sizeof(IMAGE_BASE_RELOCATION));
        RelocEnd = (UINT16 *) ((CHAR8 *) RelocBase + RelocBase->SizeOfBlock);
        if ((CHAR8 *) RelocEnd < Image->ImageBase || (CHAR8 *) RelocEnd > Image->ImageEof) {
            *(UINT8 *)(0x000b8000+22) = 'P';
            return EFI_LOAD_ERROR;
        }

        FixupBase = ImageAddress (Image, RelocBase->VirtualAddress);

        //
        // Run this relocation record
        //

        while (Reloc < RelocEnd) {

            Fixup = FixupBase + (*Reloc & 0xFFF);
            switch ((*Reloc) >> 12) {

            case IMAGE_REL_BASED_ABSOLUTE:
                break;

            case IMAGE_REL_BASED_HIGH:
                *(UINT16 *) Fixup = (UINT16) (((*(UINT16 *) Fixup) << 16) + Adjust);
                break;

            case IMAGE_REL_BASED_LOW:
                *(UINT16 *) Fixup = (UINT16)((*(UINT16 *) Fixup) + Adjust);
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                *(UINT32 *) Fixup = (*(UINT32 *) Fixup) + Adjust;
                break;

            case IMAGE_REL_BASED_HIGHADJ:
                BREAKPOINT();                 // BUGBUG: not done
                break;

            default:
                *(UINT8 *)(0x000b8000+22) = 'Q';
                return EFI_LOAD_ERROR;
            }

            // Next reloc record
            Reloc += 1;
        }

        // next reloc block
        RelocBase = (IMAGE_BASE_RELOCATION *) RelocEnd;
    }

    return EFI_SUCCESS;
}


static
EFI_STATUS
ImageRead (
    IN VOID                 *FHand,
    IN UINTN                Offset,
    IN OUT UINTN            ReadSize,
    OUT VOID                *Buffer
    )
// Load some data from the image
{
    EFILDRCopyMem(Buffer,(VOID *)((UINT32)FHand + Offset),ReadSize);

    return EFI_SUCCESS;
}


static
VOID *
ImageAddress (
    IN LOADED_IMAGE     *Image,
    IN UINTN            Address
    )
// Convert an image address to the loaded address
{
    CHAR8        *p;

    p = Image->ImageAdjust + Address;

    if (p < Image->ImageBase || p > Image->ImageEof) {
        PrintString("Error: ImageAddress: pointer is outside of image\n");
        p = NULL;
    }

    return p;
}


EFI_STATUS
SetImageType (
    IN OUT LOADED_IMAGE             *Image,
    IN UINTN                        ImageType
    )
{
    EFI_MEMORY_TYPE                 CodeType, DataType;

    switch (ImageType) {
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
        CodeType = EfiLoaderCode;
        DataType = EfiLoaderData;
        break;

    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
        CodeType = EfiBootServicesCode;
        DataType = EfiBootServicesData;
        break;

    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
        CodeType = EfiRuntimeServicesCode;
        DataType = EfiRuntimeServicesData;
        break;
    default:
        return EFI_INVALID_PARAMETER;
    }

    Image->Type = ImageType;
    Image->Info.ImageCodeType = CodeType;    
    Image->Info.ImageDataType = DataType;
    return EFI_SUCCESS;
}

EFI_STATUS
CheckImageMachineType (
    IN UINTN            MachineType
    )
// Determine if machine type is supported by the local machine
{
    EFI_STATUS          Status;

    Status = EFI_UNSUPPORTED;

#if EFI32
    if (MachineType == EFI_IMAGE_MACHINE_IA32) {
        Status = EFI_SUCCESS;
    }
#endif
    
#if EFI64
    if (MachineType == EFI_IMAGE_MACHINE_IA64) {
        Status = EFI_SUCCESS;
    }
#endif

#if EFI_FCODE
    if (MachineType == EFI_IMAGE_MACHINE_FCODE) {
        Status = EFI_SUCCESS;
    }
#endif

    return Status;
}

