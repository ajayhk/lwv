/*++

Copyright (c) 2007 Ajay Harikumar. All rights reserved
This software and associated documentation (if any) is furnished
under a license and may only be used or copied in accordance
with the terms of the license. Except as permitted by such
license, no part of this software or documentation may be
reproduced, stored in a retrieval system, or transmitted in any
form or by any means without the express written consent of
Ajay Harikumar.


Module Name:

    vmx.h
    
Abstract:



Revision History

--*/

#define IA32_VMX_BASIC_MSR_CODE			0x480
#define IA32_FEATURE_CONTROL_CODE		0x03A

//////////////////
//              //
//  PROTOTYPES  //
//              //
//////////////////

typedef struct _VMX_FEATURES
{
	unsigned SSE3		:1;		// SSE3 Extensions
	unsigned RES1		:2;
	unsigned MONITOR	:1;		// MONITOR/WAIT
	unsigned DS_CPL		:1;		// CPL qualified Debug Store
	unsigned VMX		:1;		// Virtual Machine Technology
	unsigned RES2		:1;
	unsigned EST		:1;		// Enhanced Intel© Speedstep Technology
	unsigned TM2		:1;		// Thermal monitor 2
	unsigned SSSE3		:1;		// SSSE3 extensions
	unsigned CID		:1;		// L1 context ID
	unsigned RES3		:2;
	unsigned CX16		:1;		// CMPXCHG16B
	unsigned xTPR		:1;		// Update control
	unsigned PDCM		:1;		// Performance/Debug capability MSR
	unsigned RES4		:2;
	unsigned DCA		:1;
	unsigned RES5		:13;
	
} VMX_FEATURES;

//////////////
//          //
//  EFLAGS  //
//          //
//////////////
typedef struct _EFLAGS
{
	unsigned Reserved1	:10;
	unsigned ID			:1;		// Identification flag
	unsigned VIP		:1;		// Virtual interrupt pending
	unsigned VIF		:1;		// Virtual interrupt flag
	unsigned AC			:1;		// Alignment check
	unsigned VM			:1;		// Virtual 8086 mode
	unsigned RF			:1;		// Resume flag
	unsigned Reserved2	:1;
	unsigned NT			:1;		// Nested task flag
	unsigned IOPL		:2;		// I/O privilege level
	unsigned OF			:1;
	unsigned DF			:1;
	unsigned IF			:1;		// Interrupt flag
	unsigned TF			:1;		// Task flag
	unsigned SF			:1;		// Sign flag
	unsigned ZF			:1;		// Zero flag
	unsigned Reserved3	:1;
	unsigned AF			:1;		// Borrow flag
	unsigned Reserved4	:1;
	unsigned PF			:1;		// Parity flag
	unsigned Reserved5	:1;
	unsigned CF			:1;		// Carry flag [Bit 0]

} EFLAGS;

///////////
//       //
//  MSR  //
//       //
///////////
typedef struct _MSR
{
	UINT32		Hi;
	UINT32		Lo;

} MSR;

typedef struct _IA32_VMX_BASIC_MSR
{

	unsigned RevId			:32;	// Bits 31...0 contain the VMCS revision identifier
	unsigned szVmxOnRegion  :12;	// Bits 43...32 report # of bytes for VMXON region 
	unsigned RegionClear	:1;		// Bit 44 set only if bits 32-43 are clear
	unsigned Reserved1		:3;		// Undefined
	unsigned PhyAddrWidth	:1;		// Physical address width for referencing VMXON, VMCS, etc.
	unsigned DualMon		:1;		// Reports whether the processor supports dual-monitor
									// treatment of SMI and SMM
	unsigned MemType		:4;		// Memory type that the processor uses to access the VMCS
	unsigned VmExitReport	:1;		// Reports whether the procesor reports info in the VM-exit
									// instruction information field on VM exits due to execution
									// of the INS and OUTS instructions
	unsigned Reserved2		:9;		// Undefined

} IA32_VMX_BASIC_MSR;


typedef struct _IA32_FEATURE_CONTROL_MSR
{
	unsigned Lock			:1;		// Bit 0 is the lock bit - cannot be modified once lock is set
	unsigned Reserved1		:1;		// Undefined
	unsigned EnableVmxon	:1;		// Bit 2. If this bit is clear, VMXON causes a general protection exception
	unsigned Reserved2		:29;	// Undefined
	unsigned Reserved3		:32;	// Undefined

} IA32_FEATURE_CONTROL_MSR;

/////////////////
//             //
//  REGISTERS  //
//             //
/////////////////
typedef struct _CR0_REG
{
	unsigned PE			:1;			// Protected Mode Enabled [Bit 0]
	unsigned MP			:1;			// Monitor Coprocessor FLAG
	unsigned EM			:1;			// Emulate FLAG
	unsigned TS			:1;			// Task Switched FLAG
	unsigned ET			:1;			// Extension Type FLAG
	unsigned NE			:1;			// Numeric Error
	unsigned Reserved1	:10;		// 
	unsigned WP			:1;			// Write Protect
	unsigned Reserved2	:1;			// 
	unsigned AM			:1;			// Alignment Mask
	unsigned Reserved3	:10;		// 
	unsigned NW			:1;			// Not Write-Through
	unsigned CD			:1;			// Cache Disable
	unsigned PG			:1;			// Paging Enabled

} CR0_REG;

typedef struct _CR4_REG
{
	unsigned VME		:1;			// Virtual Mode Extensions
	unsigned PVI		:1;			// Protected-Mode Virtual Interrupts
	unsigned TSD		:1;			// Time Stamp Disable
	unsigned DE			:1;			// Debugging Extensions
	unsigned PSE		:1;			// Page Size Extensions
	unsigned PAE		:1;			// Physical Address Extension
	unsigned MCE		:1;			// Machine-Check Enable
	unsigned PGE		:1;			// Page Global Enable
	unsigned PCE		:1;			// Performance-Monitoring Counter Enable
	unsigned OSFXSR		:1;			// OS Support for FXSAVE/FXRSTOR
	unsigned OSXMMEXCPT	:1;			// OS Support for Unmasked SIMD Floating-Point Exceptions
	unsigned Reserved1	:2;			// 
	unsigned VMXE		:1;			// Virtual Machine Extensions Enabled
	unsigned Reserved2	:18;		// 

} CR4_REG;

typedef struct _MISC_DATA
{
	unsigned	Reserved1		:6;		// [0-5]
	unsigned	ActivityStates	:3;		// [6-8]
	unsigned	Reserved2		:7;		// [9-15]
	unsigned	CR3Targets		:9;		// [16-24]

	// 512*(N+1) is the recommended maximum number of MSRs
	unsigned	MaxMSRs			:3;		// [25-27]

	unsigned	Reserved3		:4;		// [28-31]
	unsigned	MSEGRevID		:32;	// [32-63]

} MISC_DATA;

/////////////////
//             //
//  SELECTORS  //
//             //
/////////////////
typedef struct _GDTR
{
	unsigned	Limit		:16;
	unsigned	BaseLo		:16;
	unsigned	BaseHi		:16;

} GDTR;

typedef struct _IDTR
{
	unsigned	Limit		:16;
	unsigned	BaseLo		:16;
	unsigned	BaseHi		:16;

} IDTR;

typedef struct	_SEG_DESCRIPTOR
{
	unsigned	LimitLo	:16;
	unsigned	BaseLo	:16;
	unsigned	BaseMid	:8;
	unsigned	Type	:4;
	unsigned	System	:1;
	unsigned	DPL		:2;
	unsigned	Present	:1;
	unsigned	LimitHi	:4;
	unsigned	AVL		:1;
	unsigned	L		:1;
	unsigned	DB		:1;
	unsigned	Gran	:1;		// Granularity
	unsigned	BaseHi	:8;
	
} SEG_DESCRIPTOR;

///////////
//       //
//  Log  //
//       //
///////////
#define Log( message, value ) { PrintString(message); PrintString("  =  "); PrintValue(value); PrintString(\n); }

///////////////
//           //
//  SET BIT  //
//           //
///////////////
VOID SetBit( UINT32 * dword, UINT32 bit )
{
	UINT32 mask = ( 1 << bit );
	*dword = *dword | mask;
}

/////////////////
//             //
//  CLEAR BIT  //
//             //
/////////////////
VOID ClearBit( UINT32 * dword, UINT32 bit )
{
	UINT32 mask = 0xFFFFFFFF;
	UINT32 sub = ( 1 << bit );
	mask = mask - sub;
	*dword = *dword & mask;
}

// Format of the VMCS Region
// Byte Offset Contents
// 0 VMCS revision identifier
// 4 VMX-abort indicator
// 8 VMCS data (implementation-specific format)


typedef struct {          
    UINT32                VMCSRevisionID;
    UINT32		  Data[511];  // Assume the entire structure is 4K
} VMCS_Structure;


UINT32 GetSegmentDescriptorBase( UINT32 gdt_base , UINT16 seg_selector )
{
	UINT32			base = 0;
        UINT32			Temp32 = 0;
        UINT32                  Temp1_32 =0;
        UINT32			Temp32Val = 0;
        UINT32                  Temp1_32Val =0;
 
        Temp32 = gdt_base + (seg_selector >> 3) * 8;
        Temp1_32 = (gdt_base + (seg_selector >> 3) * 8) + 4; 
	Temp32Val = *(UINT32*)Temp32;
	Temp1_32Val = *(UINT32*)Temp1_32;
        base = Temp1_32Val >> 24;
	base <<= 8;
        base |= (Temp1_32Val & 0x0FF);
	base <<= 16;
        base |= ((Temp32Val >> 16) & 0x0FFFF);
	return base;
}

UINT32 GetSegmentDescriptorDPL( UINT32 gdt_base , UINT16 seg_selector )
{
        UINT32          Temp32 = 0;
        UINT32          Temp1_32 = 0;
        UINT32          Temp1_32Val = 0;
	
        Temp1_32 = (gdt_base + (seg_selector >> 3) * 8) + 4; 
	Temp1_32Val = *(UINT32*)Temp1_32;
        Temp32 = Temp1_32Val & 0x06000;
        Temp1_32 = Temp32 >> 13;
	
	return Temp1_32;
}


UINT32 GetSegmentDescriptorLimit( UINT32 gdt_base , UINT16 seg_selector )
{
        UINT32          Temp32 = 0;
        UINT32          Temp1_32 = 0;
        UINT32          Temp32Val = 0;
        UINT32          Temp1_32Val = 0;
        UINT32          Temp2_32 = 0;
	
        Temp32 = gdt_base + (seg_selector >> 3) * 8;
	Temp32Val = *(UINT32*)Temp32;
        Temp1_32 = (gdt_base + (seg_selector >> 3) * 8) + 4; 
	Temp1_32Val = *(UINT32*)Temp1_32;
        Temp2_32 = Temp1_32Val & 0x0F0000;

        Temp1_32 = Temp32Val & 0x0FFFF;
        Temp2_32 |= Temp1_32;
        	
	return Temp2_32;
}


///////////////
//           //
//  Globals  //
//           //
///////////////
UINT32			*pVMXONRegion		= NULL;		// Memory address of VMXON region.
UINT32			*pVMCSRegion		= NULL;
UINT32			VMXONRegionSize		= 0;
UINT32			VMCSRegionSize		= 0;
UINT32			ErrorCode			= 0;

EFLAGS			eFlags				= {0};
MSR				msr					= {0};

void*		FakeStack				= NULL;

UINT32			HandlerLogging		= 0;
UINT32			ScrubTheLaunch		= 0;

//	Writes the contents of value into the VMCS region specified by the encoding
//	The encoding is copied into the eax and a VM Write is done with the value 
//	put in the stack. 
//
VOID WriteVMCS( UINT32 encoding, UINT32 value )
{
	__asm
	{
		PUSHAD
		
		PUSH	value
		MOV		EAX, encoding 

		_emit	0x0F				// VMWRITE EAX, [ESP]
		_emit	0x79
		_emit	0x04
		_emit	0x24
		
		POP EAX
		
		POPAD
	}
}


//	Loads the contents of a 64-bit model specific register (MSR) specified
//	in the ECX register into registers EDX:EAX. The EDX register is loaded
//	with the high-order 32 bits of the MSR and the EAX register is loaded
//	with the low-order 32 bits.
//		msr.Hi --> EDX
//		msr.Lo --> EAX
//
VOID ReadMSR( UINT32 msrEncoding )
{
	__asm
	{
		PUSHAD
			
		MOV		ECX, msrEncoding

		RDMSR

		MOV		msr.Hi, EDX
		MOV		msr.Lo, EAX

		POPAD
	}
}

//	Write the msr data structure into MSR specified by msrEncoding.
//		msr.Hi <-- EDX
//		msr.Lo <-- EAX
//
VOID WriteMSR( UINT32 msrEncoding )
{
	__asm
	{
		PUSHAD

		MOV		EDX, msr.Hi
		MOV		EAX, msr.Lo
		MOV		ECX, msrEncoding

		WRMSR

		POPAD
	}
}
EFI_PHYSICAL_ADDRESS			PhysicalVMXONRegionPtr;
EFI_PHYSICAL_ADDRESS			PhysicalVMCSRegionPtr;

VMX_FEATURES				vmxFeatures;
IA32_VMX_BASIC_MSR			vmxBasicMsr ;
IA32_FEATURE_CONTROL_MSR	vmxFeatureControl ;

CR0_REG						cr0_reg = {0};
CR4_REG						cr4_reg = {0};

UINT32						temp32 = 0;
UINT16						temp16 = 0;

GDTR						gdt_reg = {0};
IDTR						idt_reg = {0};

UINT32						gdt_base = 0;
UINT32						idt_base = 0;

UINT16						mLDT = 0;
UINT16						seg_selector = 0;

SEG_DESCRIPTOR				segDescriptor = {0};
MISC_DATA					misc_data = {0};

void*						GuestReturn = NULL;
UINT32						GuestStack = 0;

