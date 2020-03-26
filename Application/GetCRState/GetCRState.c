
#include "Efi.h"

//******************** Defines ********************//
typedef enum
{
  EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP, CR0, CR2, CR3, CR4, DR0, DR1, DR2, DR3, DR6, DR7, EFLAGS
} REGISTER;

typedef enum
{
  CS, DS, SS, ES, FS, GS
} SELECTOR;

typedef enum
{
  IDT, GDT
} TABLE;

//******************** Structs ********************//


//******************** Prototypes ********************//
UINT32 GetRegVal(REGISTER Register);
UINT16 GetSelVal(SELECTOR Selector);
UINT32 GetTableBase(TABLE Table);
UINT16 GetTableLimit(TABLE Table);

//******************** Main function ********************//

#ifdef EFI_BOOTSHELL
EFI_DRIVER_ENTRY_POINT(InitializeGetCRState)
#endif

EFI_STATUS InitializeGetCRState (
  )
{

    UINT32 Value;
    ClearScreen();

    PrintString("--------------------------------------------------------------------------------");
    PrintString("--------------------------------------------------------------------------------");
    PrintString("---------------                                          -----------------------");
    PrintString("---------------     Executing the application now        -----------------------");
    PrintString("---------------     We are now in VMX non-root mode!     -----------------------");
    PrintString("---------------                                          -----------------------");
    PrintString("--------------------------------------------------------------------------------");
    PrintString("------------                                                --------------------");
    PrintString("------------     This Application reads and prints the      --------------------");
    PrintString("------------     various system register values             --------------------");
    PrintString("------------     This should trigger a VM Exit when the     --------------------");
    PrintString("------------     application tries to read CR3              --------------------");
    PrintString("------------     This causes the VMM to get control,        --------------------");
    PrintString("------------     handle the exit and return control         --------------------");
    PrintString("------------     to the app.                                --------------------");
    PrintString("------------     Thus the VMM can keep track of             --------------------");
    PrintString("------------     the number of CR3 accesses                 --------------------");
    PrintString("------------                                                --------------------");
    PrintString("--------------------------------------------------------------------------------");
    PrintString("--------------------------------------------------------------------------------");
    Delay(1);
    Delay(1);
    PrintString("\n\nClearing Screen....\n");
    Delay(1);
    ClearScreen();
    PrintString("eax = ");
    Value = GetRegVal(EAX);
    PrintValue(Value);
    PrintString("\n");
    Delay(1);

    PrintString("ebx = ");
    Value = GetRegVal(EBX);
    PrintValue(Value);
    PrintString("\n");

    PrintString("ecx = ");
    Value = GetRegVal(ECX);
    PrintValue(Value);
    PrintString("\n");

    PrintString("edx = ");
    Value = GetRegVal(EDX);
    PrintValue(Value);
    PrintString("\n");

    PrintString("esi = ");
    Value = GetRegVal(ESI);
    PrintValue(Value);
    PrintString("\n");

    PrintString("edi = ");
    Value = GetRegVal(EDI);
    PrintValue(Value);
    PrintString("\n");

    PrintString("ebp = ");
    Value = GetRegVal(EBP);
    PrintValue(Value);
    PrintString("\n");

    PrintString("esp = ");
    Value = GetRegVal(ESP);
    PrintValue(Value);
    PrintString("\n");
    PrintString("\n");

    PrintString("CRO = ");
    Value = GetRegVal(CR0);
    PrintValue(Value);
    PrintString("\n");

    PrintString("CR2 = ");
    Value = GetRegVal(CR2);
    PrintValue(Value);
    PrintString("\n");

    PrintString("CR3 = ");
    Value = GetRegVal(CR3);
    PrintValue(Value);
    PrintString("\n");

    PrintString("CR4 = ");
    Value = GetRegVal(CR4);
    PrintValue(Value);
    PrintString("\n");

    PrintString("\n");
    PrintString("\n");
    PrintString("The program has finished execution and is now in a deadloop\n");

    for(;;);
    return EFI_SUCCESS;
}

//********************  ********************//

UINT32 GetRegVal(
  REGISTER Register)
{
  UINT32 Value = 0;

  switch (Register)
  {
    case EAX:
      __asm mov Value, eax
      break;
    case EBX:
      __asm mov Value, ebx
      break;
    case ECX:
      __asm mov Value, ecx
      break;
    case EDX:
      __asm mov Value, edx
      break;

    case ESI:
      __asm mov Value, esi
      break;
    case EDI:
      __asm mov Value, edi
      break;
    case EBP:
      __asm mov Value, ebp
      break;
    case ESP:
      __asm mov Value, esp
      break;

    case CR0:
      __asm mov eax, cr0
      __asm mov Value, eax
      break;
    case CR2:
      __asm mov eax, cr2
      __asm mov Value, eax
      break;
    case CR3:
      __asm mov eax, cr3
      __asm mov Value, eax
      break;
    case CR4:
      //__asm mov eax, cr4
      __asm _emit 0x0F
      __asm _emit 0x20
      __asm _emit 0x20
      __asm mov Value, eax
      break;

    case EFLAGS:
      __asm pushfd
      __asm pop Value
      break;

    case DR0:
      __asm mov eax, cr0
      __asm mov Value, eax
      break;
    case DR1:
      __asm mov eax, dr1
      __asm mov Value, eax
      break;
    case DR2:
      __asm mov eax, dr2
      __asm mov Value, eax
      break;
    case DR3:
      __asm mov eax, dr3
      __asm mov Value, eax
      break;
    case DR6:
      __asm mov eax, dr6
      __asm mov Value, eax
      break;
    case DR7:
      __asm mov eax, dr7
      __asm mov Value, eax
      break;

    default:
      break;
  }

  return Value;
}

UINT16 GetSelVal(
  SELECTOR Selector)
{
  UINT16 Value = 0;

  switch (Selector)
  {
    case CS:
      __asm mov Value, cs
      break;
    case DS:
      __asm mov Value, ds
      break;
    case SS:
      __asm mov Value, ss
      break;
    case ES:
      __asm mov Value, es
      break;
    case FS:
      __asm mov Value, fs
      break;
    case GS:
      __asm mov Value, gs
      break;

    default:
      break;
  }

  return Value;
}

UINT32 GetTableBase(
  TABLE Table)
{
  UINT8 Buffer[6];

  switch (Table)
  {
    case IDT:
      __asm sidt Buffer
      break;
    case GDT:
      __asm sgdt Buffer
      break;

    default:
      break;
  }

  return *(UINT32*)&Buffer[2];
}

UINT16 GetTableLimit(
  TABLE Table)
{
  UINT8 Buffer[6];

  switch (Table)
  {
    case IDT:
      __asm sidt Buffer
      break;
    case GDT:
      __asm sgdt Buffer
      break;

    default:
      break;
  }

  return *(UINT16*)Buffer;
}

