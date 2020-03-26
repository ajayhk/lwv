BUILD_DIR = c:\lwv
#
# Set the processor type
#
PROCESSOR = IA32

SOURCE		= $(BUILD_DIR)\SOURCE
BIN_DIR     = $(BUILD_DIR)\Bin
TOOL_DIR	= $(BUILD_DIR)\Tools
LIB_DIR		= $(BUILD_DIR)\FV

#
# Include Tools.env enviroment
#
!INCLUDE $(TOOL_DIR)\Tools.env

all : \
  $(BIN_DIR)\Bs32.com     \
  $(BIN_DIR)\Mbr.com      \
  $(BIN_DIR)\Start32.com  \
  $(BIN_DIR)\LoadLWV.com2 \
  $(BIN_DIR)\LWV          \
  $(BIN_DIR)\vmm          \
  tempstamp_file		  \

#
# Generate loader object
#
$(BIN_DIR)\Bs32.obj: $(SOURCE)\Bs32.asm
  $(ASM16) /c /omf /Fo$(BIN_DIR)\Bs32.obj $(SOURCE)\Bs32.asm 

$(BIN_DIR)\Bs32.com: $(BIN_DIR)\Bs32.obj
  cd $(BIN_DIR)
  $(ASMLINK16) /tiny Bs32.obj,Bs32.com,Bs32.map,,,

$(BIN_DIR)\Mbr.obj: $(SOURCE)\Mbr.asm
  $(ASM16) /c /omf /Fo$(BIN_DIR)\Mbr.obj $(SOURCE)\Mbr.asm 

$(BIN_DIR)\Mbr.com: $(BIN_DIR)\Mbr.obj
  cd $(BIN_DIR)
  $(ASMLINK16) /tiny Mbr.obj,Mbr.com,Mbr.map,,,

$(BIN_DIR)\Start32.obj: $(SOURCE)\Start32.asm
  $(ASM16) /c /omf /Fo$(BIN_DIR)\Start32.obj $(SOURCE)\Start32.asm 

$(BIN_DIR)\Start32.com: $(BIN_DIR)\Start32.obj
  cd $(BIN_DIR)
  $(ASMLINK16) /tiny Start32.obj,Start32.com,Start32.map,,,

$(BIN_DIR)\LoadLWV.obj: $(SOURCE)\LoadLWV.asm
  $(ASM16) /c /omf /Fo$(BIN_DIR)\LoadLWV.obj $(SOURCE)\LoadLWV.asm 

$(BIN_DIR)\LoadLWV.com: $(BIN_DIR)\LoadLWV.obj $(SOURCE)\LoadLWV.asm
  cd $(BIN_DIR)
  $(ASMLINK16) /tiny LoadLWV.obj,LoadLWV.com,LoadLWV.map,,,

$(BIN_DIR)\LoadLWV.com2: $(BIN_DIR)\LoadLWV.com $(SOURCE)\LoadLWV.asm
  $(TOOL_DIR)\Splitfile $(BIN_DIR)\LoadLWV.com 135168

$(BIN_DIR)\LWV.obj: $(SOURCE)\LoadLWV.asm
  $(CC) $(C_FLAGS) $(SOURCE)\LWV.c

$(BIN_DIR)\LWV.dll: $(BIN_DIR)\LWV.obj
  $(LINK) /nologo /MACHINE:X86 /SUBSYSTEM:CONSOLE /NODEFAULTLIB /INCREMENTAL:NO \
          /MAP /FIXED /BASE:0x00010000 /OPT:REF /ALIGN:32 /MERGE:.data=.text \
          /MERGE:.rdata=.text /DRIVER /ENTRY:EfiLoader $(BIN_DIR)\LWV.obj \
          /OUT:$(BIN_DIR)\LWV.dll /IGNORE:4078,4096

# $(LIB_DIR)\CompilerStub.lib $(BIN_DIR)\EfiCommonLib.lib $(BIN_DIR)\PeiLib.lib \

$(BIN_DIR)\LWV.efi: $(BIN_DIR)\LWV.dll
  $(TOOL_DIR)\FwImage app $(BIN_DIR)\LWV.dll $(BIN_DIR)\LWV.efi

$(BIN_DIR)\LWV: $(BIN_DIR)\LWV.efi 
  $(TOOL_DIR)\Efildrimage $(BIN_DIR)\LWV $(BIN_DIR)\LWV.efi $(LIB_DIR)\GetCRState.efi
  
#
# Generate loader binary
#
$(BIN_DIR)\vmm: $(BIN_DIR)\Start32.com $(BIN_DIR)\LoadLWV.com2
  copy /b $(BIN_DIR)\Start32.com+$(BIN_DIR)\LoadLWV.com2+$(BIN_DIR)\LWV $(BIN_DIR)\vmm


#
# Create a file to store the date and time, and used by SetStamp.exe
#
tempstamp_file:
!IF DEFINED(DATE_STAMP) && DEFINED(TIME_STAMP)
  @echo $(DATE_STAMP) $(TIME_STAMP) > GenStamp.txt
!ELSEIF EXIST(GenStamp.txt)
  - @del GenStamp.txt
!ENDIF


#
clean :
  - @if exist vc??.* del vc??.* > NUL
  - @if exist *.bak del *.bak > NUL
  - @if exist ia32 rd /s/q ia32 > NUL
  - @if exist fv rd /s /q fv > NUL
  - @if exist makefile.out del makefile.out > NUL
  - @if exist module.* del module.* > NUL
  - @if exist ..\bin\*.* del /q ..\bin\*.*
  - @echo All targets cleaned

#
# Clean up all build directories except for tools.
#
cleanbuilds :
  - @if exist *.bak del *.bak > NUL
  - @if exist ia32 rd /s/q ia32 > NUL
  - @if exist fv rd /s /q fv > NUL
  - @if exist makefile.out del makefile.out > NUL
  - @if exist module.* del module.* > NUL
  - @echo All modules cleaned

#
# Clean up only the tools
#
cleantools :
  - @if exist vc??.* del vc??.* > NUL
  - @if exist Tools rd /s /q Tools > NUL
  - @echo All tools cleaned

#
# Rebuild target, clean and build all
#
rebuild : clean all

#
# cleanall target to clean all build directories.
#
cleanall : clean

!IFNDEF BOOT_DISK
!MESSAGE BOOT_DISK environmental variable not set - e.g. set BOOT_DISK=e:, now assume h:
BOOT_DISK=h:
!ENDIF

usb32:
  -copy $(BIN_DIR)\vmm $(BOOT_DISK)\vmm /Y
  -move $(BOOT_DISK)\vmm $(BOOT_DISK)\efildr20 

DISK_LABEL=LWV

createusb32:
  @echo Format usb ...
  @echo.> FormatCommandInput.txt
  @echo.>> FormatCommandInput.txt
  @echo.n>> FormatCommandInput.txt
  format /FS:FAT32 /v:$(DISK_LABEL) /u /q $(BOOT_DISK) < FormatCommandInput.txt > NUL
  @del FormatCommandInput.txt
  @echo Create boot sector ...
  -$(TOOL_DIR)\Genbootsector -if=$(BOOT_DISK) -of=$(BIN_DIR)\UsbBs32.com
  -$(TOOL_DIR)\Bootsectimage -g $(BIN_DIR)\UsbBs32.com $(BIN_DIR)\Bs32.com
  -$(TOOL_DIR)\Bootsectimage -g $(BIN_DIR)\UsbBs32.com $(BIN_DIR)\vmm
  @del UsbBs32.com
  -$(TOOL_DIR)\Genbootsector -of=$(BOOT_DISK) -if=$(BIN_DIR)\Bs32.com
  -$(TOOL_DIR)\Genbootsector -mbr -of=$(BOOT_DISK) -if=$(BIN_DIR)\Mbr.com
  @echo Done. PLEASE UNPLUG USB, THEN PLUG IT AGAIN!

