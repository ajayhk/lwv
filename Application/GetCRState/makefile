#    Copyright (c)  1999 - 2002 Intel Corporation. All rights reserved
#    This software and associated documentation (if any) is furnished
#    under a license and may only be used or copied in accordance
#    with the terms of the license. Except as permitted by such
#    license, no part of this software or documentation may be
#    reproduced, stored in a retrieval system, or transmitted in any
#    form or by any means without the express written consent of
#    Intel Corporation.
#


#
# Globals
#
ROOT_DIR = c:\lwv
#
# Set the processor type
#
PROCESSOR = IA32

APPS_SOURCE		= $(ROOT_DIR)\Application
BIN_DIR                 = $(ROOT_DIR)\Bin
TOOL_DIR	        = $(ROOT_DIR)\Tools
LIB_DIR		        = $(ROOT_DIR)\FV


SOURCE_DIR=$(APPS_SOURCE)\GetCRState
BUILD_DIR=$(APPS_SOURCE)\GetCRState

#######################################################################
# Assembler Flags
#######################################################################

MASM_FLAGS=/c /coff /Fl$*.lst

C_BUILD_FLAGS=/nologo /W3 /WX /Gm /GX /Zi /Od /GF /Gy 
L_BUILD_FLAGS=/nologo /MACHINE:IX86 /subsystem:console /NODEFAULTLIB /INCREMENTAL:NO /MAP /OPT:REF /DRIVER /ALIGN:16 
LIB_BUILD_FLAGS=output\Null.obj /nologo

#######################################################################
# IA32 Tools
#######################################################################

CC=cl
LINK=link
LIB=lib
MAKE=nmake -nologo
FWIMAGE=$(LIB_DIR)\FV

#######################################################################
# Convert environment variables to C defines
#######################################################################

C_STD_INCLUDE=/X
C_PROJ_FLAGS=/D EFI32 
!IF "$(EFI_DEBUG)" == "YES"
C_PROJ_FLAGS= $(C_PROJ_FLAGS) /D EFI_DEBUG 
L_PROJ_FLAGS= $(L_PROJ_FLAGS) /DEBUG
!ENDIF
!IF "$(EFI_DEBUG_CLEAR_MEMORY)" == "YES"
C_PROJ_FLAGS= $(C_PROJ_FLAGS) /D EFI_DEBUG_CLEAR_MEMORY
!ENDIF
!IF "$(EFI_BOOTSHELL)" == "YES"
C_PROJ_FLAGS= $(C_PROJ_FLAGS) /D EFI_BOOTSHELL 
!ENDIF
!IF "$(EFI_BOOTSHELL)" == "NO"
C_PROJ_FLAGS= $(C_PROJ_FLAGS) /D EFI_MONOSHELL 
!ENDIF

#######################################################################
# Compiler, Linker, and Librarian Tool Flags
#######################################################################

L_FLAGS=$(L_BUILD_FLAGS) $(L_PROJ_FLAGS)
C_FLAGS=$(C_BUILD_FLAGS) $(C_STD_INCLUDE) $(C_PROJ_FLAGS) $(INC)
LIB_FLAGS=$(LIB_BUILD_FLAGS) $(LIB_PROJ_FLAGS)


all : \
  $(BIN_DIR)\getcrstate.efi

#
# General make info
#

IMAGE_ENTRY_POINT=InitializeGetCRState
TARGET_APP=GetCRState


#
# Source file dependencies
#

$(BUILD_DIR)\getcrstate.obj : $(SOURCE_DIR)\GetCRState.c $(INC_DEPS)
	$(CC) $(C_FLAGS) $(MODULE_CFLAGS) /c $(SOURCE_DIR)\GetCRState.c 
#cl /nologo /W3 /WX /Gm /GX /Zi /Od /GF /Gy /c GetCRState.c

#
# Define the lib
#

TARGET_LIB = $(BUILD_DIR)\getcrstate.lib
BIN_TARGETS = $(BIN_TARGETS) $(TARGET_LIB)
$(TARGET_LIB) : getcrstate.obj
	$(LIB) getcrstate.obj /OUT:$(TARGET_LIB)
#	$(LIB) $(LIB_FLAGS) getcrstate.obj /OUT:$(TARGET_LIB)

#lib getcrstate.obj /nologo /OUT:getcrstate.lib


#
# Define for apps
#

TARGET_APP = $(BIN_DIR)\$(TARGET_APP).efi
BIN_TARGETS = $(BIN_TARGETS) $(TARGET_APP)
$(TARGET_APP) : $(TARGET_LIB) $(LIBS)
	$(LINK) getcrstate.obj $(L_FLAGS) $(MODULE_LFLAGS) $** /ENTRY:$(IMAGE_ENTRY_POINT) /OUT:GetCRState.dll
	
#fwimage.exe app $(@R).dll $(TARGET_APP)

#link getcrstate.obj /nologo /MACHINE:IX86 /subsystem:console /NODEFAULTLIB /INCREMENTAL:NO /MAP /OPT:REF /DRIVER /ALIGN:16  getcrstate.lib /ENTRY:GetCRState /OUT:getcrstate.dll

  - fwimage.exe app getcrstate.dll GetCRState.efi
  - copy GetCRState.efi $(LIB_DIR)\GetCRState.efi

#
clean :
  - @if exist vc??.* del vc??.* > NUL
  - @if exist *.obj del *.obj > NUL
  - @if exist *.lib del *.lib > NUL
  - @if exist *.efi del *.efi > NUL
  - @if exist *.dll del *.dll > NUL
  - @if exist *.obj del *.obj > NUL
  - @echo All targets cleaned

#
