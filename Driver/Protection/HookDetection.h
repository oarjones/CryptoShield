#pragma once

#ifndef _HOOK_DETECTION_H_
#define _HOOK_DETECTION_H_

#include "../CryptoShield.h" // Incluimos la cabecera principal

// --- Estructuras para la obtención de módulos del sistema ---
// Estas definiciones son necesarias para ZwQuerySystemInformation.
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

// --- Estructura para la información del módulo del kernel ---
typedef struct _KERNEL_MODULE_INFO {
    PVOID BaseAddress;
    ULONG Size;
} KERNEL_MODULE_INFO, * PKERNEL_MODULE_INFO;

extern KERNEL_MODULE_INFO g_NtoskrnlInfo;

// --- Prototipos de Funciones ---
NTSTATUS GetNtoskrnlBoundaries(_Out_ PKERNEL_MODULE_INFO ModuleInfo);
NTSTATUS InitializeSdtTable(VOID);
NTSTATUS IsSdtHooked(_Out_ PBOOLEAN IsHooked);

#endif // _HOOK_DETECTION_H_