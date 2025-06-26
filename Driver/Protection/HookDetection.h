/**
 * @file HookDetection.h
 * @brief Header file for SSDT and other hook detection mechanisms.
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include <ntifs.h> // For PVOID, BOOLEAN, etc.
#include <wdm.h>   // For ZwQuerySystemInformation

// Define SYSTEM_MODULE_INFORMATION structures (if not already available through includes)
// These are typically found in ntddk.h or undocumented headers. For safety, define them.

#ifndef RTL_PROCESS_MODULES
#define RTL_PROCESS_MODULES 24 // SystemModuleInformation

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
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#endif // RTL_PROCESS_MODULES


// Structure to hold ntoskrnl.exe's memory boundaries
typedef struct _KERNEL_MODULE_INFO {
    PVOID BaseAddress;
    ULONG Size;
} KERNEL_MODULE_INFO, *PKERNEL_MODULE_INFO;

extern KERNEL_MODULE_INFO g_NtoskrnlInfo; // Global to store ntoskrnl info

/**
 * @brief Retrieves the base address and size of ntoskrnl.exe.
 *
 * @param ModuleInfo Pointer to KERNEL_MODULE_INFO structure to be filled.
 * @return NTSTATUS Status of the operation. STATUS_SUCCESS on success.
 *
 * @note This function should be called at PASSIVE_LEVEL.
 */
NTSTATUS GetNtoskrnlBoundaries(
    _Out_ PKERNEL_MODULE_INFO ModuleInfo
);

/**
 * @brief Initializes SSDT related structures for hook detection.
 * @details Attempts to find KeServiceDescriptorTable. Should be called at PASSIVE_LEVEL.
 * @return NTSTATUS STATUS_SUCCESS if successful, otherwise an error code.
 */
NTSTATUS InitializeSdtTable(VOID);

/**
 * @brief Checks if the SSDT has been hooked.
 * @details Iterates through SSDT entries and checks if any service points outside ntoskrnl.exe.
 * @return BOOLEAN TRUE if a hook is detected, FALSE otherwise.
 * @warning This function should be called carefully, considering IRQL and SSDT access specifics.
 */
BOOLEAN IsSdtHooked(VOID);
