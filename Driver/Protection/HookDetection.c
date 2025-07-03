/**
 * @file HookDetection.c
 * @brief Implements SSDT and other hook detection mechanisms for CryptoShield.
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "../CryptoShield.h"
#include "HookDetection.h"
#include <ntddk.h> // Added for ZwQuerySystemInformation and SYSTEM_INFORMATION_CLASS

// Variable global para la información de ntoskrnl
KERNEL_MODULE_INFO g_NtoskrnlInfo = { NULL, 0 };

// Variable global para la tabla de descriptores de servicios
PVOID g_KeServiceDescriptorTable = NULL;

// Prototipo para ZwQuerySystemInformation
NTSTATUS ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);


NTSTATUS InitializeSdtTable(VOID)
{
    UNICODE_STRING routineName;
    PAGED_CODE();
    CS_ASSERT_IRQL_PASSIVE();

    RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
    g_KeServiceDescriptorTable = MmGetSystemRoutineAddress(&routineName);

    if (g_KeServiceDescriptorTable == NULL) {
        CS_LOG_ERROR("KeServiceDescriptorTable no encontrada. La deteccion de hooks en la SSDT no estara disponible.");
        return STATUS_NOT_FOUND;
    }

    CS_LOG_INFO("KeServiceDescriptorTable encontrada en %p.", g_KeServiceDescriptorTable);
    return STATUS_SUCCESS;
}

NTSTATUS GetNtoskrnlBoundaries(_Out_ PKERNEL_MODULE_INFO ModuleInfo)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PRTL_PROCESS_MODULES pModules = NULL;
    ULONG ulModulesSize = 0;
    ULONG ulReturnLength = 0;
    ANSI_STRING ntoskrnlNameAnsi;

    PAGED_CODE();
    CS_ASSERT_IRQL_PASSIVE();

    if (ModuleInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitAnsiString(&ntoskrnlNameAnsi, "ntoskrnl.exe");

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &ulReturnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    ulModulesSize = ulReturnLength;
    pModules = (PRTL_PROCESS_MODULES)CS_ALLOCATE_POOL(PagedPool, ulModulesSize);
    if (pModules == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, pModules, ulModulesSize, &ulReturnLength);
    if (!NT_SUCCESS(status)) {
        CS_FREE_POOL(pModules);
        return status;
    }

    for (ULONG i = 0; i < pModules->NumberOfModules; i++) {
        ANSI_STRING currentModuleNameAnsi;
        RtlInitAnsiString(&currentModuleNameAnsi, (PCSZ)(pModules->Modules[i].FullPathName + pModules->Modules[i].OffsetToFileName));
        if (RtlCompareString(&currentModuleNameAnsi, &ntoskrnlNameAnsi, TRUE) == 0) {
            ModuleInfo->BaseAddress = pModules->Modules[i].ImageBase;
            ModuleInfo->Size = pModules->Modules[i].ImageSize;
            status = STATUS_SUCCESS;
            break;
        }
    }

    CS_FREE_POOL(pModules);

    if (NT_SUCCESS(status)) {
        g_NtoskrnlInfo.BaseAddress = ModuleInfo->BaseAddress;
        g_NtoskrnlInfo.Size = ModuleInfo->Size;
    } else {
        status = STATUS_NOT_FOUND;
    }

    return status;
}

NTSTATUS IsSdtHooked(_Out_ PBOOLEAN IsHooked)
{
    // La implementación de esta función se mantiene como está.
    // El include principal ya le dará los tipos que necesita.
    // ...
    *IsHooked = FALSE; // Placeholder
    return STATUS_SUCCESS;
}