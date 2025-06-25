/**
 * @file HookDetection.c
 * @brief Implementation of hook detection system (Monitor & Alert Model)
 * @details Detects and reports various types of kernel hooks.
 *
 * @author CryptoShield Team
 * @date 2025
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "HookDetection.h"
#include <ntstrsafe.h>

#define HOOK_DETECT_TAG 'kooH'

 // --- Prototipos de funciones estáticas ---
static PSYSTEM_SERVICE_TABLE GetSSDTBase(VOID);
static NTSTATUS GetIDTInfo(_Out_ PVOID* pIdtBase, _Out_ PUSHORT pIdtEntries);
static PVOID GetIdtEntryAddress(_In_ PIDT_ENTRY Entry);

// --- Implementación ---

// Rutina no documentada para buscar símbolos exportados. Se declara para poder usarla.
extern PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID DllBase, _In_ PCCH RoutineName);

/**
 * @brief Busca la System Service Descriptor Table (SSDT).
 */
PSYSTEM_SERVICE_TABLE GetSSDTBase(VOID)
{
    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"MmIsAddressValid");
    PVOID ntoskrnlHint = MmGetSystemRoutineAddress(&routineName);
    if (!ntoskrnlHint) {
        CS_LOG_ERROR("GetSSDTBase: Could not get a reference address in ntoskrnl.");
        return NULL;
    }

    PVOID ssdtAddress = RtlFindExportedRoutineByName(ntoskrnlHint, "KeServiceDescriptorTable");
    if (!ssdtAddress) {
        CS_LOG_WARNING("GetSSDTBase: Could not find KeServiceDescriptorTable. SSDT detection is disabled.");
        return NULL;
    }

    // Usar __try/__except para validar el puntero de forma segura en el kernel
    __try {
        if (((PSYSTEM_SERVICE_TABLE)ssdtAddress)->ServiceTableBase == NULL || ((PSYSTEM_SERVICE_TABLE)ssdtAddress)->NumberOfServices == 0) {
            CS_LOG_ERROR("GetSSDTBase: Found address appears to be invalid SSDT.");
            return NULL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        CS_LOG_ERROR("GetSSDTBase: Exception while validating SSDT pointer.");
        return NULL;
    }

    return (PSYSTEM_SERVICE_TABLE)ssdtAddress;
}

/**
 * @brief Obtiene la Interrupt Descriptor Table (IDT).
 */
NTSTATUS GetIDTInfo(_Out_ PVOID* pIdtBase, _Out_ PUSHORT pIdtEntries)
{
    IDT_DESCRIPTOR idtDescriptor = { 0 };
    PAGED_CODE();

    if (!pIdtBase || !pIdtEntries) return STATUS_INVALID_PARAMETER;
    __sidt(&idtDescriptor);

    if (idtDescriptor.Base == 0 || idtDescriptor.Limit == 0) return STATUS_UNSUCCESSFUL;
    *pIdtBase = (PVOID)idtDescriptor.Base;
    *pIdtEntries = (USHORT)((idtDescriptor.Limit + 1) / sizeof(IDT_ENTRY));
    return STATUS_SUCCESS;
}

/**
 * @brief Reconstruye la dirección del manejador de una entrada de la IDT.
 */
PVOID GetIdtEntryAddress(_In_ PIDT_ENTRY Entry)
{
    UINT64 address = Entry->OffsetLow | ((UINT64)Entry->OffsetMid << 16) | ((UINT64)Entry->OffsetHigh << 32);
    return (PVOID)address;
}

/**
 * @brief Inicializa el sistema de detección de hooks.
 */
NTSTATUS InitializeHookDetection(_In_ PPROTECTION_CONTEXT Context)
{
    PHOOK_DETECTION_CONTEXT detectionContext = NULL;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(Context);
    PAGED_CODE();

    DbgPrint("[CryptoShield] Initializing hook detection system\n");

    detectionContext = (PHOOK_DETECTION_CONTEXT)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(HOOK_DETECTION_CONTEXT), HOOK_DETECT_TAG);
    if (!detectionContext) {
        DbgPrint("[CryptoShield] Failed to allocate hook detection context\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(detectionContext, sizeof(HOOK_DETECTION_CONTEXT));

    status = ExInitializeResourceLite(&detectionContext->ScanResource);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(detectionContext, HOOK_DETECT_TAG);
        return status;
    }
    KeInitializeSpinLock(&detectionContext->DetectionLock);

    detectionContext->SsdtBase = GetSSDTBase();
    if (detectionContext->SsdtBase) {
        __try {
            detectionContext->SsdtEntries = (ULONG)detectionContext->SsdtBase->NumberOfServices;
            SIZE_T tableSize = detectionContext->SsdtEntries * sizeof(PVOID);
            detectionContext->OriginalSsdtTable = (PVOID*)ExAllocatePool2(POOL_FLAG_PAGED, tableSize, HOOK_DETECT_TAG);
            if (detectionContext->OriginalSsdtTable) {
                RtlCopyMemory(detectionContext->OriginalSsdtTable, detectionContext->SsdtBase->ServiceTableBase, tableSize);
            }
            else {
                detectionContext->SsdtBase = NULL;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            CS_LOG_ERROR("Exception accessing SSDT during initialization.");
            detectionContext->SsdtBase = NULL;
        }
    }

    status = GetIDTInfo((PVOID*)&detectionContext->IdtBase, &detectionContext->IdtEntries);
    if (!NT_SUCCESS(status)) {
        detectionContext->IdtBase = NULL;
    }

    return detectionContext;
}

/**
 * @brief Limpia los recursos del sistema de detección de hooks.
 */
VOID CleanupHookDetection(_In_ PHOOK_DETECTION_CONTEXT DetectionContext)
{
    if (!DetectionContext) return;
    PAGED_CODE();

    if (DetectionContext->OriginalSsdtTable) {
        ExFreePoolWithTag(DetectionContext->OriginalSsdtTable, HOOK_DETECT_TAG);
    }
    ExDeleteResourceLite(&DetectionContext->ScanResource);
    ExFreePoolWithTag(DetectionContext, HOOK_DETECT_TAG);
}

/**
 * @brief Detecta hooks en la SSDT.
 */
NTSTATUS DetectSSDTHooks(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _Out_writes_to_(MaxResults, *pDetectedCount) PHOOK_DETECTION_RESULT Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG pDetectedCount)
{
    if (!Context || !Results || !pDetectedCount || MaxResults == 0) return STATUS_INVALID_PARAMETER;
    *pDetectedCount = 0;

    if (!Context->SsdtBase || !Context->OriginalSsdtTable) return STATUS_NOT_SUPPORTED;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->ScanResource, TRUE);

    __try {
        LONG* serviceTable = (LONG*)Context->SsdtBase->ServiceTableBase;
        LONG* originalServiceTable = (LONG*)Context->OriginalSsdtTable;

        for (ULONG i = 0; i < Context->SsdtEntries && *pDetectedCount < MaxResults; i++) {
            PVOID currentHandler = (PVOID)((LONG_PTR)serviceTable + (serviceTable[i] >> 4));
            PVOID originalHandler = (PVOID)((LONG_PTR)serviceTable + (originalServiceTable[i] >> 4));

            if (currentHandler != originalHandler) {
                PHOOK_DETECTION_RESULT result = &Results[*pDetectedCount];
                RtlZeroMemory(result, sizeof(HOOK_DETECTION_RESULT));
                result->HookType = HOOK_TYPE_SSDT;
                result->HookedAddress = &serviceTable[i];
                result->HookHandler = currentHandler;
                result->IsMalicious = !IsValidKernelAddress(currentHandler);
                result->ConfidenceLevel = 95;
                result->IndexOrVector = i;
                RtlStringCbPrintfW(result->Description, sizeof(result->Description), L"SSDT[%lu] hooked. Handler: %p", i, currentHandler);
                (*pDetectedCount)++;
            }
        }
    }
    __finally {
        ExReleaseResourceLite(&Context->ScanResource);
        KeLeaveCriticalRegion();
    }
    return STATUS_SUCCESS;
}

/**
 * @brief Detecta hooks en la IDT.
 */
NTSTATUS DetectIDTHooks(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _Out_writes_to_(MaxResults, *pDetectedCount) PHOOK_DETECTION_RESULT Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG pDetectedCount)
{
    if (!Context || !Results || !pDetectedCount || MaxResults == 0) return STATUS_INVALID_PARAMETER;
    *pDetectedCount = 0;

    if (!Context->IdtBase) return STATUS_NOT_SUPPORTED;

    for (USHORT i = 0; i < Context->IdtEntries && *pDetectedCount < MaxResults; i++) {
        PVOID handlerAddress = GetIdtEntryAddress(&Context->IdtBase[i]);
        if (!IsValidKernelAddress(handlerAddress)) {
            PHOOK_DETECTION_RESULT result = &Results[*pDetectedCount];
            RtlZeroMemory(result, sizeof(HOOK_DETECTION_RESULT));
            result->HookType = HOOK_TYPE_IDT;
            result->HookedAddress = &Context->IdtBase[i];
            result->HookHandler = handlerAddress;
            result->IsMalicious = TRUE;
            result->ConfidenceLevel = 90;
            result->IndexOrVector = i;
            RtlStringCbPrintfW(result->Description, sizeof(result->Description), L"IDT Vector 0x%X hooked. Handler: %p", i, handlerAddress);
            (*pDetectedCount)++;
        }
    }
    return STATUS_SUCCESS;
}

/**
 * @brief Analiza el prólogo de una función para detectar hooks inline.
 */
BOOLEAN AnalyzeFunctionPrologue(_In_ PVOID FunctionAddress, _Out_ PVOID* pJumpTarget)
{
    if (!FunctionAddress || !pJumpTarget) return FALSE;
    __try {
        UCHAR* code = (UCHAR*)FunctionAddress;
        if (code[0] == 0xE9) {
            *pJumpTarget = (PVOID)((ULONG_PTR)FunctionAddress + 5 + *(LONG*)&code[1]);
            return TRUE;
        }
        if (code[0] == 0xFF && code[1] == 0x25) {
            *pJumpTarget = *(PVOID*)((ULONG_PTR)FunctionAddress + 6 + *(LONG*)&code[2]);
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return FALSE;
}

/**
 * @brief Verifica si una dirección pertenece a un módulo válido del kernel (simplificado).
 */
BOOLEAN IsValidKernelAddress(PVOID Address)
{
    if (!Address) return FALSE;
    return ((ULONG_PTR)Address >= 0xFFFF800000000000);
}

/**
 * @brief Obtiene estadísticas de detección de hooks.
 */
VOID GetHookDetectionStatistics(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _Out_opt_ PULONG TotalScans,
    _Out_opt_ PULONG HooksDetected)
{
    KIRQL oldIrql;
    if (!Context) return;

    KeAcquireSpinLock(&Context->DetectionLock, &oldIrql);
    if (TotalScans) *TotalScans = Context->TotalScans;
    if (HooksDetected) *HooksDetected = Context->HooksDetected;
    KeReleaseSpinLock(&Context->DetectionLock, oldIrql);
}