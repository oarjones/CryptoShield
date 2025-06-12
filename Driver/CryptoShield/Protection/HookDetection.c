/**
 * @file HookDetection.c
 * @brief Implementation of hook detection and prevention system
 * @details Detects and prevents various types of kernel hooks and code modifications
 *
 * @author CryptoShield Team
 * @date 2025
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "HookDetection.h"
#include <ntstrsafe.h>

 // Memory allocation tag
#define HOOK_DETECT_TAG 'kooH'  // 'Hook' in little-endian

// x64 instruction opcodes
#define X64_JMP_REL32          0xE9
#define X64_JMP_ABS_FF25       0x25FF
#define X64_CALL_REL32         0xE8
#define X64_MOV_RAX            0xB848
#define X64_JMP_RAX            0xE0FF
#define X64_PUSH               0x68
#define X64_RET                0xC3
#define X64_NOP                0x90
#define X64_INT3               0xCC

// Common hook patterns
static const HOOK_PATTERN g_CommonHookPatterns[] = {
    // JMP rel32 pattern
    { { 0xE9, 0x00, 0x00, 0x00, 0x00 }, 5, 0, L"JMP rel32 hook", TRUE },
    // JMP [rip+offset] pattern
    { { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }, 6, 0, L"JMP indirect hook", TRUE },
    // MOV RAX, imm64; JMP RAX pattern
    { { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 }, 12, 0, L"MOV RAX; JMP RAX hook", TRUE },
    // PUSH addr; RET pattern
    { { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3 }, 6, 0, L"PUSH-RET hook", TRUE },
};

// Forward declarations
static PVOID GetSSDTBase(VOID);
static ULONG GetSSDTEntries(VOID);
static BOOLEAN IsAddressInValidModule(PVOID Address);
static NTSTATUS GetIDTInfo(PVOID* IdtBase, PULONG IdtEntries);

/**
 * @brief Initialize hook detection system
 */
PHOOK_DETECTION_CONTEXT InitializeHookDetection(
    _In_ PPROTECTION_CONTEXT Context)
{
    PHOOK_DETECTION_CONTEXT detectionContext;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);

    DbgPrint("[CryptoShield] Initializing hook detection system\n");

    // Allocate detection context
    /*detectionContext = (PHOOK_DETECTION_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(HOOK_DETECTION_CONTEXT),
        HOOK_DETECT_TAG
    );*/
    detectionContext = (PHOOK_DETECTION_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(HOOK_DETECTION_CONTEXT),
        HOOK_DETECT_TAG
    );

    if (!detectionContext) {
        DbgPrint("[CryptoShield] Failed to allocate hook detection context\n");
        return NULL;
    }

    RtlZeroMemory(detectionContext, sizeof(HOOK_DETECTION_CONTEXT));

    // Initialize synchronization
    KeInitializeSpinLock(&detectionContext->DetectionLock);
    status = ExInitializeResourceLite(&detectionContext->ScanResource);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[CryptoShield] Failed to initialize scan resource: 0x%08X\n", status);
        ExFreePoolWithTag(detectionContext, HOOK_DETECT_TAG);
        return NULL;
    }

    // Set default configuration
    detectionContext->DetectionMethods = HOOK_DETECT_ALL;
    detectionContext->EnableAutoRemoval = FALSE;  // Safer to not auto-remove
    detectionContext->EnableLogging = TRUE;

    // Get SSDT information
    detectionContext->SsdtBase = GetSSDTBase();
    detectionContext->SsdtEntries = GetSSDTEntries();

    if (detectionContext->SsdtBase) {
        DbgPrint("[CryptoShield] SSDT Base: %p, Entries: %lu\n",
            detectionContext->SsdtBase, detectionContext->SsdtEntries);

        // Allocate and save original SSDT
        /*detectionContext->OriginalSsdtTable = (PVOID*)ExAllocatePoolWithTag(
            NonPagedPool,
            detectionContext->SsdtEntries * sizeof(PVOID),
            HOOK_DETECT_TAG
        );*/
        detectionContext->OriginalSsdtTable = (PVOID*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            detectionContext->SsdtEntries * sizeof(PVOID),
            HOOK_DETECT_TAG
        );

        if (detectionContext->OriginalSsdtTable) {
            RtlCopyMemory(detectionContext->OriginalSsdtTable,
                detectionContext->SsdtBase,
                detectionContext->SsdtEntries * sizeof(PVOID));
        }
    }

    // Get IDT information
    GetIDTInfo(&detectionContext->IdtBase, &detectionContext->IdtEntries);

    // Initialize known patterns
    InitializeKnownPatterns(detectionContext);

    DbgPrint("[CryptoShield] Hook detection initialized. Patterns loaded: %lu\n",
        detectionContext->PatternCount);

    return detectionContext;
}

/**
 * @brief Cleanup hook detection system
 */
VOID CleanupHookDetection(
    _In_ PHOOK_DETECTION_CONTEXT DetectionContext)
{
    if (!DetectionContext) {
        return;
    }

    DbgPrint("[CryptoShield] Cleaning up hook detection system\n");

    // Free original SSDT table backup
    if (DetectionContext->OriginalSsdtTable) {
        ExFreePoolWithTag(DetectionContext->OriginalSsdtTable, HOOK_DETECT_TAG);
    }

    // Delete resource
    ExDeleteResourceLite(&DetectionContext->ScanResource);

    // Log final statistics
    DbgPrint("[CryptoShield] Hook Detection Statistics:\n");
    DbgPrint("  - Total scans: %lu\n", DetectionContext->TotalScans);
    DbgPrint("  - Hooks detected: %lu\n", DetectionContext->HooksDetected);
    DbgPrint("  - Hooks removed: %lu\n", DetectionContext->HooksRemoved);
    DbgPrint("  - False positives: %lu\n", DetectionContext->FalsePositives);

    // Free context
    ExFreePoolWithTag(DetectionContext, HOOK_DETECT_TAG);
}

/**
 * @brief Detect SSDT hooks
 */
NTSTATUS DetectSSDTHooks(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _Out_writes_(MaxResults) PHOOK_DETECTION_RESULT Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG DetectedCount)
{
    ULONG i, detected = 0;
    PVOID* currentSsdt;
    KIRQL oldIrql;

    if (!Context || !Results || !DetectedCount || MaxResults == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *DetectedCount = 0;

    if (!Context->SsdtBase || !Context->OriginalSsdtTable) {
        return STATUS_NOT_FOUND;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->ScanResource, TRUE);

    __try {
        currentSsdt = (PVOID*)Context->SsdtBase;

        for (i = 0; i < Context->SsdtEntries && detected < MaxResults; i++) {
            PVOID currentHandler = currentSsdt[i];
            PVOID originalHandler = Context->OriginalSsdtTable[i];

            // Check if handler has been modified
            if (currentHandler != originalHandler) {
                PHOOK_DETECTION_RESULT result = &Results[detected];

                RtlZeroMemory(result, sizeof(HOOK_DETECTION_RESULT));

                result->HookType = HOOK_TYPE_SSDT;
                result->HookedAddress = &currentSsdt[i];
                result->OriginalAddress = originalHandler;
                result->HookHandler = currentHandler;

                // Check if the new handler is in a valid module
                result->IsMalicious = !IsAddressInValidModule(currentHandler);
                result->ConfidenceLevel = result->IsMalicious ? 90 : 50;

                // Fill SSDT-specific info
                result->Details.SsdtInfo.ServiceIndex = i;
                result->Details.SsdtInfo.OriginalAddress = originalHandler;
                result->Details.SsdtInfo.CurrentAddress = currentHandler;
                result->Details.SsdtInfo.HookHandler = currentHandler;
                result->Details.SsdtInfo.IsHooked = TRUE;

                RtlStringCbPrintfW(result->Details.SsdtInfo.ServiceName,
                    sizeof(result->Details.SsdtInfo.ServiceName),
                    L"Service_%03X", i);

                RtlStringCbPrintfW(result->Description,
                    sizeof(result->Description),
                    L"SSDT[0x%03X] hooked: %p -> %p",
                    i, originalHandler, currentHandler);

                detected++;

                if (Context->EnableLogging) {
                    LogHookDetection(Context, result);
                }
            }
        }

        KeAcquireSpinLock(&Context->DetectionLock, &oldIrql);
        Context->TotalScans++;
        Context->HooksDetected += detected;
        KeReleaseSpinLock(&Context->DetectionLock, oldIrql);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception detecting SSDT hooks: 0x%08X\n",
            GetExceptionCode());
        ExReleaseResourceLite(&Context->ScanResource);
        KeLeaveCriticalRegion();
        return STATUS_UNHANDLED_EXCEPTION;
    }

    ExReleaseResourceLite(&Context->ScanResource);
    KeLeaveCriticalRegion();

    *DetectedCount = detected;

    return STATUS_SUCCESS;
}

/**
 * @brief Detect inline hooks in function
 */
BOOLEAN DetectInlineHooks(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ PVOID FunctionAddress,
    _Out_ PHOOK_DETECTION_RESULT Result)
{
    INLINE_HOOK_INFO hookInfo = { 0 };
    BOOLEAN isHooked = FALSE;

    if (!Context || !FunctionAddress || !Result) {
        return FALSE;
    }

    RtlZeroMemory(Result, sizeof(HOOK_DETECTION_RESULT));

    // Analyze function prologue
    if (AnalyzeFunctionPrologue(FunctionAddress, &hookInfo)) {
        isHooked = TRUE;

        Result->HookType = HOOK_TYPE_INLINE;
        Result->HookedAddress = FunctionAddress;
        Result->HookHandler = hookInfo.JumpTarget;
        Result->IsMalicious = !IsAddressInValidModule(hookInfo.JumpTarget);
        Result->ConfidenceLevel = hookInfo.IsHooked ? 85 : 40;

        // Copy inline hook details
        RtlCopyMemory(&Result->Details.InlineInfo, &hookInfo, sizeof(INLINE_HOOK_INFO));

        RtlStringCbPrintfW(Result->Description, sizeof(Result->Description),
            L"Inline hook detected at %p, jumping to %p",
            FunctionAddress, hookInfo.JumpTarget);

        if (Context->EnableLogging) {
            LogHookDetection(Context, Result);
        }
    }

    return isHooked;
}

/**
 * @brief Analyze function prologue for hooks
 */
BOOLEAN AnalyzeFunctionPrologue(
    _In_ PVOID FunctionAddress,
    _Out_ PINLINE_HOOK_INFO HookInfo)
{
    PUCHAR functionBytes;
    BOOLEAN isHooked = FALSE;

    if (!FunctionAddress || !HookInfo) {
        return FALSE;
    }

    RtlZeroMemory(HookInfo, sizeof(INLINE_HOOK_INFO));
    HookInfo->FunctionAddress = FunctionAddress;

    __try {
        functionBytes = (PUCHAR)FunctionAddress;

        // Copy first bytes for analysis
        RtlCopyMemory(HookInfo->CurrentBytes, functionBytes,
            min(MAX_INSTRUCTION_BYTES, 16));

        // Check for JMP rel32 (E9 XX XX XX XX)
        if (functionBytes[0] == X64_JMP_REL32) {
            LONG relativeOffset = *(PLONG)&functionBytes[1];
            HookInfo->JumpTarget = (PVOID)((PUCHAR)FunctionAddress + 5 + relativeOffset);
            HookInfo->HookedBytesCount = 5;
            HookInfo->IsHooked = TRUE;
            HookInfo->HookMethod = HOOK_TYPE_INLINE;
            isHooked = TRUE;
        }
        // Check for JMP [rip+offset] (FF 25 XX XX XX XX)
        else if (functionBytes[0] == 0xFF && functionBytes[1] == 0x25) {
            LONG ripOffset = *(PLONG)&functionBytes[2];
            PVOID* jumpAddress = (PVOID*)((PUCHAR)FunctionAddress + 6 + ripOffset);
            HookInfo->JumpTarget = *jumpAddress;
            HookInfo->HookedBytesCount = 6;
            HookInfo->IsHooked = TRUE;
            HookInfo->HookMethod = HOOK_TYPE_INLINE;
            isHooked = TRUE;
        }
        // Check for MOV RAX, addr; JMP RAX
        else if (functionBytes[0] == 0x48 && functionBytes[1] == 0xB8) {
            if (functionBytes[10] == 0xFF && functionBytes[11] == 0xE0) {
                HookInfo->JumpTarget = *(PVOID*)&functionBytes[2];
                HookInfo->HookedBytesCount = 12;
                HookInfo->IsHooked = TRUE;
                HookInfo->HookMethod = HOOK_TYPE_INLINE;
                isHooked = TRUE;
            }
        }
        // Check for PUSH addr; RET
        else if (functionBytes[0] == X64_PUSH) {
            if (functionBytes[5] == X64_RET) {
                HookInfo->JumpTarget = *(PVOID*)&functionBytes[1];
                HookInfo->HookedBytesCount = 6;
                HookInfo->IsHooked = TRUE;
                HookInfo->HookMethod = HOOK_TYPE_INLINE;
                isHooked = TRUE;
            }
        }

        // If no hook detected, save original bytes for comparison
        if (!isHooked) {
            RtlCopyMemory(HookInfo->OriginalBytes, functionBytes,
                min(MAX_INSTRUCTION_BYTES, 16));
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception analyzing function at %p\n", FunctionAddress);
        return FALSE;
    }

    return isHooked;
}

/**
 * @brief Remove detected hook
 */
NTSTATUS RemoveDetectedHook(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ PHOOK_DETECTION_RESULT HookResult)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;

    if (!Context || !HookResult) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Context->EnableAutoRemoval) {
        DbgPrint("[CryptoShield] Auto-removal disabled. Hook at %p not removed.\n",
            HookResult->HookedAddress);
        return STATUS_ACCESS_DENIED;
    }

    DbgPrint("[CryptoShield] Attempting to remove hook at %p\n",
        HookResult->HookedAddress);

    switch (HookResult->HookType) {
    case HOOK_TYPE_SSDT:
        status = RestoreSSDTEntry(
            HookResult->Details.SsdtInfo.ServiceIndex,
            HookResult->Details.SsdtInfo.OriginalAddress
        );
        break;

    case HOOK_TYPE_INLINE:
        status = RestoreOriginalBytes(
            HookResult->Details.InlineInfo.FunctionAddress,
            HookResult->Details.InlineInfo.OriginalBytes,
            HookResult->Details.InlineInfo.HookedBytesCount
        );
        break;

    case HOOK_TYPE_IDT:
        // IDT restoration would go here
        status = STATUS_NOT_IMPLEMENTED;
        break;

    default:
        status = STATUS_NOT_SUPPORTED;
    }

    if (NT_SUCCESS(status)) {
        KeAcquireSpinLock(&Context->DetectionLock, &oldIrql);
        Context->HooksRemoved++;
        KeReleaseSpinLock(&Context->DetectionLock, oldIrql);

        DbgPrint("[CryptoShield] Hook successfully removed\n");
    }
    else {
        DbgPrint("[CryptoShield] Failed to remove hook: 0x%08X\n", status);
    }

    return status;
}

/**
 * @brief Restore original function bytes
 */
NTSTATUS RestoreOriginalBytes(
    _In_ PVOID FunctionAddress,
    _In_reads_(ByteCount) PUCHAR OriginalBytes,
    _In_ ULONG ByteCount)
{
    PMDL mdl = NULL;
    PVOID mappedAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (!FunctionAddress || !OriginalBytes || ByteCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        // Create MDL for the target memory
        mdl = IoAllocateMdl(FunctionAddress, ByteCount, FALSE, FALSE, NULL);
        if (!mdl) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Lock pages
        MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

        // Map to writable address
        mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode,
            MmCached, NULL, FALSE, NormalPagePriority);

        if (!mappedAddress) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Disable write protection
        KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
        ULONG_PTR cr0 = __readcr0();
        __writecr0(cr0 & ~0x10000); // Clear WP bit

        // Restore original bytes
        RtlCopyMemory(mappedAddress, OriginalBytes, ByteCount);

        // Re-enable write protection
        __writecr0(cr0);
        KeLowerIrql(oldIrql);

        // Cleanup
        MmUnmapLockedPages(mappedAddress, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        DbgPrint("[CryptoShield] Restored %lu bytes at %p\n", ByteCount, FunctionAddress);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception restoring bytes: 0x%08X\n",
            GetExceptionCode());

        if (mappedAddress && mdl) {
            MmUnmapLockedPages(mappedAddress, mdl);
        }
        if (mdl) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
        }

        status = STATUS_UNHANDLED_EXCEPTION;
    }

    return status;
}

/**
 * @brief Perform comprehensive hook scan
 */
NTSTATUS PerformHookScan(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ ULONG ScanTypes,
    _Out_writes_(MaxResults) PHOOK_DETECTION_RESULT Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG DetectedCount)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG totalDetected = 0;
    ULONG remainingSpace = MaxResults;
    ULONG detected = 0;

    if (!Context || !Results || !DetectedCount || MaxResults == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *DetectedCount = 0;

    DbgPrint("[CryptoShield] Starting comprehensive hook scan. Types: 0x%X\n", ScanTypes);

    // Scan SSDT hooks
    if ((ScanTypes & HOOK_TYPE_SSDT) && remainingSpace > 0) {
        status = DetectSSDTHooks(Context, &Results[totalDetected],
            remainingSpace, &detected);

        if (NT_SUCCESS(status)) {
            totalDetected += detected;
            remainingSpace -= detected;
        }
    }

    // Additional scan types would be implemented here
    // IDT, IRP handlers, Filter callbacks, etc.

    *DetectedCount = totalDetected;

    DbgPrint("[CryptoShield] Hook scan complete. Total detected: %lu\n", totalDetected);

    return STATUS_SUCCESS;
}

/**
 * @brief Initialize known hook patterns
 */
VOID InitializeKnownPatterns(
    _In_ PHOOK_DETECTION_CONTEXT Context)
{
    ULONG i;

    if (!Context) {
        return;
    }

    // Add common hook patterns
    for (i = 0; i < sizeof(g_CommonHookPatterns) / sizeof(HOOK_PATTERN); i++) {
        if (Context->PatternCount < MAX_HOOK_DETECTIONS) {
            RtlCopyMemory(&Context->KnownPatterns[Context->PatternCount],
                &g_CommonHookPatterns[i],
                sizeof(HOOK_PATTERN));
            Context->PatternCount++;
        }
    }
}

/**
 * @brief Verify if address is within valid kernel module
 */
static BOOLEAN IsAddressInValidModule(PVOID Address)
{
    // Simplified check - in production, would enumerate loaded modules
    // and verify address is within a legitimate module's range

    if (!Address) {
        return FALSE;
    }

    // Check if in kernel address space
    if ((ULONG_PTR)Address < 0xFFFF800000000000) {
        return FALSE;
    }

    // Additional validation would go here

    return TRUE;
}

/**
 * @brief Get SSDT base address
 */
static PVOID GetSSDTBase(VOID)
{
    // In production, this would use proper methods to locate SSDT
    // For now, return NULL as placeholder
    return NULL;
}

/**
 * @brief Get number of SSDT entries
 */
static ULONG GetSSDTEntries(VOID)
{
    // Typical Windows 10/11 has around 0x1C0 services
    return 0x1C0;
}

/**
 * @brief Get IDT information
 */
static NTSTATUS GetIDTInfo(PVOID* IdtBase, PULONG IdtEntries)
{
    if (!IdtBase || !IdtEntries) {
        return STATUS_INVALID_PARAMETER;
    }

    // IDT typically has 256 entries
    *IdtEntries = 256;

    // Getting actual IDT base would use SIDT instruction
    *IdtBase = NULL;

    return STATUS_SUCCESS;
}

/**
 * @brief Log hook detection event
 */
VOID LogHookDetection(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ PHOOK_DETECTION_RESULT Detection)
{
    UNREFERENCED_PARAMETER(Context);

    if (!Detection) {
        return;
    }

    DbgPrint("[CryptoShield] HOOK DETECTED:\n");
    DbgPrint("  Type: %s\n",
        Detection->HookType == HOOK_TYPE_SSDT ? "SSDT" :
        Detection->HookType == HOOK_TYPE_INLINE ? "Inline" :
        Detection->HookType == HOOK_TYPE_IDT ? "IDT" : "Unknown");
    DbgPrint("  Address: %p\n", Detection->HookedAddress);
    DbgPrint("  Handler: %p\n", Detection->HookHandler);
    DbgPrint("  Malicious: %s\n", Detection->IsMalicious ? "Yes" : "No");
    DbgPrint("  Confidence: %lu%%\n", Detection->ConfidenceLevel);
    DbgPrint("  Description: %ws\n", Detection->Description);
}

/**
 * @brief Get hook detection statistics
 */
VOID GetHookDetectionStatistics(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _Out_opt_ PULONG TotalScans,
    _Out_opt_ PULONG HooksDetected,
    _Out_opt_ PULONG HooksRemoved)
{
    KIRQL oldIrql;

    if (!Context) {
        return;
    }

    KeAcquireSpinLock(&Context->DetectionLock, &oldIrql);

    if (TotalScans) {
        *TotalScans = Context->TotalScans;
    }
    if (HooksDetected) {
        *HooksDetected = Context->HooksDetected;
    }
    if (HooksRemoved) {
        *HooksRemoved = Context->HooksRemoved;
    }

    KeReleaseSpinLock(&Context->DetectionLock, oldIrql);
}