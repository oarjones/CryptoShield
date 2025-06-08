/**
 * @file CallbackProtection.c
 * @brief Implementation of minifilter callback protection mechanisms
 * @details Advanced protection against callback hooking, inline hooks, and tampering
 *
 * @author CryptoShield Team
 * @date 2025
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "CallbackProtection.h"
#include <ntstrsafe.h>

 // Memory allocation tag
#define CALLBACK_PROTECTION_TAG 'bcPC'  // 'CPcb' in little-endian

// x64 instruction patterns for hook detection
#define JMP_REL32_OPCODE        0xE9
#define JMP_ABS_OPCODE          0xFF
#define CALL_REL32_OPCODE       0xE8
#define MOV_RAX_OPCODE          0x48
#define PUSH_RET_SIZE           6

// Common function prologues
static const UCHAR COMMON_PROLOGUES[][4] = {
    { 0x48, 0x89, 0x5C, 0x24 },    // mov [rsp+XX], rbx
    { 0x48, 0x83, 0xEC, 0x00 },    // sub rsp, XX
    { 0x40, 0x53, 0x48, 0x83 },    // push rbx; sub rsp, XX
    { 0x48, 0x8B, 0xC4, 0x48 },    // mov rax, rsp; ...
};

/**
 * @brief Initialize callback protection system
 */
PCALLBACK_PROTECTION InitializeCallbackProtection(
    _In_ PFLT_FILTER FilterHandle)
{
    PCALLBACK_PROTECTION protection;
    NTSTATUS status;

    if (!FilterHandle) {
        return NULL;
    }

    // Allocate protection context
    protection = (PCALLBACK_PROTECTION)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(CALLBACK_PROTECTION),
        CALLBACK_PROTECTION_TAG
    );

    if (!protection) {
        DbgPrint("[CryptoShield] Failed to allocate callback protection context\n");
        return NULL;
    }

    RtlZeroMemory(protection, sizeof(CALLBACK_PROTECTION));

    // Get callback table information
    status = GetCallbackTableFromFilter(FilterHandle,
        &protection->OriginalCallbacks,
        &protection->TableSize);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[CryptoShield] Failed to get callback table: 0x%08X\n", status);
        ExFreePoolWithTag(protection, CALLBACK_PROTECTION_TAG);
        return NULL;
    }

    // Count callbacks
    protection->CallbackCount = 0;
    for (ULONG i = 0; protection->OriginalCallbacks[i].MajorFunction != IRP_MJ_OPERATION_END; i++) {
        protection->CallbackCount++;
    }

    DbgPrint("[CryptoShield] Callback protection initialized. Count: %lu, Size: %lu bytes\n",
        protection->CallbackCount, protection->TableSize);

    return protection;
}

/**
 * @brief Cleanup callback protection
 */
VOID CleanupCallbackProtection(
    _In_ PCALLBACK_PROTECTION Protection)
{
    if (!Protection) {
        return;
    }

    DbgPrint("[CryptoShield] Cleaning up callback protection\n");

    // Unlock memory if locked
    if (Protection->IsLocked) {
        UnlockCallbackMemory(Protection);
    }

    // Free backup memory
    if (Protection->BackupCallbackMemory) {
        ExFreePoolWithTag(Protection->BackupCallbackMemory, CALLBACK_PROTECTION_TAG);
    }

    // Free MDL if exists
    if (Protection->CallbackMdl) {
        if (Protection->MappedCallbackMemory) {
            MmUnmapLockedPages(Protection->MappedCallbackMemory, Protection->CallbackMdl);
        }
        MmUnlockPages(Protection->CallbackMdl);
        IoFreeMdl(Protection->CallbackMdl);
    }

    ExFreePoolWithTag(Protection, CALLBACK_PROTECTION_TAG);
}

/**
 * @brief Protect filter callbacks with advanced techniques
 */
NTSTATUS ProtectFilterCallbacks(
    _In_ PCALLBACK_PROTECTION Protection,
    _In_ PFLT_FILTER FilterHandle)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FilterHandle);

    if (!Protection || !Protection->OriginalCallbacks) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[CryptoShield] Protecting filter callbacks\n");

    __try {
        // Create backup of callback table
        status = CreateCallbackBackup(Protection);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[CryptoShield] Failed to create callback backup: 0x%08X\n", status);
            return status;
        }

        // Calculate initial checksum
        Protection->TableChecksum = CalculateChecksum(Protection->OriginalCallbacks,
            Protection->TableSize);

        // Detect any existing hooks
        Protection->DetectedHookCount = DetectCallbackHooks(Protection, HOOK_DETECT_ALL);
        if (Protection->DetectedHookCount > 0) {
            DbgPrint("[CryptoShield] WARNING: %lu hooks detected in callbacks!\n",
                Protection->DetectedHookCount);

            // Attempt to remove hooks
            status = RemoveMaliciousHooks(Protection);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[CryptoShield] Failed to remove hooks: 0x%08X\n", status);
            }
        }

        // Lock callback memory
        status = LockCallbackMemory(Protection);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[CryptoShield] Failed to lock callback memory: 0x%08X\n", status);
            // Continue even if locking fails
        }

        // Mark as protected
        Protection->IsProtected = TRUE;
        KeQuerySystemTime(&Protection->LastVerification);

        DbgPrint("[CryptoShield] Callbacks protected successfully. Checksum: 0x%08X\n",
            Protection->TableChecksum);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception during callback protection: 0x%08X\n",
            GetExceptionCode());
        return STATUS_UNHANDLED_EXCEPTION;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Verify callback table integrity
 */
BOOLEAN VerifyCallbackIntegrity(
    _In_ PCALLBACK_PROTECTION Protection,
    _Out_opt_ PCALLBACK_VERIFICATION_RESULT Result)
{
    ULONG currentChecksum;
    ULONG hooksFound = 0;
    BOOLEAN integrityValid = TRUE;
    CALLBACK_VERIFICATION_RESULT localResult = { 0 };

    if (!Protection || !Protection->IsProtected) {
        return FALSE;
    }

    __try {
        // Calculate current checksum
        currentChecksum = CalculateChecksum(Protection->OriginalCallbacks,
            Protection->TableSize);

        if (currentChecksum != Protection->TableChecksum) {
            integrityValid = FALSE;
            localResult.ModificationsFound++;

            RtlStringCbPrintfA(localResult.Details, sizeof(localResult.Details),
                "Checksum mismatch: Expected 0x%08X, Found 0x%08X",
                Protection->TableChecksum, currentChecksum);
        }

        // Detect hooks
        hooksFound = DetectCallbackHooks(Protection, HOOK_DETECT_ALL);
        if (hooksFound > 0) {
            integrityValid = FALSE;
            localResult.HooksFound = hooksFound;

            RtlStringCbCatA(localResult.Details, sizeof(localResult.Details),
                "; Hooks detected");
        }

        // Check individual callbacks
        for (ULONG i = 0; i < Protection->CallbackCount; i++) {
            PFLT_OPERATION_REGISTRATION callback = &Protection->OriginalCallbacks[i];

            // Verify pre-operation callback
            if (callback->PreOperation && !ValidateFunctionPrologue(callback->PreOperation)) {
                localResult.CorruptedEntries++;
                integrityValid = FALSE;
            }

            // Verify post-operation callback
            if (callback->PostOperation && !ValidateFunctionPrologue(callback->PostOperation)) {
                localResult.CorruptedEntries++;
                integrityValid = FALSE;
            }
        }

        // Update verification timestamp
        KeQuerySystemTime(&Protection->LastVerification);

        // Set final result
        localResult.Status = integrityValid ? CALLBACK_STATUS_CLEAN : CALLBACK_STATUS_MODIFIED;
        localResult.IntegrityValid = integrityValid;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception during integrity verification: 0x%08X\n",
            GetExceptionCode());
        integrityValid = FALSE;
        localResult.Status = CALLBACK_STATUS_UNKNOWN;
    }

    // Copy result if requested
    if (Result) {
        RtlCopyMemory(Result, &localResult, sizeof(CALLBACK_VERIFICATION_RESULT));
    }

    if (!integrityValid) {
        LogCallbackProtectionEvent(Protection, CALLBACK_STATUS_MODIFIED,
            "Integrity verification failed");
    }

    return integrityValid;
}

/**
 * @brief Detect hooks in callback functions
 */
ULONG DetectCallbackHooks(
    _In_ PCALLBACK_PROTECTION Protection,
    _In_ ULONG DetectionMethods)
{
    ULONG hooksDetected = 0;
    HOOK_INFO hookInfo;

    if (!Protection || !Protection->OriginalCallbacks) {
        return 0;
    }

    Protection->DetectedHookCount = 0;

    // Check each callback
    for (ULONG i = 0; i < Protection->CallbackCount; i++) {
        PFLT_OPERATION_REGISTRATION callback = &Protection->OriginalCallbacks[i];

        // Check pre-operation callback
        if (callback->PreOperation) {
            RtlZeroMemory(&hookInfo, sizeof(HOOK_INFO));

            if (DetectionMethods & HOOK_DETECT_INLINE) {
                if (DetectInlineHook(callback->PreOperation, &hookInfo)) {
                    // Store hook information
                    if (Protection->DetectedHookCount < MAX_HOOK_CHAIN_DEPTH) {
                        Protection->DetectedHooks[Protection->DetectedHookCount].HookedAddress =
                            callback->PreOperation;
                        Protection->DetectedHooks[Protection->DetectedHookCount].HookHandler =
                            hookInfo.HookAddress;
                        Protection->DetectedHooks[Protection->DetectedHookCount].HookType =
                            HOOK_DETECT_INLINE;

                        RtlCopyMemory(Protection->DetectedHooks[Protection->DetectedHookCount].OriginalBytes,
                            hookInfo.OriginalBytes, sizeof(hookInfo.OriginalBytes));

                        Protection->DetectedHookCount++;
                        hooksDetected++;
                    }

                    DbgPrint("[CryptoShield] Inline hook detected in PreOp[%lu]: %p -> %p\n",
                        i, callback->PreOperation, hookInfo.HookAddress);
                }
            }
        }

        // Check post-operation callback
        if (callback->PostOperation) {
            RtlZeroMemory(&hookInfo, sizeof(HOOK_INFO));

            if (DetectionMethods & HOOK_DETECT_INLINE) {
                if (DetectInlineHook(callback->PostOperation, &hookInfo)) {
                    if (Protection->DetectedHookCount < MAX_HOOK_CHAIN_DEPTH) {
                        Protection->DetectedHooks[Protection->DetectedHookCount].HookedAddress =
                            callback->PostOperation;
                        Protection->DetectedHooks[Protection->DetectedHookCount].HookHandler =
                            hookInfo.HookAddress;
                        Protection->DetectedHooks[Protection->DetectedHookCount].HookType =
                            HOOK_DETECT_INLINE;

                        Protection->DetectedHookCount++;
                        hooksDetected++;
                    }

                    DbgPrint("[CryptoShield] Inline hook detected in PostOp[%lu]: %p -> %p\n",
                        i, callback->PostOperation, hookInfo.HookAddress);
                }
            }
        }
    }

    Protection->HooksDetected += hooksDetected;

    return hooksDetected;
}

/**
 * @brief Detect inline hooks in a function
 */
BOOLEAN DetectInlineHook(
    _In_ PVOID FunctionAddress,
    _Out_ PHOOK_INFO HookInfo)
{
    PUCHAR functionBytes;
    BOOLEAN hookDetected = FALSE;

    if (!FunctionAddress || !HookInfo) {
        return FALSE;
    }

    RtlZeroMemory(HookInfo, sizeof(HOOK_INFO));
    HookInfo->TargetAddress = FunctionAddress;

    __try {
        functionBytes = (PUCHAR)FunctionAddress;

        // Copy first bytes for analysis
        RtlCopyMemory(HookInfo->CurrentBytes, functionBytes,
            min(MAX_INSTRUCTION_ANALYSIS_SIZE, 16));

        // Check for common hook patterns

        // 1. Check for JMP near (E9 XX XX XX XX)
        if (functionBytes[0] == JMP_REL32_OPCODE) {
            LONG relativeOffset = *(PLONG)&functionBytes[1];
            HookInfo->HookAddress = (PVOID)((PUCHAR)FunctionAddress + 5 + relativeOffset);
            HookInfo->HookType = HOOK_DETECT_INLINE;
            HookInfo->HookSize = 5;
            HookInfo->IsInline = TRUE;
            hookDetected = TRUE;

            RtlStringCbCopyA(HookInfo->Description, sizeof(HookInfo->Description),
                "JMP near relative hook detected");
        }
        // 2. Check for JMP indirect (FF 25 XX XX XX XX)
        else if (functionBytes[0] == JMP_ABS_OPCODE && functionBytes[1] == 0x25) {
            PVOID* jumpAddress = (PVOID*)((PUCHAR)FunctionAddress + 6 + *(PLONG)&functionBytes[2]);
            HookInfo->HookAddress = *jumpAddress;
            HookInfo->HookType = HOOK_DETECT_INLINE;
            HookInfo->HookSize = 6;
            HookInfo->IsInline = TRUE;
            hookDetected = TRUE;

            RtlStringCbCopyA(HookInfo->Description, sizeof(HookInfo->Description),
                "JMP indirect hook detected");
        }
        // 3. Check for MOV RAX, XXX; JMP RAX pattern
        else if (functionBytes[0] == MOV_RAX_OPCODE && functionBytes[1] == 0xB8) {
            // 48 B8 XX XX XX XX XX XX XX XX ; MOV RAX, QWORD
            // FF E0                         ; JMP RAX
            if (functionBytes[10] == 0xFF && functionBytes[11] == 0xE0) {
                HookInfo->HookAddress = *(PVOID*)&functionBytes[2];
                HookInfo->HookType = HOOK_DETECT_INLINE;
                HookInfo->HookSize = 12;
                HookInfo->IsInline = TRUE;
                HookInfo->IsDetour = TRUE;
                hookDetected = TRUE;

                RtlStringCbCopyA(HookInfo->Description, sizeof(HookInfo->Description),
                    "MOV RAX; JMP RAX hook pattern detected");
            }
        }
        // 4. Check for PUSH-RET hook
        else if (functionBytes[0] == 0x68) {  // PUSH imm32
            if (functionBytes[5] == 0xC3) {   // RET
                HookInfo->HookAddress = *(PVOID*)&functionBytes[1];
                HookInfo->HookType = HOOK_DETECT_INLINE;
                HookInfo->HookSize = 6;
                HookInfo->IsInline = TRUE;
                hookDetected = TRUE;

                RtlStringCbCopyA(HookInfo->Description, sizeof(HookInfo->Description),
                    "PUSH-RET hook detected");
            }
        }

        // If no hook detected, validate function prologue
        if (!hookDetected) {
            BOOLEAN validPrologue = FALSE;

            // Check against known good prologues
            for (ULONG i = 0; i < sizeof(COMMON_PROLOGUES) / sizeof(COMMON_PROLOGUES[0]); i++) {
                if (RtlCompareMemory(functionBytes, COMMON_PROLOGUES[i], 4) == 4) {
                    validPrologue = TRUE;
                    break;
                }
            }

            if (!validPrologue) {
                // Suspicious but not definitively a hook
                RtlStringCbCopyA(HookInfo->Description, sizeof(HookInfo->Description),
                    "Unusual function prologue detected");
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception analyzing function at %p\n", FunctionAddress);
        return FALSE;
    }

    return hookDetected;
}

/**
 * @brief Create secure backup of callback memory
 */
NTSTATUS CreateCallbackBackup(
    _In_ PCALLBACK_PROTECTION Protection)
{
    if (!Protection || !Protection->OriginalCallbacks || Protection->TableSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate backup memory
    Protection->BackupCallbackMemory = ExAllocatePoolWithTag(
        NonPagedPool,
        Protection->TableSize,
        CALLBACK_PROTECTION_TAG
    );

    if (!Protection->BackupCallbackMemory) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        // Copy callback table to backup
        RtlCopyMemory(Protection->BackupCallbackMemory,
            Protection->OriginalCallbacks,
            Protection->TableSize);

        DbgPrint("[CryptoShield] Callback backup created. Size: %lu bytes\n",
            Protection->TableSize);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(Protection->BackupCallbackMemory, CALLBACK_PROTECTION_TAG);
        Protection->BackupCallbackMemory = NULL;
        return STATUS_UNHANDLED_EXCEPTION;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Restore callback table from backup
 */
NTSTATUS RestoreCallbackTable(
    _In_ PCALLBACK_PROTECTION Protection)
{
    if (!Protection || !Protection->BackupCallbackMemory || !Protection->OriginalCallbacks) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[CryptoShield] Restoring callback table from backup\n");

    __try {
        // Temporarily disable write protection if needed
        KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

        // Restore callbacks from backup
        RtlCopyMemory(Protection->OriginalCallbacks,
            Protection->BackupCallbackMemory,
            Protection->TableSize);

        KeLowerIrql(oldIrql);

        // Recalculate checksum
        Protection->TableChecksum = CalculateChecksum(Protection->OriginalCallbacks,
            Protection->TableSize);

        // Update status
        Protection->ModificationAttempts = 0;
        KeQuerySystemTime(&Protection->LastVerification);

        LogCallbackProtectionEvent(Protection, CALLBACK_STATUS_RESTORED,
            "Callback table restored from backup");

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception during callback restoration: 0x%08X\n",
            GetExceptionCode());
        return STATUS_UNHANDLED_EXCEPTION;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Lock callback memory pages
 */
NTSTATUS LockCallbackMemory(
    _In_ PCALLBACK_PROTECTION Protection)
{
    PMDL mdl;
    PVOID mappedAddress;

    if (!Protection || !Protection->OriginalCallbacks || Protection->IsLocked) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        // Create MDL for callback memory
        mdl = IoAllocateMdl(Protection->OriginalCallbacks,
            Protection->TableSize,
            FALSE,
            FALSE,
            NULL);

        if (!mdl) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Lock pages in memory
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

        // Map to system address space
        mappedAddress = MmMapLockedPagesSpecifyCache(mdl,
            KernelMode,
            MmCached,
            NULL,
            FALSE,
            NormalPagePriority);

        if (!mappedAddress) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Protection->CallbackMdl = mdl;
        Protection->MappedCallbackMemory = mappedAddress;
        Protection->IsLocked = TRUE;

        DbgPrint("[CryptoShield] Callback memory locked\n");

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (mdl) {
            IoFreeMdl(mdl);
        }
        return STATUS_UNHANDLED_EXCEPTION;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Validate function prologue
 */
BOOLEAN ValidateFunctionPrologue(
    _In_ PVOID FunctionAddress)
{
    PUCHAR functionBytes;
    BOOLEAN isValid = FALSE;

    if (!FunctionAddress) {
        return FALSE;
    }

    __try {
        functionBytes = (PUCHAR)FunctionAddress;

        // Check for common valid prologues
        for (ULONG i = 0; i < sizeof(COMMON_PROLOGUES) / sizeof(COMMON_PROLOGUES[0]); i++) {
            if (RtlCompareMemory(functionBytes, COMMON_PROLOGUES[i], 3) >= 3) {
                isValid = TRUE;
                break;
            }
        }

        // Additional checks for obviously invalid patterns
        if (functionBytes[0] == 0x00 && functionBytes[1] == 0x00) {
            isValid = FALSE;  // NULL bytes at function start
        }
        else if (functionBytes[0] == 0xCC) {
            isValid = FALSE;  // INT3 breakpoint
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        isValid = FALSE;
    }

    return isValid;
}

/**
 * @brief Get callback table from filter
 */
NTSTATUS GetCallbackTableFromFilter(
    _In_ PFLT_FILTER FilterHandle,
    _Out_ PFLT_OPERATION_REGISTRATION* CallbackTable,
    _Out_ PULONG TableSize)
{
    PFLT_OPERATION_REGISTRATION callbacks;
    ULONG size = 0;
    ULONG count = 0;

    if (!FilterHandle || !CallbackTable || !TableSize) {
        return STATUS_INVALID_PARAMETER;
    }

    // This is a simplified approach - in production you'd need proper parsing
    // For now, we assume callbacks follow the filter structure
    callbacks = (PFLT_OPERATION_REGISTRATION)((PUCHAR)FilterHandle + sizeof(FLT_FILTER));

    // Count callbacks and calculate size
    while (callbacks[count].MajorFunction != IRP_MJ_OPERATION_END) {
        count++;
        size += sizeof(FLT_OPERATION_REGISTRATION);
    }
    size += sizeof(FLT_OPERATION_REGISTRATION); // For terminator

    *CallbackTable = callbacks;
    *TableSize = size;

    return STATUS_SUCCESS;
}

/**
 * @brief Log callback protection event
 */
VOID LogCallbackProtectionEvent(
    _In_ PCALLBACK_PROTECTION Protection,
    _In_ ULONG EventType,
    _In_ PCHAR Description)
{
    UNREFERENCED_PARAMETER(Protection);

    DbgPrint("[CryptoShield] Callback Protection Event:\n");
    DbgPrint("  Type: 0x%08X\n", EventType);
    DbgPrint("  Description: %s\n", Description);
    DbgPrint("  Hooks Detected: %lu\n", Protection->HooksDetected);
    DbgPrint("  Hooks Removed: %lu\n", Protection->HooksRemoved);
    DbgPrint("  Modification Attempts: %lu\n", Protection->ModificationAttempts);
}