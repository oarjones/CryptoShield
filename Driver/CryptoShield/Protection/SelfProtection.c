/**
 * @file SelfProtection.c
 * @brief Implementation of kernel self-protection mechanisms
 * @details Provides tamper detection, integrity verification, and self-healing capabilities
 *
 * @author CryptoShield Team
 * @date 2025
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "SelfProtection.h"
#include <ntstrsafe.h>

 // Global protection context
static PROTECTION_CONTEXT g_ProtectionContext = { 0 };

// Tags for memory allocation
#define PROTECTION_TAG 'torP'  // 'Prot' in little-endian

/**
 * @brief Initialize the self-protection system
 */
NTSTATUS InitializeSelfProtection(
    _In_ PCRYPTOSHIELD_CONTEXT Context,
    _In_ ULONG ProtectionFlags)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!Context || !Context->FilterHandle) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[CryptoShield] Initializing self-protection system with flags: 0x%08X\n",
        ProtectionFlags);

    // Initialize protection context
    RtlZeroMemory(&g_ProtectionContext, sizeof(PROTECTION_CONTEXT));

    g_ProtectionContext.FilterHandle = Context->FilterHandle;
    g_ProtectionContext.ProtectionFlags = ProtectionFlags;
    g_ProtectionContext.MaxTamperAttempts = MAX_TAMPER_ATTEMPTS;
    g_ProtectionContext.HealingCooldownMs = SELF_HEALING_COOLDOWN_MS;

    // Initialize spin lock
    KeInitializeSpinLock(&g_ProtectionContext.ProtectionLock);

    // Initialize timer and DPC for integrity checks
    KeInitializeTimer(&g_ProtectionContext.IntegrityTimer);
    KeInitializeDpc(&g_ProtectionContext.IntegrityDpc, IntegrityCheckDpc, &g_ProtectionContext);

    // Set check interval
    g_ProtectionContext.CheckInterval.QuadPart = -((LONGLONG)INTEGRITY_CHECK_INTERVAL_MS * 10000);

    __try {
        // Protect callback table if requested
        if (ProtectionFlags & PROTECTION_FLAG_CALLBACK_GUARD) {
            status = ProtectCallbackTable(&g_ProtectionContext);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[CryptoShield] Failed to protect callback table: 0x%08X\n", status);
                __leave;
            }
        }

        // Add critical regions to protection
        if (ProtectionFlags & PROTECTION_FLAG_MEMORY_INTEGRITY) {
            // Protect our own context structure
            status = AddProtectedRegion(&g_ProtectionContext,
                &g_ProtectionContext,
                sizeof(PROTECTION_CONTEXT));
            if (!NT_SUCCESS(status)) {
                DbgPrint("[CryptoShield] Failed to protect context structure: 0x%08X\n", status);
                __leave;
            }
        }

        // Enable self-healing if requested
        if (ProtectionFlags & PROTECTION_FLAG_SELF_HEALING) {
            g_ProtectionContext.SelfHealingEnabled = TRUE;
            KeQuerySystemTime(&g_ProtectionContext.LastHealingTime);
        }

        // Start protection monitoring
        status = StartProtectionMonitoring(&g_ProtectionContext);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[CryptoShield] Failed to start protection monitoring: 0x%08X\n", status);
            __leave;
        }

        g_ProtectionContext.ProtectionActive = TRUE;
        DbgPrint("[CryptoShield] Self-protection initialized successfully\n");

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_UNHANDLED_EXCEPTION;
        DbgPrint("[CryptoShield] Exception during protection initialization: 0x%08X\n",
            GetExceptionCode());
    }

    if (!NT_SUCCESS(status)) {
        // Cleanup on failure
        CleanupSelfProtection(Context);
    }

    return status;
}

/**
 * @brief Cleanup and shutdown self-protection
 */
VOID CleanupSelfProtection(
    _In_ PCRYPTOSHIELD_CONTEXT Context)
{
    UNREFERENCED_PARAMETER(Context);

    DbgPrint("[CryptoShield] Cleaning up self-protection system\n");

    // Stop monitoring first
    StopProtectionMonitoring(&g_ProtectionContext);

    // Acquire lock for cleanup
    KeAcquireSpinLock(&g_ProtectionContext.ProtectionLock, &g_ProtectionContext.OldIrql);

    // Clear protection active flag
    g_ProtectionContext.ProtectionActive = FALSE;

    // Free callback table backup
    if (g_ProtectionContext.CallbackTableBackup) {
        ExFreePoolWithTag(g_ProtectionContext.CallbackTableBackup, PROTECTION_TAG);
        g_ProtectionContext.CallbackTableBackup = NULL;
    }

    // Clear protected regions
    g_ProtectionContext.ProtectedRegionCount = 0;

    KeReleaseSpinLock(&g_ProtectionContext.ProtectionLock, g_ProtectionContext.OldIrql);

    // Log final statistics
    DbgPrint("[CryptoShield] Protection Statistics:\n");
    DbgPrint("  - Integrity checks performed: %lu\n", g_ProtectionContext.IntegrityChecksPerformed);
    DbgPrint("  - Tamper attempts detected: %lu\n", g_ProtectionContext.TamperAttemptsDetected);
    DbgPrint("  - Self-healing activations: %lu\n", g_ProtectionContext.SelfHealingActivations);
    DbgPrint("  - Hooks detected: %lu\n", g_ProtectionContext.HooksDetected);
}

/**
 * @brief Start active protection monitoring
 */
NTSTATUS StartProtectionMonitoring(
    _In_ PPROTECTION_CONTEXT Context)
{
    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[CryptoShield] Starting protection monitoring\n");

    // Set the timer for periodic integrity checks
    KeSetTimerEx(&Context->IntegrityTimer,
        Context->CheckInterval,
        INTEGRITY_CHECK_INTERVAL_MS,  // Period in ms
        &Context->IntegrityDpc);

    return STATUS_SUCCESS;
}

/**
 * @brief Stop active protection monitoring
 */
VOID StopProtectionMonitoring(
    _In_ PPROTECTION_CONTEXT Context)
{
    if (!Context) {
        return;
    }

    DbgPrint("[CryptoShield] Stopping protection monitoring\n");

    // Cancel timer and wait for any pending DPC
    KeCancelTimer(&Context->IntegrityTimer);
    KeFlushQueuedDpcs();
}

/**
 * @brief DPC routine for periodic integrity checks
 */
VOID IntegrityCheckDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    PPROTECTION_CONTEXT context = (PPROTECTION_CONTEXT)DeferredContext;
    ULONG tamperCount;
    ULONG corruptedRegions;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (!context || !context->ProtectionActive) {
        return;
    }

    // Increment check counter
    InterlockedIncrement64(&context->IntegrityChecksPerformed);

    // Detect memory tampering
    tamperCount = DetectMemoryTampering(context);
    if (tamperCount > 0) {
        DbgPrint("[CryptoShield] WARNING: Detected %lu tampering attempts!\n", tamperCount);
        InterlockedAdd64(&context->TamperAttemptsDetected, tamperCount);

        // Check if we exceeded tamper threshold
        if (context->TamperAttempts >= context->MaxTamperAttempts) {
            HandleCriticalBreach(context, PROTECTION_STATUS_CRITICAL);
            return;
        }
    }

    // Verify protected memory regions
    corruptedRegions = VerifyProtectedRegions(context);
    if (corruptedRegions > 0) {
        DbgPrint("[CryptoShield] WARNING: %lu protected regions corrupted!\n", corruptedRegions);

        // Trigger self-healing if enabled
        if (context->SelfHealingEnabled) {
            status = TriggerSelfHealing(context);
            if (NT_SUCCESS(status)) {
                InterlockedIncrement64(&context->SelfHealingActivations);
            }
        }
    }

    // Validate driver integrity
    if (context->ProtectionFlags & PROTECTION_FLAG_SIGNATURE_CHECK) {
        status = ValidateDriverIntegrity(context);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[CryptoShield] Driver integrity validation failed!\n");
            HandleCriticalBreach(context, PROTECTION_STATUS_TAMPERED);
        }
    }
}

/**
 * @brief Protect minifilter callback table
 */
NTSTATUS ProtectCallbackTable(
    _In_ PPROTECTION_CONTEXT Context)
{
    //PFLT_FILTER filter;
    //PFLT_OPERATION_REGISTRATION callbacks;
    //SIZE_T tableSize = 0;
    //ULONG i;

    //if (!Context || !Context->FilterHandle) {
    //    return STATUS_INVALID_PARAMETER;
    //}

    //filter = Context->FilterHandle;

    //// Get callback table from filter
    //// Note: This is a simplified approach. In production, you'd need to
    //// parse the filter structure more carefully
    //callbacks = (PFLT_OPERATION_REGISTRATION)((PUCHAR)filter + sizeof(FLT_FILTER));

    //// Calculate table size
    //for (i = 0; callbacks[i].MajorFunction != IRP_MJ_OPERATION_END; i++) {
    //    tableSize += sizeof(FLT_OPERATION_REGISTRATION);
    //}
    //tableSize += sizeof(FLT_OPERATION_REGISTRATION); // For the terminator

    //// Allocate backup buffer
    //Context->CallbackTableBackup = ExAllocatePoolWithTag(NonPagedPool, tableSize, PROTECTION_TAG);
    //if (!Context->CallbackTableBackup) {
    //    return STATUS_INSUFFICIENT_RESOURCES;
    //}

    //// Create backup copy
    //RtlCopyMemory(Context->CallbackTableBackup, callbacks, tableSize);
    //Context->CallbackTableSize = (ULONG)tableSize;
    //Context->OriginalCallbacks = callbacks;

    //// Calculate checksum
    //Context->OriginalChecksum = CalculateChecksum(callbacks, (ULONG)tableSize);

    //DbgPrint("[CryptoShield] Callback table protected. Size: %lu, Checksum: 0x%08X\n",
    //    tableSize, Context->OriginalChecksum);

    //return STATUS_SUCCESS;

    // La tabla de callbacks es la que definimos globalmente en CryptoShield.c
    extern CONST FLT_OPERATION_REGISTRATION Callbacks[];
    SIZE_T tableSize = 0;
    ULONG i;

    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    // Calcular el tamaño real de nuestra tabla de callbacks
    for (i = 0; Callbacks[i].MajorFunction != IRP_MJ_OPERATION_END; i++) {
        tableSize += sizeof(FLT_OPERATION_REGISTRATION);
    }
    tableSize += sizeof(FLT_OPERATION_REGISTRATION); // Sumar el terminador IRP_MJ_OPERATION_END

    // Asignar memoria para la copia de seguridad
    Context->CallbackTableBackup = ExAllocatePool2(POOL_FLAG_NON_PAGED, tableSize, PROTECTION_TAG);
    if (!Context->CallbackTableBackup) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Crear la copia de seguridad
    RtlCopyMemory(Context->CallbackTableBackup, (PVOID)Callbacks, tableSize);
    Context->CallbackTableSize = (ULONG)tableSize;
    Context->OriginalCallbacks = (PFLT_OPERATION_REGISTRATION)Callbacks;

    // Calcular el checksum inicial
    Context->OriginalChecksum = CalculateChecksum((PVOID)Callbacks, (ULONG)tableSize);

    DbgPrint("[CryptoShield] Callback table protected. Size: %lu, Checksum: 0x%08X\n",
        (ULONG)tableSize, Context->OriginalChecksum);

    return STATUS_SUCCESS;


}

/**
 * @brief Detect memory tampering attempts
 */
ULONG DetectMemoryTampering(
    _In_ PPROTECTION_CONTEXT Context)
{
    ULONG tamperCount = 0;
    ULONG currentChecksum;
    KIRQL oldIrql;

    if (!Context || !Context->CallbackTableBackup) {
        return 0;
    }

    KeAcquireSpinLock(&Context->ProtectionLock, &oldIrql);

    __try {
        // Check callback table integrity
        if (Context->OriginalCallbacks) {
            currentChecksum = CalculateChecksum(Context->OriginalCallbacks,
                Context->CallbackTableSize);

            if (currentChecksum != Context->OriginalChecksum) {
                tamperCount++;

                // Log tamper event
                TAMPER_EVENT event = { 0 };
                KeQuerySystemTime(&event.Timestamp);
                /*event.ProcessId = (ULONG)PsGetCurrentProcessId();
                event.ThreadId = (ULONG)PsGetCurrentThreadId();*/
                event.ProcessId = (ULONG_PTR)PsGetCurrentProcessId();
                event.ThreadId = (ULONG_PTR)PsGetCurrentThreadId();
                event.TamperType = PROTECTION_STATUS_TAMPERED;
                event.TargetAddress = Context->OriginalCallbacks;

                RtlStringCbCopyA(event.Description, sizeof(event.Description),
                    "Callback table checksum mismatch detected");

                LogTamperEvent(Context, &event);

                // Restore from backup if self-healing enabled
                if (Context->SelfHealingEnabled && Context->CallbackTableBackup) {
                    RtlCopyMemory(Context->OriginalCallbacks,
                        Context->CallbackTableBackup,
                        Context->CallbackTableSize);
                    DbgPrint("[CryptoShield] Callback table restored from backup\n");
                }
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception during tampering detection: 0x%08X\n",
            GetExceptionCode());
    }

    KeReleaseSpinLock(&Context->ProtectionLock, oldIrql);

    return tamperCount;
}

/**
 * @brief Verify integrity of all protected regions
 */
ULONG VerifyProtectedRegions(
    _In_ PPROTECTION_CONTEXT Context)
{
    ULONG corruptedCount = 0;
    ULONG i, currentChecksum;
    KIRQL oldIrql;

    if (!Context) {
        return 0;
    }

    KeAcquireSpinLock(&Context->ProtectionLock, &oldIrql);

    for (i = 0; i < Context->ProtectedRegionCount; i++) {
        if (!Context->ProtectedRegions[i].IsProtected) {
            continue;
        }

        __try {
            currentChecksum = CalculateChecksum(Context->ProtectedRegions[i].BaseAddress,
                (ULONG)Context->ProtectedRegions[i].Size);

            if (currentChecksum != Context->ProtectedRegions[i].Checksum) {
                corruptedCount++;
                DbgPrint("[CryptoShield] Protected region %lu corrupted! "
                    "Address: %p, Expected: 0x%08X, Current: 0x%08X\n",
                    i, Context->ProtectedRegions[i].BaseAddress,
                    Context->ProtectedRegions[i].Checksum, currentChecksum);
            }

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            corruptedCount++;
            DbgPrint("[CryptoShield] Exception verifying region %lu\n", i);
        }
    }

    KeReleaseSpinLock(&Context->ProtectionLock, oldIrql);

    return corruptedCount;
}

/**
 * @brief Trigger self-healing procedures
 */
NTSTATUS TriggerSelfHealing(
    _In_ PPROTECTION_CONTEXT Context)
{
    LARGE_INTEGER currentTime;
    LONGLONG timeDiff;

    if (!Context || !Context->SelfHealingEnabled) {
        return STATUS_INVALID_PARAMETER;
    }

    KeQuerySystemTime(&currentTime);

    // Check cooldown period
    timeDiff = (currentTime.QuadPart - Context->LastHealingTime.QuadPart) / 10000; // Convert to ms
    if (timeDiff < Context->HealingCooldownMs) {
        DbgPrint("[CryptoShield] Self-healing in cooldown period. Remaining: %lld ms\n",
            Context->HealingCooldownMs - timeDiff);
        return STATUS_RETRY;
    }

    DbgPrint("[CryptoShield] Triggering self-healing procedures\n");

    // Update last healing time
    Context->LastHealingTime = currentTime;

    // Restore callback table if we have backup
    if (Context->CallbackTableBackup && Context->OriginalCallbacks) {
        RtlCopyMemory(Context->OriginalCallbacks,
            Context->CallbackTableBackup,
            Context->CallbackTableSize);

        // Recalculate checksum
        Context->OriginalChecksum = CalculateChecksum(Context->OriginalCallbacks,
            Context->CallbackTableSize);
    }

    // Re-register with filter manager if needed
    // This would require more complex implementation in production

    return STATUS_SUCCESS;
}

/**
 * @brief Add a memory region to protection list
 */
NTSTATUS AddProtectedRegion(
    _In_ PPROTECTION_CONTEXT Context,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size)
{
    KIRQL oldIrql;
    ULONG index;

    if (!Context || !BaseAddress || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Context->ProtectionLock, &oldIrql);

    // Find free slot
    for (index = 0; index < MAX_PROTECTED_REGIONS; index++) {
        if (!Context->ProtectedRegions[index].IsProtected) {
            Context->ProtectedRegions[index].BaseAddress = BaseAddress;
            Context->ProtectedRegions[index].Size = Size;
            Context->ProtectedRegions[index].Checksum = CalculateChecksum(BaseAddress, (ULONG)Size);
            Context->ProtectedRegions[index].IsProtected = TRUE;

            if (index >= Context->ProtectedRegionCount) {
                Context->ProtectedRegionCount = index + 1;
            }

            KeReleaseSpinLock(&Context->ProtectionLock, oldIrql);

            DbgPrint("[CryptoShield] Added protected region: %p, Size: %zu, Checksum: 0x%08X\n",
                BaseAddress, Size, Context->ProtectedRegions[index].Checksum);

            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&Context->ProtectionLock, oldIrql);

    return STATUS_INSUFFICIENT_RESOURCES;
}

/**
 * @brief Calculate checksum for memory region
 */
ULONG CalculateChecksum(
    _In_ PVOID Buffer,
    _In_ ULONG Size)
{
    PUCHAR data = (PUCHAR)Buffer;
    ULONG checksum = 0;
    ULONG i;

    if (!Buffer || Size == 0) {
        return 0;
    }

    // Simple XOR-based checksum with rotation
    for (i = 0; i < Size; i++) {
        checksum = _rotl(checksum, 1);
        checksum ^= data[i];
    }

    return checksum;
}

/**
 * @brief Log tamper detection event
 */
VOID LogTamperEvent(
    _In_ PPROTECTION_CONTEXT Context,
    _In_ PTAMPER_EVENT Event)
{
    UNREFERENCED_PARAMETER(Context);

    if (!Event) {
        return;
    }

    DbgPrint("[CryptoShield] TAMPER DETECTED:\n");
    DbgPrint("  - Time: %lld\n", Event->Timestamp.QuadPart);
    DbgPrint("  - Process: %lu\n", Event->ProcessId);
    DbgPrint("  - Thread: %lu\n", Event->ThreadId);
    DbgPrint("  - Type: 0x%08X\n", Event->TamperType);
    DbgPrint("  - Target: %p\n", Event->TargetAddress);
    DbgPrint("  - Description: %s\n", Event->Description);

    // In production, this would also log to event log or send to service
}

/**
 * @brief Handle critical protection breach
 */
VOID HandleCriticalBreach(
    _In_ PPROTECTION_CONTEXT Context,
    _In_ ULONG BreachType)
{
    if (!Context) {
        return;
    }

    DbgPrint("[CryptoShield] CRITICAL BREACH DETECTED! Type: 0x%08X\n", BreachType);

    // Notify user-mode service
    // In production, this would send an emergency message to the service

    // Consider initiating emergency lockdown
    if (BreachType == PROTECTION_STATUS_CRITICAL) {
        InitiateEmergencyLockdown(Context);
    }
}

/**
 * @brief Initiate emergency lockdown
 */
NTSTATUS InitiateEmergencyLockdown(
    _In_ PPROTECTION_CONTEXT Context)
{
    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[CryptoShield] INITIATING EMERGENCY LOCKDOWN!\n");

    // In production, this would:
    // 1. Block all file operations
    // 2. Notify admin
    // 3. Create memory dump
    // 4. Isolate system if configured

    return STATUS_SUCCESS;
}