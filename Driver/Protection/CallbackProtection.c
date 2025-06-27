/**
 * @file CallbackProtection.c
 * @brief Implements callback table protection mechanisms for CryptoShield.
 * @details This file contains functions to backup, monitor, and restore the driver's
 *          callback table to prevent tampering.
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include <fltKernel.h>
#include <ntddk.h> // Required for DPC, Timer, etc.
#include "../CryptoShield.h" // Access to g_Context, CRYPTOSHIELD_POOL_TAG, CS_LOG_ERROR
#include "CallbackProtection.h" // Function declarations for this file
#include "HookDetection.h"      // For IsSdtHooked()
#include "MemoryIntegrity.h"    // For IsDriverMemoryIntact()

// External declaration for FilterRegistration.Callbacks
// This is defined in CryptoShield.c
extern CONST FLT_OPERATION_REGISTRATION Callbacks[];

// Define timer interval (5 seconds)
#define INTEGRITY_CHECK_INTERVAL_SECONDS 5
#define INTEGRITY_CHECK_INTERVAL_MS (INTEGRITY_CHECK_INTERVAL_SECONDS * 1000)
// Relative time for KeSetTimer: negative value in 100-nanosecond units.
#define INTEGRITY_TIMER_DUE_TIME_100NS (-1 * INTEGRITY_CHECK_INTERVAL_SECONDS * 10 * 1000 * 1000)

// Tamper types specific to integrity checks
#define TAMPER_TYPE_CALLBACK_TABLE_MODIFIED 1
#define TAMPER_TYPE_DRIVER_MEMORY_MODIFIED 2
#define TAMPER_TYPE_SSDT_HOOK_DETECTED 3


/**
 * @brief DPC routine to periodically check the integrity of the callback table.
 * @param Dpc Pointer to the DPC object.
 * @param DeferredContext Context data (g_Context in this case).
 * @param SystemArgument1 System-defined argument 1.
 * @param SystemArgument2 System-defined argument 2.
 */
VOID IntegrityCheckDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    PCRYPTOSHIELD_CONTEXT context = (PCRYPTOSHIELD_CONTEXT)DeferredContext;
    SIZE_T comparisonResult;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (context == NULL || context->CallbackTableBackup == NULL || context->CallbackTableSize == 0) {
        // This shouldn't happen if initialization was successful
        CS_LOG_ERROR("IntegrityCheckDpcRoutine: Invalid context or backup table.");
        return;
    }

    // It's crucial to know the actual current address of 'Callbacks'.
    // Since 'Callbacks' is an extern const global, its address is fixed at link time.
    // We are comparing the live Callbacks table in .data/.rdata section with our backup.
    comparisonResult = RtlCompareMemory(Callbacks, context->CallbackTableBackup, context->CallbackTableSize);

    if (comparisonResult != context->CallbackTableSize) {
        CS_LOG_ERROR("¡ALERTA DE TAMPERING! La tabla de callbacks del driver ha sido modificada.");
        QueueTamperAlert(TAMPER_TYPE_CALLBACK_TABLE_MODIFIED);
        // Future: Attempt restoration if safe and configured.
    }

    NTSTATUS integrityStatus;
    BOOLEAN isIntact; // For IsDriverMemoryIntact, TRUE means intact.
    BOOLEAN isHooked; // For IsSdtHooked, TRUE means a hook is detected.

    // Check for driver memory modification
    // IsDriverMemoryIntact now returns TRUE in isIntact if memory is NOT modified.
    integrityStatus = IsDriverMemoryIntact(&isIntact);
    if (!NT_SUCCESS(integrityStatus)) {
        CS_LOG_ERROR("No se pudo verificar la integridad de la memoria del driver. Status: 0x%X", integrityStatus);
    } else if (!isIntact) { // If memory is NOT intact (modified)
        CS_LOG_ERROR("¡ALERTA DE TAMPERING! La memoria del driver ha sido modificada.");
        QueueTamperAlert(TAMPER_TYPE_DRIVER_MEMORY_MODIFIED);
    }

    // Check for SSDT hooks
    integrityStatus = IsSdtHooked(&isHooked);
    if (!NT_SUCCESS(integrityStatus)) {
        CS_LOG_ERROR("No se pudo verificar la SSDT en busca de hooks. Status: 0x%X", integrityStatus);
    } else if (isHooked) { // If a hook IS detected
        CS_LOG_ERROR("¡ALERTA DE TAMPERING! Se ha detectado un hook en la SSDT.");
        QueueTamperAlert(TAMPER_TYPE_SSDT_HOOK_DETECTED);
    }

    // Note: The DPC routine should complete as quickly as possible.
    // If IsSdtHooked or IsDriverMemoryIntact become too slow,
    // they might need to be offloaded to a worker thread.
    // However, for read-only checks, they are generally acceptable in a DPC
    // if their execution time is minimal and predictable.
}

/**
 * @brief Initializes the callback protection mechanism.
 * @details Backs up the filter callback table and sets up a periodic integrity check.
 * @param filterHandle Handle to the filter object (currently unused but good for context).
 * @return NTSTATUS Status of the operation.
 */
NTSTATUS InitializeCallbackProtection(
    _In_ PFLT_FILTER filterHandle
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG callbackTableEntrySize = sizeof(FLT_OPERATION_REGISTRATION);
    ULONG callbackCount = 0;
    PFLT_OPERATION_REGISTRATION currentCallback = (PFLT_OPERATION_REGISTRATION)Callbacks;

    UNREFERENCED_PARAMETER(filterHandle); // filterHandle might be used later if needed

    PAGED_CODE(); // This function should be called at PASSIVE_LEVEL

    CS_LOG_TRACE("Initializing callback protection...");

    // Calculate the size of the Callbacks table
    // The Callbacks array is terminated by an entry with IRP_MJ_OPERATION_END
    while (currentCallback->MajorFunction != IRP_MJ_OPERATION_END) {
        callbackCount++;
        currentCallback++;
    }
    // Include the terminator entry in the count and size
    callbackCount++;
    g_Context.CallbackTableSize = callbackCount * callbackTableEntrySize;

    if (g_Context.CallbackTableSize == 0) {
        CS_LOG_ERROR("Callback table size is zero, cannot initialize protection.");
        return STATUS_INVALID_PARAMETER; // Or a more specific error
    }

    CS_LOG_INFO("Callback table located. Size: %lu bytes, Entries: %lu", g_Context.CallbackTableSize, callbackCount);

    // Allocate memory for the backup table
    g_Context.CallbackTableBackup = CS_ALLOCATE_POOL(NonPagedPoolNx, g_Context.CallbackTableSize);
    if (g_Context.CallbackTableBackup == NULL) {
        CS_LOG_ERROR("Failed to allocate memory for callback table backup. Size: %lu", g_Context.CallbackTableSize);
        g_Context.CallbackTableSize = 0; // Reset size
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Copy the original callback table to the backup
    RtlCopyMemory(g_Context.CallbackTableBackup, Callbacks, g_Context.CallbackTableSize);
    CS_LOG_TRACE("Callback table backed up successfully to %p.", g_Context.CallbackTableBackup);

    // Initialize DPC and Timer
    // g_Context is used as the DeferredContext for the DPC routine
    KeInitializeDpc(&g_Context.IntegrityDpc, IntegrityCheckDpcRoutine, &g_Context);
    KeInitializeTimer(&g_Context.IntegrityTimer);

    // Set up the periodic timer
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = INTEGRITY_TIMER_DUE_TIME_100NS; // Negative for relative time

    // KeSetTimerEx is generally preferred if you need to pass parameters or control CPU affinity
    // For a simple periodic timer, KeSetTimer is sufficient.
    // The DPC routine (IntegrityCheckDpcRoutine) will be queued when the timer expires.
    // The timer will be rescheduled from within the DPC or a worker thread if continuous checks are needed.
    // For this implementation, we'll make it a periodic timer.
    if (!KeSetTimerEx(&g_Context.IntegrityTimer, dueTime, INTEGRITY_CHECK_INTERVAL_MS, &g_Context.IntegrityDpc)) {
        CS_LOG_INFO("Integrity timer was already in the timer queue.");
        // This is not necessarily an error, but good to note.
        // If it's a recurring timer, it might have been set by a previous partial init.
    }


    CS_LOG_INFO("Callback protection initialized. Integrity checks will run every %d seconds.", INTEGRITY_CHECK_INTERVAL_SECONDS);

    return status;
}

/**
 * @brief Cleans up resources used by the callback protection mechanism.
 * @details Stops the integrity check timer and frees the backup table memory.
 */
VOID CleanupCallbackProtection(VOID)
{
    PAGED_CODE(); // This function should be called at PASSIVE_LEVEL

    CS_LOG_TRACE("Cleaning up callback protection...");

    // Stop the timer. This also cancels any pending DPCs for this timer.
    // It's important to do this before freeing memory that the DPC might access.
    KeCancelTimer(&g_Context.IntegrityTimer);
    CS_LOG_TRACE("Integrity timer cancelled.");

    // KeCancelTimer waits until the timer object is no longer active and no DPC associated with it is running.
    // However, if the DPC is already running on another processor, KeCancelTimer does not wait for it to complete.
    // For robust cleanup, especially if the DPC accesses shared resources that are about to be freed,
    // one might need additional synchronization (e.g., ensuring DPC completion via KeFlushQueuedDpcs or a custom flag).
    // Given our DPC only reads g_Context.CallbackTableBackup and g_Context.CallbackTableSize,
    // and we free CallbackTableBackup *after* KeCancelTimer, this should be safe.
    // The DPC itself doesn't reschedule the timer; KeSetTimerEx does for periodic timers.

    if (g_Context.CallbackTableBackup != NULL) {
        CS_FREE_POOL(g_Context.CallbackTableBackup);
        g_Context.CallbackTableBackup = NULL;
        CS_LOG_TRACE("Callback table backup memory freed.");
    }
    g_Context.CallbackTableSize = 0;

    CS_LOG_INFO("Callback protection cleaned up.");
}
