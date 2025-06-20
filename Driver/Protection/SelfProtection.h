/**
 * @file SelfProtection.h
 * @brief Main kernel self-protection module interface
 * @details Provides comprehensive protection against tampering, hooks, and malicious modifications
 *
 * @author CryptoShield Team
 * @date 2025
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

//#include <ntddk.h>
#include <fltKernel.h>
#include "../CryptoShield.h"

 // Protection configuration flags
#define PROTECTION_FLAG_CALLBACK_GUARD      0x00000001
#define PROTECTION_FLAG_MEMORY_INTEGRITY    0x00000002
#define PROTECTION_FLAG_HOOK_DETECTION      0x00000004
#define PROTECTION_FLAG_SELF_HEALING        0x00000008
#define PROTECTION_FLAG_SIGNATURE_CHECK     0x00000010
#define PROTECTION_FLAG_ALL                 0x0000001F

// Protection status codes
#define PROTECTION_STATUS_HEALTHY           0x00000000
#define PROTECTION_STATUS_TAMPERED          0x00000001
#define PROTECTION_STATUS_HOOKS_DETECTED    0x00000002
#define PROTECTION_STATUS_HEALING_NEEDED    0x00000004
#define PROTECTION_STATUS_CRITICAL          0x00000008

// Maximum values
#define MAX_PROTECTED_REGIONS               16
#define MAX_TAMPER_ATTEMPTS                 10
#define INTEGRITY_CHECK_INTERVAL_MS         5000    // 5 seconds
#define SELF_HEALING_COOLDOWN_MS            30000   // 30 seconds

// Protection context structure
typedef struct _PROTECTION_CONTEXT {
    // Filter handle reference
    PFLT_FILTER FilterHandle;

    // Callback table protection
    PVOID CallbackTableBackup;
    ULONG CallbackTableSize;
    ULONG OriginalChecksum;
    PFLT_OPERATION_REGISTRATION OriginalCallbacks;

    // Integrity verification timer
    KTIMER IntegrityTimer;
    KDPC IntegrityDpc;
    LARGE_INTEGER CheckInterval;

    // Protection configuration
    ULONG ProtectionFlags;
    BOOLEAN ProtectionActive;
    BOOLEAN SelfHealingEnabled;
    ULONG TamperAttempts;
    ULONG MaxTamperAttempts;

    // Self-healing state
    LARGE_INTEGER LastHealingTime;
    ULONG HealingCooldownMs;

    // Synchronization
    KSPIN_LOCK ProtectionLock;
    KIRQL OldIrql;

    // Statistics
    volatile LONG64 IntegrityChecksPerformed;
    volatile LONG64 TamperAttemptsDetected;
    volatile LONG64 SelfHealingActivations;
    volatile LONG64 HooksDetected;
    volatile LONG64 HooksRemoved;

    // Protected memory regions
    struct {
        PVOID BaseAddress;
        SIZE_T Size;
        ULONG Checksum;
        BOOLEAN IsProtected;
    } ProtectedRegions[MAX_PROTECTED_REGIONS];
    ULONG ProtectedRegionCount;

} PROTECTION_CONTEXT, * PPROTECTION_CONTEXT;

// Tamper detection event
typedef struct _TAMPER_EVENT {
    LARGE_INTEGER Timestamp;
    ULONG_PTR ProcessId;
    ULONG_PTR ThreadId;
    ULONG TamperType;
    PVOID TargetAddress;
    CHAR Description[256];
} TAMPER_EVENT, * PTAMPER_EVENT;

// Function declarations

/**
 * @brief Initialize the self-protection system
 * @param Context Global CryptoShield context
 * @param ProtectionFlags Flags indicating which protections to enable
 * @return STATUS_SUCCESS on success, appropriate error code on failure
 */
NTSTATUS InitializeSelfProtection(
    _In_ PCRYPTOSHIELD_CONTEXT Context,
    _In_ ULONG ProtectionFlags
);

/**
 * @brief Cleanup and shutdown self-protection
 * @param Context Global CryptoShield context
 */
VOID CleanupSelfProtection(
    _In_ PCRYPTOSHIELD_CONTEXT Context
);

/**
 * @brief Start active protection monitoring
 * @param Context Protection context
 * @return STATUS_SUCCESS on success
 */
NTSTATUS StartProtectionMonitoring(
    _In_ PPROTECTION_CONTEXT Context
);

/**
 * @brief Stop active protection monitoring
 * @param Context Protection context
 */
VOID StopProtectionMonitoring(
    _In_ PPROTECTION_CONTEXT Context
);

/**
 * @brief DPC routine for periodic integrity checks
 * @param Dpc DPC object
 * @param DeferredContext Protection context
 * @param SystemArgument1 Unused
 * @param SystemArgument2 Unused
 */
VOID IntegrityCheckDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

/**
 * @brief Timer callback for integrity verification
 * @param Timer Timer object
 * @param DeferredContext Protection context
 */
VOID IntegrityTimerCallback(
    _In_ PKTIMER Timer,
    _In_opt_ PVOID DeferredContext
);

// Core protection functions

/**
 * @brief Protect minifilter callback table
 * @param Context Protection context
 * @return STATUS_SUCCESS on success
 */
NTSTATUS ProtectCallbackTable(
    _In_ PPROTECTION_CONTEXT Context
);

/**
 * @brief Verify driver integrity
 * @param Context Protection context
 * @return STATUS_SUCCESS if integrity intact
 */
NTSTATUS ValidateDriverIntegrity(
    _In_ PPROTECTION_CONTEXT Context
);

/**
 * @brief Detect memory tampering attempts
 * @param Context Protection context
 * @return Number of tampering attempts detected
 */
ULONG DetectMemoryTampering(
    _In_ PPROTECTION_CONTEXT Context
);

/**
 * @brief Trigger self-healing procedures
 * @param Context Protection context
 * @return STATUS_SUCCESS on successful healing
 */
NTSTATUS TriggerSelfHealing(
    _In_ PPROTECTION_CONTEXT Context
);

// Memory protection functions

/**
 * @brief Add a memory region to protection list
 * @param Context Protection context
 * @param BaseAddress Start address of region
 * @param Size Size of region
 * @return STATUS_SUCCESS on success
 */
NTSTATUS AddProtectedRegion(
    _In_ PPROTECTION_CONTEXT Context,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size
);

/**
 * @brief Remove a memory region from protection
 * @param Context Protection context
 * @param BaseAddress Start address of region
 * @return STATUS_SUCCESS on success
 */
NTSTATUS RemoveProtectedRegion(
    _In_ PPROTECTION_CONTEXT Context,
    _In_ PVOID BaseAddress
);

/**
 * @brief Verify integrity of all protected regions
 * @param Context Protection context
 * @return Number of corrupted regions
 */
ULONG VerifyProtectedRegions(
    _In_ PPROTECTION_CONTEXT Context
);

// Utility functions

/**
 * @brief Calculate checksum for memory region
 * @param Buffer Memory buffer
 * @param Size Size of buffer
 * @return Checksum value
 */
ULONG CalculateChecksum(
    _In_ PVOID Buffer,
    _In_ ULONG Size
);

/**
 * @brief Verify digital signature of driver image
 * @param ImageBase Base address of driver image
 * @return TRUE if signature valid
 */
BOOLEAN VerifyDigitalSignature(
    _In_ PVOID ImageBase
);

/**
 * @brief Log tamper detection event
 * @param Context Protection context
 * @param Event Tamper event details
 */
VOID LogTamperEvent(
    _In_ PPROTECTION_CONTEXT Context,
    _In_ PTAMPER_EVENT Event
);

/**
 * @brief Get current protection status
 * @param Context Protection context
 * @return Protection status flags
 */
ULONG GetProtectionStatus(
    _In_ PPROTECTION_CONTEXT Context
);

/**
 * @brief Update protection configuration
 * @param Context Protection context
 * @param NewFlags New protection flags
 * @return STATUS_SUCCESS on success
 */
NTSTATUS UpdateProtectionConfig(
    _In_ PPROTECTION_CONTEXT Context,
    _In_ ULONG NewFlags
);

// Emergency response functions

/**
 * @brief Handle critical protection breach
 * @param Context Protection context
 * @param BreachType Type of breach detected
 */
VOID HandleCriticalBreach(
    _In_ PPROTECTION_CONTEXT Context,
    _In_ ULONG BreachType
);

/**
 * @brief Initiate emergency lockdown
 * @param Context Protection context
 * @return STATUS_SUCCESS on success
 */
NTSTATUS InitiateEmergencyLockdown(
    _In_ PPROTECTION_CONTEXT Context
);

// _CRYPTOSHIELD_SELFPROTECTION_H_