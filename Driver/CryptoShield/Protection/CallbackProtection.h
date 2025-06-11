/**
 * @file CallbackProtection.h
 * @brief Minifilter callback table protection interface
 * @details Provides advanced protection against callback hooking and manipulation
 *
 * @author CryptoShield Team
 * @date 2025
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include <ntddk.h>
#include <fltKernel.h>
#include "SelfProtection.h"


 // Protection status for callbacks
#define CALLBACK_STATUS_CLEAN           0x00000000
#define CALLBACK_STATUS_HOOKED          0x00000001
#define CALLBACK_STATUS_MODIFIED        0x00000002
#define CALLBACK_STATUS_RESTORED        0x00000004
#define CALLBACK_STATUS_UNKNOWN         0x00000008

// Hook detection methods
#define HOOK_DETECT_INLINE              0x00000001
#define HOOK_DETECT_IAT                 0x00000002
#define HOOK_DETECT_SSDT                0x00000004
#define HOOK_DETECT_FILTER_TABLE        0x00000008
#define HOOK_DETECT_ALL                 0x0000000F

// Maximum hook detection depth
#define MAX_HOOK_CHAIN_DEPTH            10
#define MAX_INSTRUCTION_ANALYSIS_SIZE   64

// Callback protection context
typedef struct _CALLBACK_PROTECTION {
    // Original callback information
    PFLT_OPERATION_REGISTRATION OriginalCallbacks;
    PVOID BackupCallbackMemory;
    ULONG CallbackCount;
    ULONG TableSize;
    ULONG TableChecksum;

    // Protection state
    BOOLEAN IsProtected;
    BOOLEAN IsLocked;
    LARGE_INTEGER LastVerification;
    ULONG ModificationAttempts;
    ULONG HooksDetected;
    ULONG HooksRemoved;

    // Memory protection info
    PMDL CallbackMdl;
    PVOID MappedCallbackMemory;
    ULONG OriginalProtection;

    // Hook detection results
    struct {
        PVOID HookedAddress;
        PVOID HookHandler;
        ULONG HookType;
        UCHAR OriginalBytes[16];
        UCHAR HookBytes[16];
    } DetectedHooks[MAX_HOOK_CHAIN_DEPTH];
    ULONG DetectedHookCount;

} CALLBACK_PROTECTION, * PCALLBACK_PROTECTION;

// Hook information structure
typedef struct _HOOK_INFO {
    PVOID TargetAddress;
    PVOID HookAddress;
    ULONG HookType;
    ULONG HookSize;
    BOOLEAN IsInline;
    BOOLEAN IsDetour;
    UCHAR OriginalBytes[MAX_INSTRUCTION_ANALYSIS_SIZE];
    UCHAR CurrentBytes[MAX_INSTRUCTION_ANALYSIS_SIZE];
    CHAR Description[256];
} HOOK_INFO, * PHOOK_INFO;

// Callback verification result
typedef struct _CALLBACK_VERIFICATION_RESULT {
    ULONG Status;
    ULONG HooksFound;
    ULONG ModificationsFound;
    ULONG CorruptedEntries;
    BOOLEAN IntegrityValid;
    CHAR Details[512];
} CALLBACK_VERIFICATION_RESULT, * PCALLBACK_VERIFICATION_RESULT;

// Function declarations

/**
 * @brief Initialize callback protection system
 * @param FilterHandle Handle to the minifilter
 * @return Allocated protection context or NULL on failure
 */
PCALLBACK_PROTECTION InitializeCallbackProtection(
    _In_ PFLT_FILTER FilterHandle
);

/**
 * @brief Cleanup callback protection
 * @param Protection Protection context to cleanup
 */
VOID CleanupCallbackProtection(
    _In_ PCALLBACK_PROTECTION Protection
);

/**
 * @brief Protect filter callbacks with advanced techniques
 * @param Protection Protection context
 * @param FilterHandle Filter handle
 * @return STATUS_SUCCESS on success
 */
NTSTATUS ProtectFilterCallbacks(
    _In_ PCALLBACK_PROTECTION Protection,
    _In_ PFLT_FILTER FilterHandle
);

/**
 * @brief Verify callback table integrity
 * @param Protection Protection context
 * @param Result Output verification result
 * @return TRUE if integrity is valid
 */
BOOLEAN VerifyCallbackIntegrity(
    _In_ PCALLBACK_PROTECTION Protection,
    _Out_opt_ PCALLBACK_VERIFICATION_RESULT Result
);

/**
 * @brief Restore callback table from backup
 * @param Protection Protection context
 * @return STATUS_SUCCESS on success
 */
NTSTATUS RestoreCallbackTable(
    _In_ PCALLBACK_PROTECTION Protection
);

/**
 * @brief Lock callback memory pages
 * @param Protection Protection context
 * @return STATUS_SUCCESS on success
 */
NTSTATUS LockCallbackMemory(
    _In_ PCALLBACK_PROTECTION Protection
);

/**
 * @brief Unlock callback memory pages
 * @param Protection Protection context
 * @return STATUS_SUCCESS on success
 */
NTSTATUS UnlockCallbackMemory(
    _In_ PCALLBACK_PROTECTION Protection
);

// Hook detection functions

/**
 * @brief Detect hooks in callback functions
 * @param Protection Protection context
 * @param DetectionMethods Methods to use for detection
 * @return Number of hooks detected
 */
ULONG DetectCallbackHooks(
    _In_ PCALLBACK_PROTECTION Protection,
    _In_ ULONG DetectionMethods
);

/**
 * @brief Analyze function for inline hooks
 * @param FunctionAddress Address to analyze
 * @param HookInfo Output hook information
 * @return TRUE if hook detected
 */
BOOLEAN DetectInlineHook(
    _In_ PVOID FunctionAddress,
    _Out_ PHOOK_INFO HookInfo
);

/**
 * @brief Remove detected malicious hooks
 * @param Protection Protection context
 * @return STATUS_SUCCESS on success
 */
NTSTATUS RemoveMaliciousHooks(
    _In_ PCALLBACK_PROTECTION Protection
);

/**
 * @brief Restore original function bytes
 * @param HookInfo Hook information
 * @return STATUS_SUCCESS on success
 */
NTSTATUS RestoreHookedFunction(
    _In_ PHOOK_INFO HookInfo
);

// Memory protection functions

/**
 * @brief Mark callback memory as read-only
 * @param Protection Protection context
 * @return STATUS_SUCCESS on success
 */
NTSTATUS MarkCallbackMemoryReadOnly(
    _In_ PCALLBACK_PROTECTION Protection
);

/**
 * @brief Restore original memory permissions
 * @param Protection Protection context
 * @return STATUS_SUCCESS on success
 */
NTSTATUS RestoreCallbackMemoryPermissions(
    _In_ PCALLBACK_PROTECTION Protection
);

/**
 * @brief Create secure backup of callback memory
 * @param Protection Protection context
 * @return STATUS_SUCCESS on success
 */
NTSTATUS CreateCallbackBackup(
    _In_ PCALLBACK_PROTECTION Protection
);

// Analysis functions

/**
 * @brief Analyze callback for suspicious patterns
 * @param CallbackAddress Callback function address
 * @param PatternBuffer Buffer for pattern data
 * @param BufferSize Size of pattern buffer
 * @return TRUE if suspicious pattern found
 */
BOOLEAN AnalyzeCallbackPattern(
    _In_ PVOID CallbackAddress,
    _Out_writes_bytes_(BufferSize) PVOID PatternBuffer,
    _In_ ULONG BufferSize
);

/**
 * @brief Calculate callback chain depth
 * @param StartAddress Starting callback address
 * @param MaxDepth Maximum depth to check
 * @return Actual chain depth
 */
ULONG CalculateCallbackChainDepth(
    _In_ PVOID StartAddress,
    _In_ ULONG MaxDepth
);

/**
 * @brief Validate callback function prologue
 * @param FunctionAddress Function to validate
 * @return TRUE if prologue is valid
 */
BOOLEAN ValidateFunctionPrologue(
    _In_ PVOID FunctionAddress
);

// Utility functions

/**
 * @brief Get callback table from filter
 * @param FilterHandle Filter handle
 * @param CallbackTable Output callback table pointer
 * @param TableSize Output table size
 * @return STATUS_SUCCESS on success
 */
NTSTATUS GetCallbackTableFromFilter(
    _In_ PFLT_FILTER FilterHandle,
    _Out_ PFLT_OPERATION_REGISTRATION* CallbackTable,
    _Out_ PULONG TableSize
);

/**
 * @brief Disassemble instruction at address
 * @param Address Instruction address
 * @param InstructionInfo Output instruction information
 * @return Instruction length or 0 on error
 */
ULONG DisassembleInstruction(
    _In_ PVOID Address,
    _Out_ PVOID InstructionInfo
);

/**
 * @brief Check if address is within driver range
 * @param Address Address to check
 * @param DriverBase Driver base address
 * @param DriverSize Driver size
 * @return TRUE if within range
 */
BOOLEAN IsAddressInDriverRange(
    _In_ PVOID Address,
    _In_ PVOID DriverBase,
    _In_ ULONG DriverSize
);

/**
 * @brief Log callback protection event
 * @param Protection Protection context
 * @param EventType Type of event
 * @param Description Event description
 */
VOID LogCallbackProtectionEvent(
    _In_ PCALLBACK_PROTECTION Protection,
    _In_ ULONG EventType,
    _In_ PCHAR Description
);

// Advanced protection features

/**
 * @brief Enable callback address space layout randomization
 * @param Protection Protection context
 * @return STATUS_SUCCESS on success
 */
NTSTATUS EnableCallbackASLR(
    _In_ PCALLBACK_PROTECTION Protection
);

/**
 * @brief Create callback execution trap
 * @param Protection Protection context
 * @param TrapAddress Address for trap
 * @return STATUS_SUCCESS on success
 */
NTSTATUS CreateCallbackTrap(
    _In_ PCALLBACK_PROTECTION Protection,
    _In_ PVOID TrapAddress
);

/**
 * @brief Verify callback execution flow
 * @param Protection Protection context
 * @param CallbackAddress Callback being executed
 * @return TRUE if execution flow is valid
 */
BOOLEAN VerifyCallbackExecutionFlow(
    _In_ PCALLBACK_PROTECTION Protection,
    _In_ PVOID CallbackAddress
);

// _CRYPTOSHIELD_CALLBACKPROTECTION_H_