/**
 * @file HookDetection.h
 * @brief Hook detection and prevention system interface
 * @details Detects and prevents various types of kernel hooks and code modifications
 *
 * @author CryptoShield Team
 * @date 2025
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include <ntddk.h>
#include <fltKernel.h>
#include "SelfProtection.h"

 // Hook types
typedef enum _HOOK_TYPE {
    HOOK_TYPE_NONE = 0,
    HOOK_TYPE_SSDT = 1,
    HOOK_TYPE_IDT = 2,
    HOOK_TYPE_IRP_HANDLER = 4,
    HOOK_TYPE_FILTER_CALLBACK = 8,
    HOOK_TYPE_INLINE = 16,
    HOOK_TYPE_IAT = 32,
    HOOK_TYPE_EAT = 64,
    HOOK_TYPE_OBJECT_HOOK = 128,
    HOOK_TYPE_ALL = 0xFF
} HOOK_TYPE;

// Hook detection methods
#define HOOK_DETECT_SIGNATURE       0x00000001
#define HOOK_DETECT_PATTERN         0x00000002
#define HOOK_DETECT_CHECKSUM        0x00000004
#define HOOK_DETECT_RANGE_CHECK     0x00000008
#define HOOK_DETECT_INSTRUCTION     0x00000010
#define HOOK_DETECT_ALL            0x0000001F

// Maximum detection limits
#define MAX_HOOK_DETECTIONS         100
#define MAX_SSDT_ENTRIES           0x200
#define MAX_IDT_ENTRIES            0x100
#define MAX_INSTRUCTION_BYTES      32
#define MAX_PATTERN_SIZE           64

// SSDT hook information
typedef struct _SSDT_HOOK_INFO {
    ULONG ServiceIndex;
    PVOID OriginalAddress;
    PVOID CurrentAddress;
    PVOID HookHandler;
    BOOLEAN IsHooked;
    WCHAR ServiceName[64];
} SSDT_HOOK_INFO, * PSSDT_HOOK_INFO;

// IDT hook information
typedef struct _IDT_HOOK_INFO {
    ULONG VectorNumber;
    PVOID OriginalHandler;
    PVOID CurrentHandler;
    BOOLEAN IsHooked;
    WCHAR Description[64];
} IDT_HOOK_INFO, * PIDT_HOOK_INFO;

// IRP handler hook information
typedef struct _IRP_HOOK_INFO {
    PDRIVER_OBJECT DriverObject;
    ULONG MajorFunction;
    PVOID OriginalHandler;
    PVOID CurrentHandler;
    BOOLEAN IsHooked;
    WCHAR DriverName[64];
} IRP_HOOK_INFO, * PIRP_HOOK_INFO;

// Inline hook information
typedef struct _INLINE_HOOK_INFO {
    PVOID FunctionAddress;
    UCHAR OriginalBytes[MAX_INSTRUCTION_BYTES];
    UCHAR CurrentBytes[MAX_INSTRUCTION_BYTES];
    ULONG HookedBytesCount;
    PVOID JumpTarget;
    BOOLEAN IsHooked;
    HOOK_TYPE HookMethod;
} INLINE_HOOK_INFO, * PINLINE_HOOK_INFO;

// Generic hook detection result
typedef struct _HOOK_DETECTION_RESULT {
    HOOK_TYPE HookType;
    PVOID HookedAddress;
    PVOID OriginalAddress;
    PVOID HookHandler;
    BOOLEAN IsMalicious;
    ULONG ConfidenceLevel;  // 0-100
    WCHAR Description[256];
    union {
        SSDT_HOOK_INFO SsdtInfo;
        IDT_HOOK_INFO IdtInfo;
        IRP_HOOK_INFO IrpInfo;
        INLINE_HOOK_INFO InlineInfo;
    } Details;
} HOOK_DETECTION_RESULT, * PHOOK_DETECTION_RESULT;

// Hook pattern definition
typedef struct _HOOK_PATTERN {
    UCHAR Pattern[MAX_PATTERN_SIZE];
    ULONG PatternLength;
    ULONG Offset;
    WCHAR Description[128];
    BOOLEAN IsMalicious;
} HOOK_PATTERN, * PHOOK_PATTERN;

// Hook detection context
typedef struct _HOOK_DETECTION_CONTEXT {
    // SSDT information
    PVOID SsdtBase;
    ULONG SsdtEntries;
    PVOID* OriginalSsdtTable;

    // IDT information
    PVOID IdtBase;
    ULONG IdtEntries;

    // Detection configuration
    ULONG DetectionMethods;
    BOOLEAN EnableAutoRemoval;
    BOOLEAN EnableLogging;

    // Detection statistics
    ULONG TotalScans;
    ULONG HooksDetected;
    ULONG HooksRemoved;
    ULONG FalsePositives;

    // Synchronization
    KSPIN_LOCK DetectionLock;
    ERESOURCE ScanResource;

    // Pattern database
    HOOK_PATTERN KnownPatterns[MAX_HOOK_DETECTIONS];
    ULONG PatternCount;

} HOOK_DETECTION_CONTEXT, * PHOOK_DETECTION_CONTEXT;

// Function declarations

/**
 * @brief Initialize hook detection system
 * @param Context Protection context
 * @return Allocated detection context or NULL
 */
PHOOK_DETECTION_CONTEXT InitializeHookDetection(
    _In_ PPROTECTION_CONTEXT Context
);

/**
 * @brief Cleanup hook detection system
 * @param DetectionContext Context to cleanup
 */
VOID CleanupHookDetection(
    _In_ PHOOK_DETECTION_CONTEXT DetectionContext
);

// SSDT hook detection

/**
 * @brief Detect SSDT hooks
 * @param Context Detection context
 * @param Results Output array for results
 * @param MaxResults Maximum results to return
 * @param DetectedCount Output count of detections
 * @return STATUS_SUCCESS on success
 */
NTSTATUS DetectSSDTHooks(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _Out_writes_(MaxResults) PHOOK_DETECTION_RESULT Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG DetectedCount
);

/**
 * @brief Get original SSDT address for service
 * @param ServiceIndex Service table index
 * @param OriginalAddress Output original address
 * @return STATUS_SUCCESS if found
 */
NTSTATUS GetOriginalSSDTAddress(
    _In_ ULONG ServiceIndex,
    _Out_ PVOID* OriginalAddress
);

// IDT hook detection

/**
 * @brief Detect IDT hooks
 * @param Context Detection context
 * @param Results Output array for results
 * @param MaxResults Maximum results to return
 * @param DetectedCount Output count of detections
 * @return STATUS_SUCCESS on success
 */
NTSTATUS DetectIDTHooks(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _Out_writes_(MaxResults) PHOOK_DETECTION_RESULT Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG DetectedCount
);

/**
 * @brief Validate IDT handler address
 * @param VectorNumber Interrupt vector
 * @param HandlerAddress Handler address to validate
 * @return TRUE if valid
 */
BOOLEAN ValidateIDTHandler(
    _In_ ULONG VectorNumber,
    _In_ PVOID HandlerAddress
);

// IRP handler hook detection

/**
 * @brief Detect IRP handler hooks
 * @param Context Detection context
 * @param DriverObject Driver to check
 * @param Results Output array for results
 * @param MaxResults Maximum results to return
 * @param DetectedCount Output count of detections
 * @return STATUS_SUCCESS on success
 */
NTSTATUS DetectIRPHooks(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ PDRIVER_OBJECT DriverObject,
    _Out_writes_(MaxResults) PHOOK_DETECTION_RESULT Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG DetectedCount
);

// Inline hook detection

/**
 * @brief Detect inline hooks in function
 * @param Context Detection context
 * @param FunctionAddress Function to analyze
 * @param Result Output detection result
 * @return TRUE if hook detected
 */
BOOLEAN DetectInlineHooks(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ PVOID FunctionAddress,
    _Out_ PHOOK_DETECTION_RESULT Result
);

/**
 * @brief Analyze function prologue for hooks
 * @param FunctionAddress Function address
 * @param HookInfo Output hook information
 * @return TRUE if hooked
 */
BOOLEAN AnalyzeFunctionPrologue(
    _In_ PVOID FunctionAddress,
    _Out_ PINLINE_HOOK_INFO HookInfo
);

// Filter callback hook detection

/**
 * @brief Detect minifilter callback hooks
 * @param Context Detection context
 * @param FilterHandle Filter to check
 * @param Results Output array for results
 * @param MaxResults Maximum results to return
 * @param DetectedCount Output count of detections
 * @return STATUS_SUCCESS on success
 */
NTSTATUS DetectFilterCallbackHooks(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ PFLT_FILTER FilterHandle,
    _Out_writes_(MaxResults) PHOOK_DETECTION_RESULT Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG DetectedCount
);

// Hook removal and restoration

/**
 * @brief Remove detected hook
 * @param Context Detection context
 * @param HookResult Hook to remove
 * @return STATUS_SUCCESS on success
 */
NTSTATUS RemoveDetectedHook(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ PHOOK_DETECTION_RESULT HookResult
);

/**
 * @brief Restore original function bytes
 * @param FunctionAddress Function to restore
 * @param OriginalBytes Original bytes to write
 * @param ByteCount Number of bytes
 * @return STATUS_SUCCESS on success
 */
NTSTATUS RestoreOriginalBytes(
    _In_ PVOID FunctionAddress,
    _In_reads_(ByteCount) PUCHAR OriginalBytes,
    _In_ ULONG ByteCount
);

/**
 * @brief Restore hooked SSDT entry
 * @param ServiceIndex Service index
 * @param OriginalAddress Original handler address
 * @return STATUS_SUCCESS on success
 */
NTSTATUS RestoreSSDTEntry(
    _In_ ULONG ServiceIndex,
    _In_ PVOID OriginalAddress
);

// Pattern-based detection

/**
 * @brief Add hook pattern to database
 * @param Context Detection context
 * @param Pattern Pattern to add
 * @return STATUS_SUCCESS on success
 */
NTSTATUS AddHookPattern(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ PHOOK_PATTERN Pattern
);

/**
 * @brief Scan memory for hook patterns
 * @param Context Detection context
 * @param StartAddress Start of scan range
 * @param Size Size of scan range
 * @param Results Output array for results
 * @param MaxResults Maximum results to return
 * @param DetectedCount Output count of detections
 * @return STATUS_SUCCESS on success
 */
NTSTATUS ScanForHookPatterns(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ PVOID StartAddress,
    _In_ SIZE_T Size,
    _Out_writes_(MaxResults) PHOOK_DETECTION_RESULT Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG DetectedCount
);

// Comprehensive scanning

/**
 * @brief Perform comprehensive hook scan
 * @param Context Detection context
 * @param ScanTypes Types to scan (HOOK_TYPE flags)
 * @param Results Output array for results
 * @param MaxResults Maximum results to return
 * @param DetectedCount Output count of detections
 * @return STATUS_SUCCESS on success
 */
NTSTATUS PerformHookScan(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ ULONG ScanTypes,
    _Out_writes_(MaxResults) PHOOK_DETECTION_RESULT Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG DetectedCount
);

// Utility functions

/**
 * @brief Disassemble instruction
 * @param Address Instruction address
 * @param Instruction Output instruction info
 * @param InstructionLength Output instruction length
 * @return STATUS_SUCCESS on success
 */
NTSTATUS DisassembleInstruction(
    _In_ PVOID Address,
    _Out_writes_bytes_(MAX_INSTRUCTION_BYTES) PUCHAR Instruction,
    _Out_ PULONG InstructionLength
);

/**
 * @brief Calculate jump target from instruction
 * @param InstructionAddress Instruction address
 * @param JumpTarget Output jump target
 * @return TRUE if jump instruction found
 */
BOOLEAN CalculateJumpTarget(
    _In_ PVOID InstructionAddress,
    _Out_ PVOID* JumpTarget
);

/**
 * @brief Verify address is within valid kernel range
 * @param Address Address to verify
 * @return TRUE if valid kernel address
 */
BOOLEAN IsValidKernelAddress(
    _In_ PVOID Address
);

/**
 * @brief Get driver for address
 * @param Address Code address
 * @param DriverBase Output driver base
 * @param DriverName Output driver name
 * @param NameSize Size of name buffer
 * @return STATUS_SUCCESS if found
 */
NTSTATUS GetDriverForAddress(
    _In_ PVOID Address,
    _Out_opt_ PVOID* DriverBase,
    _Out_writes_z_(NameSize) PWCHAR DriverName,
    _In_ SIZE_T NameSize
);

/**
 * @brief Log hook detection event
 * @param Context Detection context
 * @param Detection Detection result
 */
VOID LogHookDetection(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _In_ PHOOK_DETECTION_RESULT Detection
);

/**
 * @brief Initialize known hook patterns
 * @param Context Detection context
 */
VOID InitializeKnownPatterns(
    _In_ PHOOK_DETECTION_CONTEXT Context
);

// Statistics and reporting

/**
 * @brief Get hook detection statistics
 * @param Context Detection context
 * @param TotalScans Output total scans
 * @param HooksDetected Output hooks detected
 * @param HooksRemoved Output hooks removed
 */
VOID GetHookDetectionStatistics(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _Out_opt_ PULONG TotalScans,
    _Out_opt_ PULONG HooksDetected,
    _Out_opt_ PULONG HooksRemoved
);

/**
 * @brief Generate hook detection report
 * @param Context Detection context
 * @param ReportBuffer Output report buffer
 * @param BufferSize Size of buffer
 * @return Bytes written
 */
ULONG GenerateHookReport(
    _In_ PHOOK_DETECTION_CONTEXT Context,
    _Out_writes_bytes_(BufferSize) PWCHAR ReportBuffer,
    _In_ ULONG BufferSize
);

// _CRYPTOSHIELD_HOOKDETECTION_H_