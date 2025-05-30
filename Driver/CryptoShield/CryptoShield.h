/**
 * @file CryptoShield.h
 * @brief Main header file for CryptoShield minifilter driver
 * @details Contains core definitions, structures and function declarations
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

 // Driver identification
#define CRYPTOSHIELD_DRIVER_NAME     L"CryptoShield"
#define CRYPTOSHIELD_DRIVER_VERSION  L"1.0.0"
#define CRYPTOSHIELD_POOL_TAG        'dShC'  // 'CShd' in reverse

// Communication port
#define CRYPTOSHIELD_PORT_NAME       L"\\CryptoShieldPort"
#define MAX_PORT_CONNECTIONS         1

// Configuration defaults
#define DEFAULT_MONITORING_ENABLED   TRUE
#define DEFAULT_DETECTION_SENSITIVITY 50
#define MAX_FILE_PATH_LENGTH         520  // MAX_PATH * 2 for Unicode

// Message types for kernel-user communication
#define MSG_FILE_OPERATION          1
#define MSG_STATUS_REQUEST          2
#define MSG_CONFIG_UPDATE           3
#define MSG_SHUTDOWN_REQUEST        4

// File operation types
#define FILE_OP_CREATE              1
#define FILE_OP_WRITE               2
#define FILE_OP_DELETE              3
#define FILE_OP_RENAME              4
#define FILE_OP_SET_INFORMATION     5

// Driver context structure
typedef struct _CRYPTOSHIELD_CONTEXT {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;

    // Configuration
    BOOLEAN MonitoringEnabled;
    ULONG DetectionSensitivity;

    // Statistics
    volatile LONG FileOperationCount;
    volatile LONG MessagesSent;
    volatile LONG MessagesReceived;

    // Synchronization
    KSPIN_LOCK StatisticsLock;
    KSPIN_LOCK ConfigLock;
    ERESOURCE PortResource;

    // Status flags
    BOOLEAN IsUnloading;
    BOOLEAN ClientConnected;

} CRYPTOSHIELD_CONTEXT, * PCRYPTOSHIELD_CONTEXT;

// Global driver context
extern CRYPTOSHIELD_CONTEXT g_Context;

// Filter message structure for communication
typedef struct _CRYPTOSHIELD_MESSAGE {
    FILTER_MESSAGE_HEADER Header;

    // Message data
    ULONG MessageType;
    ULONG ProcessId;
    ULONG ThreadId;
    LARGE_INTEGER Timestamp;
    ULONG OperationType;

    // File information
    USHORT FilePathLength;
    WCHAR FilePath[MAX_FILE_PATH_LENGTH];

} CRYPTOSHIELD_MESSAGE, * PCRYPTOSHIELD_MESSAGE;

// Reply message structure
typedef struct _CRYPTOSHIELD_REPLY {
    FILTER_REPLY_HEADER Header;
    NTSTATUS Status;
    BOOLEAN AllowOperation;
} CRYPTOSHIELD_REPLY, * PCRYPTOSHIELD_REPLY;

// Function declarations - DriverEntry and Unload
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS CryptoShieldUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

// Pre/Post operation callbacks
FLT_PREOP_CALLBACK_STATUS CryptoShieldPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS CryptoShieldPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// Instance setup/teardown callbacks
NTSTATUS CryptoShieldInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS CryptoShieldInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

// Communication callbacks
NTSTATUS CryptoShieldConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie
);

VOID CryptoShieldDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS CryptoShieldMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);

// Utility functions
NTSTATUS SendFileOperationMessage(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG OperationType
);

NTSTATUS GetFileNameInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_writes_bytes_(FileNameBufferSize) PWCHAR FileNameBuffer,
    _In_ ULONG FileNameBufferSize,
    _Out_ PULONG ReturnedLength
);

VOID UpdateStatistics(
    _In_ ULONG StatType
);

// Debug/Logging macros
#if DBG
#define CS_DBG_PRINT(Level, Fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, Level, "[CryptoShield] " Fmt "\n", __VA_ARGS__)
#else
#define CS_DBG_PRINT(Level, Fmt, ...)
#endif

#define CS_ERROR(Fmt, ...)   CS_DBG_PRINT(DPFLTR_ERROR_LEVEL, Fmt, __VA_ARGS__)
#define CS_WARNING(Fmt, ...) CS_DBG_PRINT(DPFLTR_WARNING_LEVEL, Fmt, __VA_ARGS__)
#define CS_INFO(Fmt, ...)    CS_DBG_PRINT(DPFLTR_INFO_LEVEL, Fmt, __VA_ARGS__)
#define CS_TRACE(Fmt, ...)   CS_DBG_PRINT(DPFLTR_TRACE_LEVEL, Fmt, __VA_ARGS__)

// Memory allocation helpers
#define CS_ALLOC_POOL(Size) \
    ExAllocatePoolWithTag(NonPagedPool, Size, CRYPTOSHIELD_POOL_TAG)

#define CS_FREE_POOL(Buffer) \
    ExFreePoolWithTag(Buffer, CRYPTOSHIELD_POOL_TAG)

// IRQL verification helpers
#define CS_VERIFY_IRQL_PASSIVE() \
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL)

#define CS_VERIFY_IRQL_APC_OR_BELOW() \
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL)