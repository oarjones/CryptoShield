#include "CryptoShield.h" // Should include fltKernel.h or ensure fltKernel.h is included before this
#include <dontuse.h>      // For PSECURITY_DESCRIPTOR, InitializeObjectAttributes. Minifilter drivers usually include fltKernel.h which includes necessary headers.
#include <wdm.h>          // For KeInitializeSpinLock, ExAllocatePoolZero, ExFreePoolWithTag, etc.

// Global driver context variable
PCRYPTOSHIELD_CONTEXT g_CryptoShieldContext = NULL;

// Forward declarations for callbacks to be implemented in other files
FLT_PREOP_CALLBACK_STATUS PreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

NTSTATUS ConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
);

VOID DisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS MessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);

// Operation Callbacks definition
// Note: Standard C initialization for array of structs uses single braces for each struct.
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,          0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_WRITE,           0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_SET_INFORMATION, 0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_CLEANUP,         0, PreOperationCallback, NULL                  },
    { IRP_MJ_OPERATION_END }
};

// Context Registration structure
const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    { FLT_CONTEXT_END }
};

// Filter Registration structure definition
const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),         // Size
    FLT_REGISTRATION_VERSION,         // Version
    0,                                // Flags
    ContextRegistration,              // ContextRegistration
    Callbacks,                        // OperationRegistration
    FilterUnloadCallback,             // FilterUnloadCallback
    NULL,                             // InstanceSetupCallback
    NULL,                             // InstanceQueryTeardownCallback
    NULL,                             // InstanceTeardownStartCallback
    NULL,                             // InstanceTeardownCompleteCallback
    NULL,                             // GenerateFileNameCallback
    NULL,                             // NormalizeNameComponentCallback
    NULL                              // NormalizeContextCleanupCallback
#if FLT_MGR_METADATA_VERSION >= FLT_MGR_METADATA_VERSION_V1_1 // Use FLT_MGR_METADATA_VERSION for current WDKs
    ,NULL                             // TransactionNotificationCallback
    ,NULL                             // NormalizeNameComponentExCallback
#endif
#if FLT_MGR_METADATA_VERSION >= FLT_MGR_METADATA_VERSION_V2_0
    ,NULL                             // SectionNotificationCallback
#endif
};


NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName = RTL_CONSTANT_STRING(L"\\CryptoShieldPort");

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("CryptoShield: DriverEntry - Loading driver.\n"));

    g_CryptoShieldContext = (PCRYPTOSHIELD_CONTEXT)ExAllocatePoolZero(
        NonPagedPool,
        sizeof(CRYPTOSHIELD_CONTEXT),
        CRYPTOSHIELD_TAG
    );

    if (g_CryptoShieldContext == NULL) {
        KdPrint(("CryptoShield: DriverEntry - Failed to allocate driver context.\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeSpinLock(&g_CryptoShieldContext->StatisticsLock);
    g_CryptoShieldContext->MonitoringEnabled = TRUE;
    g_CryptoShieldContext->DetectionSensitivity = 1;
    g_CryptoShieldContext->FileOperationCount = 0;
    g_CryptoShieldContext->MessagesSent = 0;
    g_CryptoShieldContext->ClientPort = NULL;
    g_CryptoShieldContext->ServerPort = NULL;
    g_CryptoShieldContext->FilterHandle = NULL;

    status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &g_CryptoShieldContext->FilterHandle
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("CryptoShield: DriverEntry - FltRegisterFilter failed (0x%08X).\n", status));
        ExFreePoolWithTag(g_CryptoShieldContext, CRYPTOSHIELD_TAG);
        g_CryptoShieldContext = NULL;
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        KdPrint(("CryptoShield: DriverEntry - FltBuildDefaultSecurityDescriptor failed (0x%08X).\n", status));
        FltUnregisterFilter(g_CryptoShieldContext->FilterHandle);
        ExFreePoolWithTag(g_CryptoShieldContext, CRYPTOSHIELD_TAG);
        g_CryptoShieldContext = NULL;
        return status;
    }

    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,    
        sd      
    );

    status = FltCreateCommunicationPort(
        g_CryptoShieldContext->FilterHandle,
        &g_CryptoShieldContext->ServerPort,
        &oa,
        NULL, 
        ConnectNotifyCallback,
        DisconnectNotifyCallback,
        MessageNotifyCallback,
        1 
    );

    FltFreeSecurityDescriptor(sd); 
    sd = NULL; 

    if (!NT_SUCCESS(status)) {
        KdPrint(("CryptoShield: DriverEntry - FltCreateCommunicationPort failed (0x%08X).\n", status));
        FltUnregisterFilter(g_CryptoShieldContext->FilterHandle);
        ExFreePoolWithTag(g_CryptoShieldContext, CRYPTOSHIELD_TAG);
        g_CryptoShieldContext = NULL;
        return status;
    }

    status = FltStartFiltering(g_CryptoShieldContext->FilterHandle);

    if (!NT_SUCCESS(status)) {
        KdPrint(("CryptoShield: DriverEntry - FltStartFiltering failed (0x%08X).\n", status));
        if (g_CryptoShieldContext->ServerPort) { // Check if port was created before trying to close
            FltCloseServerPort(g_CryptoShieldContext->FilterHandle, &g_CryptoShieldContext->ServerPort);
        }
        FltUnregisterFilter(g_CryptoShieldContext->FilterHandle);
        ExFreePoolWithTag(g_CryptoShieldContext, CRYPTOSHIELD_TAG);
        g_CryptoShieldContext = NULL;
        return status;
    }

    KdPrint(("CryptoShield: DriverEntry - Driver loaded and filtering started successfully.\n"));
    return STATUS_SUCCESS;
}

NTSTATUS FilterUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE(); 

    KdPrint(("CryptoShield: FilterUnloadCallback - Unloading driver.\n"));

    if (g_CryptoShieldContext == NULL) {
        KdPrint(("CryptoShield: FilterUnloadCallback - Global context is already NULL.\n"));
        return STATUS_SUCCESS; 
    }

    if (g_CryptoShieldContext->ServerPort) {
        FltCloseServerPort(g_CryptoShieldContext->FilterHandle, &g_CryptoShieldContext->ServerPort); 
        g_CryptoShieldContext->ServerPort = NULL; 
    }

    if (g_CryptoShieldContext->FilterHandle) {
        FltUnregisterFilter(g_CryptoShieldContext->FilterHandle);
        g_CryptoShieldContext->FilterHandle = NULL;
    }
    
    // Check g_CryptoShieldContext again before freeing, though the initial check should be enough
    // if no other code path nullifies it without full cleanup.
    if (g_CryptoShieldContext) { 
       ExFreePoolWithTag(g_CryptoShieldContext, CRYPTOSHIELD_TAG);
       g_CryptoShieldContext = NULL;
    }

    KdPrint(("CryptoShield: FilterUnloadCallback - Driver unloaded successfully.\n"));
    return STATUS_SUCCESS;
}
