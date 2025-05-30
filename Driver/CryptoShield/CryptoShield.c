/**
 * @file CryptoShield.c
 * @brief Main implementation file for CryptoShield minifilter driver
 * @details Contains driver entry point, filter registration and core callbacks
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "CryptoShield.h"

 // Global driver context
CRYPTOSHIELD_CONTEXT g_Context = { 0 };

// Operation registration - defines which I/O operations we want to intercept
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      CryptoShieldPreOperation,
      CryptoShieldPostOperation },

    { IRP_MJ_WRITE,
      0,
      CryptoShieldPreOperation,
      CryptoShieldPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      CryptoShieldPreOperation,
      CryptoShieldPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      CryptoShieldPreOperation,
      NULL },  // No post-operation needed for cleanup

    { IRP_MJ_OPERATION_END }
};

// Filter registration structure
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version
    0,                                  // Flags
    NULL,                               // Context registration
    Callbacks,                          // Operation callbacks
    CryptoShieldUnload,                 // FilterUnload
    CryptoShieldInstanceSetup,          // InstanceSetup
    CryptoShieldInstanceQueryTeardown,  // InstanceQueryTeardown
    NULL,                               // InstanceTeardownStart
    NULL,                               // InstanceTeardownComplete
    NULL,                               // GenerateFileName
    NULL,                               // GenerateDestinationFileName
    NULL                                // NormalizeNameComponent
};

/**
 * @brief Driver entry point
 * @details Initializes the minifilter driver and registers with Filter Manager
 *
 * @param DriverObject Driver object created by system
 * @param RegistryPath Registry path for driver parameters
 * @return STATUS_SUCCESS on success, appropriate error code on failure
 */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING portName = { 0 };

    UNREFERENCED_PARAMETER(RegistryPath);

    CS_INFO("CryptoShield driver loading, version %ws", CRYPTOSHIELD_DRIVER_VERSION);

    __try {
        // Initialize driver context
        RtlZeroMemory(&g_Context, sizeof(CRYPTOSHIELD_CONTEXT));

        // Initialize synchronization objects
        KeInitializeSpinLock(&g_Context.StatisticsLock);
        KeInitializeSpinLock(&g_Context.ConfigLock);
        status = ExInitializeResourceLite(&g_Context.PortResource);
        if (!NT_SUCCESS(status)) {
            CS_ERROR("Failed to initialize port resource: 0x%08x", status);
            __leave;
        }

        // Set default configuration
        g_Context.MonitoringEnabled = DEFAULT_MONITORING_ENABLED;
        g_Context.DetectionSensitivity = DEFAULT_DETECTION_SENSITIVITY;

        // Register with Filter Manager
        status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_Context.FilterHandle);
        if (!NT_SUCCESS(status)) {
            CS_ERROR("Failed to register filter: 0x%08x", status);
            __leave;
        }

        // Create communication port
        status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
        if (!NT_SUCCESS(status)) {
            CS_ERROR("Failed to build security descriptor: 0x%08x", status);
            __leave;
        }

        RtlInitUnicodeString(&portName, CRYPTOSHIELD_PORT_NAME);
        InitializeObjectAttributes(&oa,
            &portName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            sd);

        status = FltCreateCommunicationPort(g_Context.FilterHandle,
            &g_Context.ServerPort,
            &oa,
            NULL,  // ServerPortCookie
            CryptoShieldConnectNotify,
            CryptoShieldDisconnectNotify,
            CryptoShieldMessageNotify,
            MAX_PORT_CONNECTIONS);

        if (!NT_SUCCESS(status)) {
            CS_ERROR("Failed to create communication port: 0x%08x", status);
            __leave;
        }

        // Start filtering
        status = FltStartFiltering(g_Context.FilterHandle);
        if (!NT_SUCCESS(status)) {
            CS_ERROR("Failed to start filtering: 0x%08x", status);
            __leave;
        }

        CS_INFO("CryptoShield driver loaded successfully");

    }
    __finally {

        if (sd != NULL) {
            FltFreeSecurityDescriptor(sd);
        }

        if (!NT_SUCCESS(status)) {
            // Cleanup on failure
            if (g_Context.ServerPort != NULL) {
                FltCloseCommunicationPort(g_Context.ServerPort);
                g_Context.ServerPort = NULL;
            }

            if (g_Context.FilterHandle != NULL) {
                FltUnregisterFilter(g_Context.FilterHandle);
                g_Context.FilterHandle = NULL;
            }

            ExDeleteResourceLite(&g_Context.PortResource);
        }
    }

    return status;
}

/**
 * @brief Filter unload routine
 * @details Cleans up resources and unregisters the filter
 *
 * @param Flags Unload flags
 * @return STATUS_SUCCESS on success, STATUS_FLT_DO_NOT_DETACH if unsafe
 */
NTSTATUS CryptoShieldUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    CS_INFO("CryptoShield driver unloading");

    // Set unloading flag
    InterlockedExchange8((CHAR*)&g_Context.IsUnloading, TRUE);

    // Close communication port
    if (g_Context.ServerPort != NULL) {
        FltCloseCommunicationPort(g_Context.ServerPort);
        g_Context.ServerPort = NULL;
    }

    // Wait for any pending operations
    // In a production driver, we would implement proper synchronization here

    // Unregister filter
    if (g_Context.FilterHandle != NULL) {
        FltUnregisterFilter(g_Context.FilterHandle);
        g_Context.FilterHandle = NULL;
    }

    // Cleanup synchronization objects
    ExDeleteResourceLite(&g_Context.PortResource);

    CS_INFO("CryptoShield driver unloaded successfully");
    CS_INFO("Total file operations monitored: %d", g_Context.FileOperationCount);
    CS_INFO("Total messages sent: %d", g_Context.MessagesSent);

    return STATUS_SUCCESS;
}

/**
 * @brief Pre-operation callback
 * @details Called before an I/O operation is passed to the file system
 *
 * @param Data Callback data with operation information
 * @param FltObjects Filter objects for this operation
 * @param CompletionContext Context to pass to post-operation callback
 * @return FLT_PREOP_SUCCESS_WITH_CALLBACK to continue with post-operation
 */
FLT_PREOP_CALLBACK_STATUS CryptoShieldPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS status;
    ULONG operationType = 0;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Check if we're unloading
    if (g_Context.IsUnloading) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check if monitoring is enabled
    if (!g_Context.MonitoringEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Skip kernel requests
    if (Data->Iopb->OperationFlags & SL_OPEN_PAGING_FILE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Determine operation type
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        operationType = FILE_OP_CREATE;
        break;
    case IRP_MJ_WRITE:
        operationType = FILE_OP_WRITE;
        break;
    case IRP_MJ_SET_INFORMATION:
        if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation ||
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformationEx) {
            operationType = FILE_OP_DELETE;
        }
        else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx) {
            operationType = FILE_OP_RENAME;
        }
        else {
            operationType = FILE_OP_SET_INFORMATION;
        }
        break;
    case IRP_MJ_CLEANUP:
        // We monitor cleanup but don't send messages for it
        InterlockedIncrement(&g_Context.FileOperationCount);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Update statistics
    InterlockedIncrement(&g_Context.FileOperationCount);

    // Send message to user mode if client is connected
    if (g_Context.ClientConnected) {
        status = SendFileOperationMessage(Data, operationType);
        if (!NT_SUCCESS(status)) {
            CS_WARNING("Failed to send file operation message: 0x%08x", status);
        }
    }

    // For now, we always allow operations
    // In later tasks, we'll implement blocking based on detection
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/**
 * @brief Post-operation callback
 * @details Called after an I/O operation completes
 *
 * @param Data Callback data with operation information
 * @param FltObjects Filter objects for this operation
 * @param CompletionContext Context from pre-operation callback
 * @param Flags Post-operation flags
 * @return FLT_POSTOP_FINISHED_PROCESSING
 */
FLT_POSTOP_CALLBACK_STATUS CryptoShieldPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    // In this basic implementation, we don't do anything in post-operation
    // Later tasks will add analysis here

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/**
 * @brief Instance setup callback
 * @details Called when filter attaches to a volume
 *
 * @param FltObjects Filter objects for this instance
 * @param Flags Setup flags
 * @param VolumeDeviceType Type of volume device
 * @param VolumeFilesystemType Type of file system
 * @return STATUS_SUCCESS to attach, STATUS_FLT_DO_NOT_ATTACH to skip
 */
NTSTATUS CryptoShieldInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    CS_INFO("Instance setup for volume type %d, filesystem %d",
        VolumeDeviceType, VolumeFilesystemType);

    // We only attach to disk file systems
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) {
        CS_INFO("Skipping non-disk volume");
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    // Skip read-only volumes
    if (FlagOn(Flags, FLTFL_INSTANCE_SETUP_NEWLY_MOUNTED_VOLUME) &&
        FltObjects->Volume != NULL) {
        // Would check volume properties here in production
    }

    CS_INFO("Attaching to volume");
    return STATUS_SUCCESS;
}

/**
 * @brief Instance query teardown callback
 * @details Called when filter is about to detach from a volume
 *
 * @param FltObjects Filter objects for this instance
 * @param Flags Query teardown flags
 * @return STATUS_SUCCESS to allow detach
 */
NTSTATUS CryptoShieldInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    CS_INFO("Instance query teardown");

    // Always allow detach in this basic implementation
    return STATUS_SUCCESS;
}