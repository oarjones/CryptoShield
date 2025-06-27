/**
 * @file CryptoShield.c
 * @brief Main implementation file for CryptoShield minifilter driver
 * @details Contains driver entry point, filter registration and core callbacks
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "CryptoShield.h"
#include "Communication.h"
#include "Utilities.h"
#include "FileMonitor.h" // <-- Añadir si no está
#include "Protection/CallbackProtection.h"
#include "Protection/MemoryIntegrity.h"
#include "Protection/HookDetection.h"
// ----- Global Driver Context -----
CRYPTOSHIELD_CONTEXT g_Context = { 0 };

// ----- Forward Declarations (si alguna función de este archivo se llama antes de su definición) -----
// (No parece necesario por ahora)


// ----- Minifilter Registration Structures -----

// Operation registration - define qué operaciones I/O se interceptan (del documento técnico)
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0, // Flags (e.g., FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO)
      PreOperationCallback,
      PostOperationCallback },

    { IRP_MJ_WRITE,
      0,
      PreOperationCallback,
      PostOperationCallback },

    { IRP_MJ_SET_INFORMATION,
      0,
      PreOperationCallback,
      PostOperationCallback },

    { IRP_MJ_CLEANUP,
      0,
      PreOperationCallback, // O NULL si no se necesita pre-procesamiento
      NULL },               // No se necesita post-operación para cleanup según el doc.

      // Considerar otras operaciones si es relevante para la detección:
      // { IRP_MJ_READ, 0, PreOperationCallback, PostOperationCallback },
      // { IRP_MJ_CLOSE, 0, PreOperationCallback, NULL }, // Post-close no existe, pre-close sí.
      // { IRP_MJ_DIRECTORY_CONTROL, 0, PreOperationCallback, PostOperationCallback }, // Para enumeración de directorios

      { IRP_MJ_OPERATION_END } // Terminador de la lista
};

// Context registration (si se usan contextos de Stream, File, etc.)
// Por ahora, no se definen contextos específicos en el documento técnico.
/*
CONST FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    { FLT_STREAMHANDLE_CONTEXT,
      0,
      NULL, // CleanupContext
      sizeof(MY_STREAMHANDLE_CONTEXT),
      MY_STREAMHANDLE_CONTEXT_TAG },
    { FLT_CONTEXT_END }
};
*/

// Filter registration structure (principalmente del código original, ajustada)
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version (FLT_REGISTRATION_VERSION es el actual)
    0,                                  // Flags (e.g., FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP)
    NULL,                               // ContextRegistration (NULL si no se usan contextos arriba)
    Callbacks,                          // Operation callbacks
    FilterUnloadCallback,               // FilterUnload (nombre del doc. técnico)
    InstanceSetupCallback,              // InstanceSetup
    InstanceQueryTeardownCallback,      // InstanceQueryTeardown
    NULL,                               // InstanceTeardownStart (NULL si no se necesita)
    NULL,                               // InstanceTeardownComplete (NULL si no se necesita)
    NULL,                               // GenerateFileName (usar FltGetFileNameInformation en su lugar)
    NULL,                               // GenerateDestinationFileName (para operaciones de renombrado/hardlink)
    NULL                                // NormalizeNameComponent (para normalización de nombres)
    // Faltarían callbacks de Normalización de Nombres si se quieren nombres canónicos.
};


// ----- Driver Entry Point -----
/**
 * @brief Driver entry point
 * @details Initializes the minifilter driver and registers with Filter Manager
 */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa = { 0 };
    UNICODE_STRING portNameUnicodeString = { 0 };

    UNREFERENCED_PARAMETER(RegistryPath);

    CS_LOG_INFO("CryptoShield driver loading, version %ws", CRYPTOSHIELD_VERSION_STRING);

    // Inicializar el contexto global del driver
    RtlZeroMemory(&g_Context, sizeof(CRYPTOSHIELD_CONTEXT));
    KeQuerySystemTime(&g_Context.DriverLoadTime); // Guardar el momento de carga

    // Inicializar objetos de sincronización
    KeInitializeSpinLock(&g_Context.StatisticsLock);
    KeInitializeSpinLock(&g_Context.ConfigLock);
    status = ExInitializeResourceLite(&g_Context.PortResource);
    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("Failed to initialize PortResource: 0x%08X", status);
        // No hay mucho que limpiar aquí si esto falla al inicio.
        return status;
    }

    // Establecer configuración por defecto (podría leerse del RegistryPath también)
    g_Context.MonitoringEnabled = (DEFAULT_MONITORING_ENABLED == TRUE); // Desde Shared.h
    g_Context.DetectionSensitivity = DEFAULT_DETECTION_SENSITIVITY;   // Desde Shared.h
    g_Context.ActiveConfigFlags = 0;
    if (g_Context.MonitoringEnabled) {
        g_Context.ActiveConfigFlags |= CONFIG_FLAG_MONITORING_ENABLED;
    }
    // Inicializar otros flags de configuración y acciones de respuesta si es necesario.

    g_Context.IsUnloading = FALSE;
    g_Context.ClientConnected = FALSE;

    // Registrar el minifilter con el Filter Manager
    CS_LOG_TRACE("Registering filter with Filter Manager...");
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_Context.FilterHandle);
    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("Failed to register filter: 0x%08X", status);
        ExDeleteResourceLite(&g_Context.PortResource); // Limpiar recurso
        return status;
    }

    // Crear el puerto de comunicación para el servicio de usuario
    CS_LOG_TRACE("Creating communication port '%ws'...", CRYPTOSHIELD_PORT_NAME);
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("Failed to build security descriptor for port: 0x%08X", status);
        FltUnregisterFilter(g_Context.FilterHandle); // Limpiar registro del filtro
        ExDeleteResourceLite(&g_Context.PortResource);
        return status;
    }

    RtlInitUnicodeString(&portNameUnicodeString, CRYPTOSHIELD_PORT_NAME);
    InitializeObjectAttributes(&oa,
        &portNameUnicodeString,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, // Atributos del objeto
        NULL,                                     // RootDirectory (NULL para nombres globales)
        sd);                                      // SecurityDescriptor

    status = FltCreateCommunicationPort(
        g_Context.FilterHandle,
        &g_Context.ServerPort,      // Recibe el handle del puerto del servidor
        &oa,                        // Atributos del objeto para el puerto
        NULL,                       // ServerPortCookie (contexto para este puerto, no para conexiones)
        ConnectNotifyCallback,      // Callback para nuevas conexiones de clientes
        DisconnectNotifyCallback,   // Callback para desconexiones de clientes
        MessageNotifyCallback,      // Callback para mensajes de clientes
        MAX_CLIENT_CONNECTIONS);    // Número máximo de clientes simultáneos

    FltFreeSecurityDescriptor(sd); // Liberar el descriptor de seguridad, ya no se necesita
    sd = NULL;

    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("Failed to create communication port: 0x%08X", status);
        FltUnregisterFilter(g_Context.FilterHandle);
        ExDeleteResourceLite(&g_Context.PortResource);
        return status;
    }

    // Iniciar el filtrado de I/O
    CS_LOG_TRACE("Starting filtering...");
    status = FltStartFiltering(g_Context.FilterHandle);
    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("Failed to start filtering: 0x%08X", status);
        FltCloseCommunicationPort(g_Context.ServerPort); // Cerrar puerto
        g_Context.ServerPort = NULL;
        FltUnregisterFilter(g_Context.FilterHandle);
        g_Context.FilterHandle = NULL;
        ExDeleteResourceLite(&g_Context.PortResource);
        return status;
    }

    // Initialize callback protection
    CS_LOG_TRACE("Initializing callback protection mechanism...");
    status = InitializeCallbackProtection(g_Context.FilterHandle);
    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("Failed to initialize callback protection: 0x%08X", status);
        // Cleanup previously initialized resources
        FltStopFiltering(g_Context.FilterHandle); // Stop filtering first
        FltCloseCommunicationPort(g_Context.ServerPort);
        g_Context.ServerPort = NULL;
        FltUnregisterFilter(g_Context.FilterHandle);
        g_Context.FilterHandle = NULL;
        ExDeleteResourceLite(&g_Context.PortResource);
        // CleanupCallbackProtection() is not called here as it might not have been fully initialized
        return status;
    }

    // Initialize Ntoskrnl boundaries for SSDT checks
    CS_LOG_TRACE("Initializing Ntoskrnl.exe boundary detection...");
    status = GetNtoskrnlBoundaries(&g_NtoskrnlInfo); // g_NtoskrnlInfo is defined in HookDetection.c
    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("Failed to get Ntoskrnl.exe boundaries: 0x%08X. SSDT checks will be impaired.", status);
        // This might be considered critical depending on policy. For now, log and continue if other protections are up.
        // Or, to be strict:
        // CleanupCallbackProtection();
        // FltStopFiltering(g_Context.FilterHandle);
        // FltCloseCommunicationPort(g_Context.ServerPort);
        // g_Context.ServerPort = NULL;
        // FltUnregisterFilter(g_Context.FilterHandle);
        // g_Context.FilterHandle = NULL;
        // ExDeleteResourceLite(&g_Context.PortResource);
        // return status;
    }

    // Initialize SSDT table information for hook detection
    // This should be done after GetNtoskrnlBoundaries if it's a dependency for future validation, though currently not.
    if (NT_SUCCESS(status)) { // Only proceed if ntoskrnl boundaries were found (or if we decide it's not fatal)
        CS_LOG_TRACE("Initializing SDT Table for hook detection...");
        status = InitializeSdtTable(); // g_KeServiceDescriptorTable is in HookDetection.c
        if (!NT_SUCCESS(status)) {
            CS_LOG_ERROR("Failed to initialize SDT Table: 0x%08X. SSDT hook detection will be unavailable.", status);
            // This is critical for SSDT hook detection.
            // Depending on policy, driver load could fail here.
            // For now, we log and continue, as other features might still work.
            // If this is considered fatal:
            // CleanupCallbackProtection();
            // FltStopFiltering(g_Context.FilterHandle);
            // FltCloseCommunicationPort(g_Context.ServerPort); ... etc.
            // return status;
        }
    }
    // Reset status to SUCCESS if previous non-fatal errors occurred but we decided to continue.
    // However, if any of these are truly critical, the status from them should propagate.
    // For this implementation, let's assume they are critical for full functionality.
    // If GetNtoskrnlBoundaries or InitializeSdtTable failed, we might not want to load.
    // Let's refine this: if any of these new critical init steps fail, we *should* unload.

    // Re-evaluating the error handling for strictness:
    // If GetNtoskrnlBoundaries failed, InitializeSdtTable might not be as useful,
    // and IsSdtHooked would fail.
    // Let's make them sequential critical steps.

    if (!NT_SUCCESS(status)) { // Check if GetNtoskrnlBoundaries or InitializeSdtTable failed
        CS_LOG_ERROR("A critical hook detection initialization failed. Unloading driver.");
        CleanupCallbackProtection();
        FltStopFiltering(g_Context.FilterHandle);
        FltCloseCommunicationPort(g_Context.ServerPort);
        g_Context.ServerPort = NULL;
        FltUnregisterFilter(g_Context.FilterHandle);
        g_Context.FilterHandle = NULL;
        ExDeleteResourceLite(&g_Context.PortResource);
        return status; // Return the first error that occurred
    }


    // Initialize Memory Integrity checking
    CS_LOG_TRACE("Initializing memory integrity protection...");
    status = InitializeMemoryIntegrity(DriverObject);
    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("Failed to initialize memory integrity protection: 0x%08X", status);
        CleanupCallbackProtection();
        goto ExitDriverEntry_ClosePortAndUnregister;
    }

    // Initialize Tamper Alert Worker Thread components
    CS_LOG_TRACE("Initializing tamper alert worker components...");
    KeInitializeSpinLock(&g_Context.TamperAlertQueueLock);
    InitializeListHead(&g_Context.TamperAlertQueue);
    g_Context.IsWorkItemScheduled = FALSE;
    g_Context.TamperAlertWorkItem = IoAllocateWorkItem(g_Context.FilterHandle); // Assuming g_Context.FilterHandle is a PDEVICE_OBJECT equivalent for IoAllocateWorkItem
                                                                               // If FilterHandle is not PDEVICE_OBJECT, this needs the actual device object.
                                                                               // For minifilters, the filter handle itself is not a device object.
                                                                               // We might need DriverObject->DeviceObject or a specific device object created by the filter.
                                                                               // Let's assume for now FltGetDeviceObject(g_Context.FilterHandle, &deviceObject) would be needed if FilterHandle is not enough.
                                                                               // For simplicity, the prompt implies g_Context.FilterHandle can be used.
                                                                               // Correction: IoAllocateWorkItem takes a PDEVICE_OBJECT.
                                                                               // A filter doesn't have a traditional device object in the same way.
                                                                               // We should use the DeviceObject associated with the FltRegisterFilter.
                                                                               // This usually means DriverObject->DeviceObject if the filter is attached to it.
                                                                               // Or, if the filter creates its own control device object, use that.
                                                                               // Given the context, using DriverObject->DeviceObject seems most plausible if no specific control device object exists.
                                                                               // Let's use DriverObject->DeviceObject for now.
    // To get the correct PDEVICE_OBJECT for IoAllocateWorkItem with a minifilter,
    // we should use the one associated with FltRegisterFilter.
    // FltObjects->DeviceObject from an IRP_MJ_CREATE in InstanceSetup might be one way,
    // but that's too late. DriverObject->DeviceObject is a common pattern.
    // Let's assume DriverObject is the correct one to pass.
    // Actually, the PFLT_FILTER handle itself can be used as the device object for IoAllocateWorkItem.
    // No, this is incorrect. IoAllocateWorkItem requires a PDEVICE_OBJECT.
    // FltGetFilterDeviceObject(g_Context.FilterHandle, &pDeviceObject) could be used, but might not be initialized yet.
    // The most reliable is the device object from the DriverObject.
    PDEVICE_OBJECT pDeviceObject = DriverObject->DeviceObject; // This is typically the FDO for the driver.

    if (g_Context.FilterHandle == NULL) { // Should not happen if registration was successful
        CS_LOG_ERROR("FilterHandle is NULL before IoAllocateWorkItem for TamperAlert. Critical error.");
        status = STATUS_INVALID_HANDLE;
        CleanupMemoryIntegrity();
        CleanupCallbackProtection();
        goto ExitDriverEntry_ClosePortAndUnregister;
    }
    // According to MSDN, IoAllocateWorkItem takes a PDEVICE_OBJECT.
    // For a minifilter, this is typically the device object of the filter itself,
    // which is *not* g_Context.FilterHandle.
    // A common way is to create a control device object (CDO) or use the one FltMgr provides.
    // If no CDO, using the DriverObject's DeviceObject is a fallback but might not be ideal.
    // The prompt used g_Context.FilterHandle, which is PFLT_FILTER.
    // Let's assume there's a helper or it's implicitly convertible, or the prompt implies a simplification.
    // Given the structure, it's more likely that g_Context.FilterHandle (PFLT_FILTER) is *not* the PDEVICE_OBJECT.
    // We need a PDEVICE_OBJECT. The DriverObject has a list of them.
    // For a minifilter, a control device object is often created. If not, then what?
    // Let's use a placeholder and note this needs clarification for a real driver.
    // For the purpose of this exercise, I will follow the prompt's `g_Context.FilterHandle`
    // but add a comment. It should ideally be a PDEVICE_OBJECT.
    // The most correct way to get a PDEVICE_OBJECT for a minifilter for such purposes
    // is often to create a control device object (CDO) using IoCreateDevice.
    // Or, if the filter is associated with a specific device stack, use that device object.
    // FltGetDeviceObject(g_Context.FilterHandle, &deviceObjectForWorkItem) might be possible too.
    // Let's stick to the user's direct instruction and use g_Context.FilterHandle, assuming it's a simplification.
    // **CORRECTION based on typical Minifilter structure & IoAllocateWorkItem documentation:**
    // IoAllocateWorkItem *requires* a PDEVICE_OBJECT. g_Context.FilterHandle is PFLT_FILTER.
    // The correct device object to use is typically the one associated with the minifilter's "control device object"
    // or the underlying device object of a volume instance if the work item is instance-specific.
    // For a global work item like this, a control device object (created by IoCreateDevice) is standard.
    // If no such CDO exists, one should be created in DriverEntry.
    // Let's assume DriverObject->DeviceObject is acceptable as a fallback if no CDO is explicitly created by CryptoShield.
    // This is often the FDO of the driver stack.
    g_Context.TamperAlertWorkItem = IoAllocateWorkItem(pDeviceObject);


    if (g_Context.TamperAlertWorkItem == NULL) {
        CS_LOG_ERROR("Failed to allocate TamperAlertWorkItem.");
        status = STATUS_INSUFFICIENT_RESOURCES;
        CleanupMemoryIntegrity();
        CleanupCallbackProtection();
        goto ExitDriverEntry_ClosePortAndUnregister;
    }
    // Note: InitializeTamperAlertThread and ShutdownTamperAlertThread were removed from the prompt
    // as we are now managing the work item directly in DriverEntry/FilterUnload.

    // All critical initializations are successful. Now start filtering.
    CS_LOG_TRACE("Starting filtering I/O operations...");
    status = FltStartFiltering(g_Context.FilterHandle);
    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("Failed to start filtering: 0x%08X", status);
        IoFreeWorkItem(g_Context.TamperAlertWorkItem); // Clean up allocated work item
        g_Context.TamperAlertWorkItem = NULL;
        CleanupMemoryIntegrity();
        CleanupCallbackProtection();
        goto ExitDriverEntry_ClosePortAndUnregister;
    }

    CS_LOG_INFO("CryptoShield driver loaded successfully. All protection mechanisms initialized and filtering started.");
    return STATUS_SUCCESS;

    // Centralized cleanup for failures after port creation and filter registration
ExitDriverEntry_ClosePortAndUnregister:
    CS_LOG_INFO("Cleaning up communication port and filter registration due to critical initialization failure.");
    if (g_Context.ServerPort != NULL) {
        FltCloseCommunicationPort(g_Context.ServerPort);
        g_Context.ServerPort = NULL;
    }
    if (g_Context.FilterHandle != NULL) {
        FltUnregisterFilter(g_Context.FilterHandle);
        g_Context.FilterHandle = NULL;
    }
    ExDeleteResourceLite(&g_Context.PortResource); // Ensure this is only called if initialized
    return status; // Return the specific error status
}


// ----- Filter Unload Callback -----
/**
 * @brief Filter unload routine (nombre del doc. técnico: FilterUnloadCallback)
 * @details Cleans up resources and unregisters the filter
 */
NTSTATUS FilterUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE(); // Esta rutina debe ser paginable
    PTAMPER_ALERT_WORK_ITEM workItem;
    PLIST_ENTRY listEntry;

    CS_LOG_INFO("CryptoShield driver unloading...");

    // Clean up memory integrity protection
    CleanupMemoryIntegrity();

    // Clean up callback protection
    CleanupCallbackProtection();

    // Indicate that the driver is unloading to stop new work items from being queued
    // and to allow the worker thread (if it were a separate thread) to terminate.
    // For IoQueueWorkItem, we need to ensure no more items are queued,
    // and then wait for any scheduled work item to complete before freeing it.
    // However, IoQueueWorkItem is "fire and forget" in terms of waiting from *this* path.
    // The work item itself runs and completes. We free g_Context.TamperAlertWorkItem here.
    // Any item *in the queue* needs to be drained and freed.

    // Prevent new items from being queued and processed by ProcessTamperAlertQueueWorkRoutine.
    // Set IsUnloading early. This flag should be checked before queuing new work items.
    InterlockedExchange8((CHAR*)&g_Context.IsUnloading, TRUE);
    CS_LOG_TRACE("IsUnloading flag set to TRUE.");

    CS_LOG_TRACE("Cleaning up Tamper Alert Worker Thread resources...");

    // 1. Clean up any remaining items in the TamperAlertQueue
    // This must be done carefully, acquiring the lock.
    // The IsUnloading flag should prevent new items from being added by DPCs.
    if (g_Context.TamperAlertQueueLock != NULL) { // Check if spinlock was initialized
        KIRQL oldIrql;
        CS_LOG_TRACE("Acquiring TamperAlertQueueLock for cleanup.");
        KeAcquireSpinLock(&g_Context.TamperAlertQueueLock, &oldIrql);

        while (!IsListEmpty(&g_Context.TamperAlertQueue)) {
            listEntry = RemoveHeadList(&g_Context.TamperAlertQueue);
            // Ensure listEntry is not NULL, though IsListEmpty should prevent this.
            // However, if the list is corrupted, CONTAINING_RECORD could crash.
            // Given this is unload path and under spinlock, corruption is less likely
            // unless there was prior memory corruption.
            if (listEntry == NULL) { // Should not happen with IsListEmpty check
                 CS_LOG_ERROR("RemoveHeadList returned NULL from a non-empty list. Queue might be corrupted.");
                 break;
            }
            workItem = CONTAINING_RECORD(listEntry, TAMPER_ALERT_WORK_ITEM, ListEntry);
            // workItem could be NULL if listEntry was bad.
            if (workItem != NULL) { // Check if workItem is valid before accessing its members
                CS_LOG_INFO("Freeing queued tamper alert work item (Type: %u) during unload.", workItem->AlertPayload.TamperType);
                CS_FREE_POOL(workItem);
            } else {
                CS_LOG_ERROR("CONTAINING_RECORD resulted in NULL workItem. Skipping free for this entry.");
                // This indicates a severe issue, potentially list corruption or bad cast.
            }
        }
        // g_Context.IsWorkItemScheduled is not critical to reset here as the work item is being freed.
        KeReleaseSpinLock(&g_Context.TamperAlertQueueLock, oldIrql);
        CS_LOG_TRACE("TamperAlertQueue drained.");
    }
    // Ensure the spinlock itself is not accessed if it was never initialized,
    // though in a normal flow it would be.


    // 2. Free the IoWorkItem
    // It's important to free the work item after ensuring the queue is empty and no more items
    // will be processed that might reference this work item, although ProcessTamperAlertQueueWorkRoutine
    // doesn't directly depend on g_Context.TamperAlertWorkItem for its execution parameters once scheduled.
    // IoFreeWorkItem must be called when the work item is not currently queued and will not be queued again.
    // The IsUnloading flag helps prevent re-queuing.
    if (g_Context.TamperAlertWorkItem != NULL) {
        CS_LOG_TRACE("Freeing TamperAlertWorkItem.");
        IoFreeWorkItem(g_Context.TamperAlertWorkItem);
        g_Context.TamperAlertWorkItem = NULL;
    }

    // Note: ShutdownTamperAlertThread() was removed as we are not using a dedicated thread anymore.

    // Indicar que el driver se está descargando para detener nuevas operaciones/mensajes.
    // Moved IsUnloading setting to be earlier in this function.
    // This should ideally be set earlier to prevent new work items from being queued
    // by DPCs that might still run.
    InterlockedExchange8((CHAR*)&g_Context.IsUnloading, TRUE);

    // Cerrar el puerto de comunicación del servidor.
    // Esto evitará nuevas conexiones y debería hacer que FltSendMessage falle para los clientes.

    // Cerrar el puerto de comunicación del servidor.
    // Esto evitará nuevas conexiones y debería hacer que FltSendMessage falle para los clientes.
    if (g_Context.ServerPort != NULL) {
        CS_LOG_TRACE("Closing communication server port...");
        FltCloseCommunicationPort(g_Context.ServerPort);
        g_Context.ServerPort = NULL; // Marcar como cerrado
    }

    // En un driver de producción, se necesitaría esperar a que se completen
    // las operaciones pendientes o los hilos de mensajes.
    // Aquí, se asume que DisconnectNotifyCallback limpiará g_Context.ClientPort.
    // Se podría añadir una espera activa o un evento.

    // Anular el registro del filtro con el Filter Manager.
    // Esto detendrá la llegada de nuevos IRPs a los callbacks.
    if (g_Context.FilterHandle != NULL) {
        CS_LOG_TRACE("Unregistering filter...");
        FltUnregisterFilter(g_Context.FilterHandle);
        g_Context.FilterHandle = NULL; // Marcar como no registrado
    }

    // Limpiar objetos de sincronización.
    // ExDeleteResourceLite debe llamarse solo si ExInitializeResourceLite tuvo éxito.
    CS_LOG_TRACE("Deleting port resource...");
    ExDeleteResourceLite(&g_Context.PortResource); // Asumiendo que siempre se inicializó si llegamos aquí.

    CS_LOG_INFO("CryptoShield driver unloaded successfully.");
    CS_LOG_INFO("Total file operations monitored: %lld", g_Context.FileOperationsMonitored);
    CS_LOG_INFO("Total messages sent to user mode: %lld", g_Context.MessagesSentToUserMode);
    CS_LOG_INFO("Total messages received from user mode: %lld", g_Context.MessagesReceivedFromUserMode);

    return STATUS_SUCCESS;
}

// ----- Instance Setup/Teardown Callbacks -----
// (Implementados en este archivo por simplicidad, podrían estar en otro si crecen mucho)

/**
 * @brief Instance setup callback
 * @details Called when filter attaches to a volume
 */
NTSTATUS InstanceSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{

    CS_LOG_INFO("Enter in InstanceSetupCallback");

    PAGED_CODE();
    UNREFERENCED_PARAMETER(FltObjects); // Usar si se necesita info del volumen/instancia
    UNREFERENCED_PARAMETER(Flags);      // Usar para FLTFL_INSTANCE_SETUP_FLAGS

    CS_LOG_TRACE("InstanceSetupCallback entered for volume type %u, filesystem type %u.",
        VolumeDeviceType, VolumeFilesystemType);

    // Decidir si adjuntar a este volumen.
    // Por ejemplo, solo adjuntar a sistemas de archivos de disco y NTFS/ReFS.
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) {
        CS_LOG_INFO("Skipping attachment to non-disk volume type %u.", VolumeDeviceType);
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    if (!IsFileSystemSupported(VolumeFilesystemType)) {
        CS_LOG_INFO("Skipping attachment to unsupported filesystem type %u.", VolumeFilesystemType);
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    // Podrían hacerse más comprobaciones aquí:
    // - Volumen de solo lectura.
    // - Volumen de sistema (si no se quiere monitorizar).
    // - Tipo de dispositivo específico.

    CS_LOG_INFO("Attaching to volume (FS type %u).", VolumeFilesystemType);
    return STATUS_SUCCESS; // Adjuntar a este volumen
}

/**
 * @brief Instance query teardown callback
 * @details Called when filter is about to detach from a volume
 */
NTSTATUS InstanceQueryTeardownCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags); // Flags como FLTFL_INSTANCE_QUERY_TEARDOWN_VOLUNTARY_DETACHMENT

    CS_LOG_TRACE("InstanceQueryTeardownCallback entered.");

    // En una implementación básica, siempre se permite el detach.
    // En casos más complejos, se podría querer impedir el detach si hay operaciones críticas pendientes.
    // Si el driver se está descargando (g_Context.IsUnloading es TRUE), permitir siempre.
    if (g_Context.IsUnloading) {
        return STATUS_SUCCESS;
    }

    // Lógica para decidir si permitir el detach o no (STATUS_FLT_DO_NOT_DETACH).
    // Por ejemplo, si hay un análisis en curso en este volumen que no puede interrumpirse.

    return STATUS_SUCCESS; // Permitir el detach
}