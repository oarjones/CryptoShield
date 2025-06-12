/**
 * @file CryptoShield.c
 * @brief Main implementation file for CryptoShield minifilter driver
 * @details Contains driver entry point, filter registration and core callbacks
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "CryptoShield.h" // Incluye Shared.h indirectamente

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

    CS_LOG_INFO("CryptoShield driver loaded successfully.");
    return STATUS_SUCCESS;
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

    CS_LOG_INFO("CryptoShield driver unloading...");

    // Indicar que el driver se está descargando para detener nuevas operaciones/mensajes.
    InterlockedExchange8((CHAR*)&g_Context.IsUnloading, TRUE);

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