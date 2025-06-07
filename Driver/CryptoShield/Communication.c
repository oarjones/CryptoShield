/**
 * @file Communication.c
 * @brief Kernel-User communication implementation
 * @details Handles communication port callbacks and message processing for CryptoShield.
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "CryptoShield.h" // Incluye Shared.h

 // ----- Forward Declarations (para funciones internas de este archivo si se usan antes de definirlas) -----
static NTSTATUS HandleStatusRequestMessage(
    _Out_writes_bytes_to_(OutputBufferLength, *ActualOutputLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ActualOutputLength
);

static NTSTATUS HandleConfigUpdateMessage(
    _In_ PCS_CONFIG_UPDATE_PAYLOAD ConfigUpdatePayload, // De Shared.h
    _In_ ULONG PayloadLength
);

static NTSTATUS HandleShutdownRequestMessage(VOID);


// ----- Communication Port Callbacks (nombres seg�n documento t�cnico) -----

/**
 * @brief Client connection notification callback (ConnectNotifyCallback)
 * @details Called when a user-mode client connects to the communication port.
 */
NTSTATUS ConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie, // No usado en esta implementaci�n
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, // Contexto del cliente
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie // Cookie para esta conexi�n
)
{
    PAGED_CODE(); // Esta callback se llama en PASSIVE_LEVEL.

    UNREFERENCED_PARAMETER(ServerPortCookie);
    
    
    if (ConnectionContext == NULL || SizeOfContext != sizeof(ULONG)) {
        // Rechazar conexi�n si no env�a un PID v�lido.
        return STATUS_INVALID_PARAMETER;
    }
    g_Context.UserModeProcessId = *(PULONG)ConnectionContext;
    CS_LOG_INFO("User service connected with PID: %lu", g_Context.UserModeProcessId);
    
    
    
    UNREFERENCED_PARAMETER(ConnectionContext); // Podr�a usarse para validar versi�n del cliente, etc.
    UNREFERENCED_PARAMETER(SizeOfContext);

    CS_LOG_INFO("User service connection request received.");

    // Solo se permite un cliente a la vez (seg�n MAX_CLIENT_CONNECTIONS = 1 en DriverEntry)
    // Usar el recurso para proteger el acceso a g_Context.ClientPort y g_Context.ClientConnected
    ExEnterCriticalRegionAndAcquireResourceExclusive(&g_Context.PortResource);

    if (g_Context.ClientConnected) {
        ExReleaseResourceAndLeaveCriticalRegion(&g_Context.PortResource);
        CS_LOG_WARNING("A client is already connected. Rejecting new connection.");
        return STATUS_TOO_MANY_SESSIONS; // O STATUS_ALREADY_REGISTERED
    }

    // Guardar el puerto del cliente y marcar como conectado.
    g_Context.ClientPort = ClientPort;
    g_Context.ClientConnected = TRUE;

    // El ConnectionCookie puede ser un puntero a una estructura de contexto de conexi�n si se necesita.
    // Por ahora, podemos usar un valor simple o incluso el mismo ClientPort si no se necesita m�s.
    // Aqu�, no asignaremos un cookie complejo, el driver solo soporta un cliente.
    // Se podr�a usar ClientPort como cookie si FltMgr lo permite o un puntero a g_Context.
    *ConnectionCookie = (PVOID)ClientPort; // Ejemplo: usar el handle del puerto como cookie.

    ExReleaseResourceAndLeaveCriticalRegion(&g_Context.PortResource);

    CS_LOG_INFO("User service connected successfully. ClientPort: 0x%p", ClientPort);
    return STATUS_SUCCESS;
}

/**
 * @brief Client disconnection notification callback (DisconnectNotifyCallback)
 * @details Called when a user-mode client disconnects from the communication port.
 */
VOID DisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie // El cookie devuelto por ConnectNotifyCallback
)
{
    PAGED_CODE(); // Esta callback se llama en PASSIVE_LEVEL.

    CS_LOG_INFO("User service disconnecting. ConnectionCookie: 0x%p", ConnectionCookie);

    ExEnterCriticalRegionAndAcquireResourceExclusive(&g_Context.PortResource);

    // Verificar si el cookie de conexi�n coincide con el cliente actual (si se usara un cookie m�s complejo).
    // En este caso, como solo hay un cliente, si g_Context.ClientConnected es TRUE, es este.
    if (g_Context.ClientConnected && (PFLT_PORT)ConnectionCookie == g_Context.ClientPort) {
        g_Context.ClientConnected = FALSE;
        g_Context.ClientPort = NULL; // Liberar la referencia al puerto del cliente.
        // FltCloseClientPort no se llama aqu�; el Filter Manager lo maneja.
        CS_LOG_INFO("User service disconnected successfully.");
    }
    else {
        CS_LOG_WARNING("DisconnectNotifyCallback received for an unknown or already disconnected client. Cookie: 0x%p, CurrentClientPort: 0x%p",
            ConnectionCookie, g_Context.ClientPort);
    }

    ExReleaseResourceAndLeaveCriticalRegion(&g_Context.PortResource);
}

/**
 * @brief Message notification callback (MessageNotifyCallback)
 * @details Processes messages received from the user-mode client.
 */
NTSTATUS MessageNotifyCallback(
    _In_opt_ PVOID PortCookie, // El ConnectionCookie de la conexi�n
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PCS_MESSAGE_PAYLOAD_HEADER payloadHeader = NULL; // De Shared.h

    UNREFERENCED_PARAMETER(PortCookie); // Podr�a usarse para identificar al cliente si hay m�ltiples.

    PAGED_CODE(); // Esta callback se llama en el contexto del hilo del cliente, en PASSIVE_LEVEL.

    *ReturnOutputBufferLength = 0; // Inicializar

    if (g_Context.IsUnloading) {
        CS_LOG_WARNING("Message received while driver is unloading. Ignoring.");
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }

    // Validar el buffer de entrada. Debe contener al menos la cabecera del payload.
    if (InputBuffer == NULL || InputBufferLength < sizeof(CS_MESSAGE_PAYLOAD_HEADER)) {
        CS_LOG_ERROR("Invalid input buffer (NULL or too small for header). Length: %u", InputBufferLength);
        return STATUS_INVALID_PARAMETER;
    }

    payloadHeader = (PCS_MESSAGE_PAYLOAD_HEADER)InputBuffer;

    // Validar que el tama�o del buffer de entrada coincida con el tama�o indicado en el payload.
    if (InputBufferLength < payloadHeader->PayloadSize) {
        CS_LOG_ERROR("InputBufferLength (%u) is less than PayloadSize in header (%u).",
            InputBufferLength, payloadHeader->PayloadSize);
        return STATUS_BUFFER_TOO_SMALL; // O STATUS_INFO_LENGTH_MISMATCH
    }
    // Tambi�n es buena idea limitar el PayloadSize m�ximo para evitar DoS.
    // if (payloadHeader->PayloadSize > MAX_EXPECTED_PAYLOAD_SIZE) return STATUS_INVALID_PARAMETER;


    CS_LOG_TRACE("Received message from user service. Type: %u, ID: %u, Size: %u",
        payloadHeader->MessageType, payloadHeader->MessageId, payloadHeader->PayloadSize);
    InterlockedIncrement64(&g_Context.MessagesReceivedFromUserMode);

    // Procesar el mensaje seg�n su tipo (definido en Shared.h)
    switch (payloadHeader->MessageType) {
    case MSG_TYPE_STATUS_REQUEST:
        // El payload de entrada para StatusRequest es solo la cabecera.
        // La respuesta se escribe en OutputBuffer.
        status = HandleStatusRequestMessage(OutputBuffer, OutputBufferLength, ReturnOutputBufferLength);
        break;

    case MSG_TYPE_CONFIG_UPDATE:
        // Verificar que el payload sea del tama�o esperado para CS_CONFIG_UPDATE_PAYLOAD.
        if (payloadHeader->PayloadSize < sizeof(CS_CONFIG_UPDATE_PAYLOAD)) {
            CS_LOG_ERROR("PayloadSize (%u) for MSG_TYPE_CONFIG_UPDATE is too small (expected %u).",
                payloadHeader->PayloadSize, (ULONG)sizeof(CS_CONFIG_UPDATE_PAYLOAD));
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
        else {
            status = HandleConfigUpdateMessage(
                (PCS_CONFIG_UPDATE_PAYLOAD)InputBuffer, // Castear al tipo espec�fico
                payloadHeader->PayloadSize
            );
            // Opcionalmente, enviar una respuesta de confirmaci�n en OutputBuffer.
            // Por ahora, se asume que la respuesta es solo el NTSTATUS.
            // Si se env�a payload de respuesta, actualizar *ReturnOutputBufferLength.
        }
        break;

    case MSG_TYPE_SHUTDOWN_REQUEST:
        // El driver no puede auto-descargarse, pero puede prepararse.
        status = HandleShutdownRequestMessage();
        // No se espera payload de respuesta.
        break;

        // Otros tipos de mensajes del cliente al kernel podr�an manejarse aqu�.
        // Por ejemplo, si el cliente env�a una respuesta a una alerta que el kernel envi�.

    default:
        CS_LOG_WARNING("Unknown message type received from user service: %u", payloadHeader->MessageType);
        status = STATUS_INVALID_MESSAGE; // O STATUS_NOT_SUPPORTED
        break;
    }

    return status;
}


// ----- Funciones de Manejo de Mensajes Espec�ficos -----

static NTSTATUS HandleStatusRequestMessage(
    _Out_writes_bytes_to_(OutputBufferLength, *ActualOutputLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ActualOutputLength
)
{
    PCS_STATUS_REPLY_PAYLOAD statusReply;
    KIRQL oldIrqlCfg, oldIrqlStats;

    PAGED_CODE();

    // 1. Comprobar que el buffer del servicio es suficientemente grande.
    if (OutputBuffer == NULL || OutputBufferLength < sizeof(CS_STATUS_REPLY_PAYLOAD)) {
        *ActualOutputLength = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    // 2. Preparar el buffer de respuesta.
    statusReply = (PCS_STATUS_REPLY_PAYLOAD)OutputBuffer;
    RtlZeroMemory(statusReply, sizeof(CS_STATUS_REPLY_PAYLOAD));

    // 3. Rellenar la cabecera. ESTA ES LA PARTE CLAVE.
    // Nos aseguramos de que el tama�o sea el correcto de la estructura completa.
    statusReply->Header.MessageType = MSG_TYPE_STATUS_REQUEST;
    statusReply->Header.MessageId = 0;
    statusReply->Header.PayloadSize = sizeof(CS_STATUS_REPLY_PAYLOAD);

    // 4. Rellenar el resto de los datos del estado del driver.
    statusReply->DriverVersionMajor = CRYPTOSHIELD_VERSION_MAJOR;
    statusReply->DriverVersionMinor = CRYPTOSHIELD_VERSION_MINOR;
    statusReply->DriverVersionBuild = CRYPTOSHIELD_VERSION_BUILD;
    statusReply->DriverLoadTime = g_Context.DriverLoadTime;

    KeAcquireSpinLock(&g_Context.ConfigLock, &oldIrqlCfg);
    statusReply->CurrentConfigFlags = g_Context.ActiveConfigFlags;
    statusReply->CurrentDetectionSensitivity = g_Context.DetectionSensitivity;
    KeReleaseSpinLock(&g_Context.ConfigLock, oldIrqlCfg);

    KeAcquireSpinLock(&g_Context.StatisticsLock, &oldIrqlStats);
    statusReply->TotalOperationsMonitored = g_Context.FileOperationsMonitored;
    statusReply->OperationsBlocked = g_Context.OperationsBlockedByDriver;
    statusReply->ThreatsDetected = g_Context.ThreatsDetectedByDriver;
    statusReply->KernelMessagesSent = g_Context.MessagesSentToUserMode;
    statusReply->KernelMessagesReceived = g_Context.MessagesReceivedFromUserMode;
    KeReleaseSpinLock(&g_Context.StatisticsLock, oldIrqlStats);

    // 5. Indicar al sistema el tama�o exacto de la respuesta que hemos escrito.
    *ActualOutputLength = sizeof(CS_STATUS_REPLY_PAYLOAD);

    return STATUS_SUCCESS;
}



static NTSTATUS HandleConfigUpdateMessage(
    _In_ PCS_CONFIG_UPDATE_PAYLOAD ConfigUpdatePayload, // De Shared.h
    _In_ ULONG PayloadLength // Tama�o del payload recibido
)
{
    KIRQL oldIrql;
    BOOLEAN newMonitoringEnabled;

    UNREFERENCED_PARAMETER(PayloadLength); // Ya validado parcialmente por el llamador.
    PAGED_CODE();

    // Validar los nuevos valores de configuraci�n
    if (ConfigUpdatePayload->NewDetectionSensitivity > MAX_DETECTION_SENSITIVITY) {
        CS_LOG_WARNING("Invalid new detection sensitivity received: %u", ConfigUpdatePayload->NewDetectionSensitivity);
        return STATUS_INVALID_PARAMETER_2; // O un error m�s espec�fico
    }
    // Se podr�an validar otros flags y acciones aqu�.

    newMonitoringEnabled = (ConfigUpdatePayload->NewConfigFlags & CONFIG_FLAG_MONITORING_ENABLED) ? TRUE : FALSE;

    // Actualizar la configuraci�n global del driver (protegida por spinlock)
    KeAcquireSpinLock(&g_Context.ConfigLock, &oldIrql);
    g_Context.MonitoringEnabled = newMonitoringEnabled;
    g_Context.DetectionSensitivity = ConfigUpdatePayload->NewDetectionSensitivity;
    g_Context.ActiveConfigFlags = ConfigUpdatePayload->NewConfigFlags;
    g_Context.ActiveResponseActions = ConfigUpdatePayload->NewResponseActions;
    KeReleaseSpinLock(&g_Context.ConfigLock, oldIrql);

    CS_LOG_INFO("Configuration updated by user service. Monitoring: %s, Sensitivity: %u, Flags: 0x%X, Actions: 0x%X",
        g_Context.MonitoringEnabled ? "Enabled" : "Disabled",
        g_Context.DetectionSensitivity,
        g_Context.ActiveConfigFlags,
        g_Context.ActiveResponseActions);

    return STATUS_SUCCESS;
}

static NTSTATUS HandleShutdownRequestMessage(VOID)
{
    PAGED_CODE();
    CS_LOG_INFO("Shutdown request received from user service.");

    // Preparar para la descarga: deshabilitar el monitoreo.
    // El FilterUnloadCallback se encargar� de la limpieza final.
    KeAcquireSpinLockAtDpcLevel(&g_Context.ConfigLock); // Usar ConfigLock para proteger MonitoringEnabled
    g_Context.MonitoringEnabled = FALSE;
    // Tambi�n se podr�a establecer g_Context.ActiveConfigFlags &= ~CONFIG_FLAG_MONITORING_ENABLED;
    KeReleaseSpinLockFromDpcLevel(&g_Context.ConfigLock);

    CS_LOG_INFO("Monitoring disabled due to shutdown request.");

    // No se puede iniciar la descarga del driver desde aqu�.
    // El servicio de usuario tendr�a que coordinar la detenci�n del servicio y la descarga del driver.
    return STATUS_SUCCESS;
}


// ----- Funci�n para Enviar Mensajes al Servicio de Usuario -----
/**
 * @brief Sends a message (payload) to the connected user-mode service.
 * Esta funci�n se encarga de la FILTER_MESSAGE_HEADER si se espera una respuesta.
 */
NTSTATUS SendMessageToUserService(
    _In_ PCS_MESSAGE_PAYLOAD_HEADER PayloadHeader, // Puntero al payload (debe ser un tipo de Shared.h)
    _In_ ULONG PayloadSize,                        // Tama�o del payload
    _Out_opt_ PVOID ReplyBuffer,                   // Buffer para la respuesta del servicio (debe ser KERNEL_EXPECTED_USER_REPLY o similar)
    _Inout_opt_ PULONG ReplyLength                 // Tama�o del buffer de respuesta / tama�o devuelto
)
{
    NTSTATUS status;
    PVOID messageToSendBuffer = NULL;
    ULONG messageToSendSize = 0;
    LARGE_INTEGER timeout;

    // CS_ASSERT_IRQL_PASSIVE(); // FltSendMessage debe llamarse en PASSIVE_LEVEL

    if (g_Context.IsUnloading || !g_Context.ClientConnected || g_Context.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED; // O STATUS_SHUTDOWN_IN_PROGRESS
    }
    if (PayloadHeader == NULL || PayloadSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Si se espera una respuesta, el buffer que se env�a a FltSendMessage DEBE
    // comenzar con una FILTER_MESSAGE_HEADER. El payload sigue despu�s.
    if (ReplyBuffer != NULL && ReplyLength != NULL && *ReplyLength > 0) {
        messageToSendSize = sizeof(FILTER_MESSAGE_HEADER) + PayloadSize;
        messageToSendBuffer = CS_ALLOCATE_POOL(POOL_FLAG_NON_PAGED, messageToSendSize); // O PagedPool si el contenido lo permite
        if (messageToSendBuffer == NULL) {
            CS_LOG_ERROR("Failed to allocate buffer for message with filter header.");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        // La FILTER_MESSAGE_HEADER (ReplyLength, MessageId) es inicializada por FltSendMessage.
        // Solo necesitamos copiar el payload despu�s de ella.
        RtlCopyMemory((PUCHAR)messageToSendBuffer + sizeof(FILTER_MESSAGE_HEADER), PayloadHeader, PayloadSize);
    }
    else {
        // Si no se espera respuesta, se puede enviar el payload directamente.
        // (Aunque FltSendMessage a�n podr�a requerir la cabecera si ciertos par�metros no son NULL).
        // Para ser consistentes y m�s seguros, siempre podr�amos incluir FILTER_MESSAGE_HEADER.
        // O, si es una notificaci�n pura sin respuesta, se podr�a intentar enviar solo el payload.
        // Por ahora, asumiremos que si no hay ReplyBuffer, enviamos solo el payload.
        // �CUIDADO! La documentaci�n de FltSendMessage es espec�fica:
        // "If ReplyBuffer is NULL, SenderBuffer does not need to begin with a FILTER_MESSAGE_HEADER structure."
        // "If ReplyBuffer is not NULL, SenderBuffer must begin with a FILTER_MESSAGE_HEADER structure."
        messageToSendBuffer = (PVOID)PayloadHeader; // Enviar el payload directamente
        messageToSendSize = PayloadSize;
    }

    // Establecer un timeout para el env�o del mensaje (ej. 500 ms)
    timeout.QuadPart = -(500LL * 10000LL); // 500 ms en unidades de 100ns, negativo para tiempo relativo

    status = FltSendMessage(
        g_Context.FilterHandle,
        &g_Context.ClientPort,      // Puntero al handle del puerto del cliente
        messageToSendBuffer,        // Buffer a enviar (con o sin FILTER_MESSAGE_HEADER)
        messageToSendSize,          // Tama�o del buffer a enviar
        ReplyBuffer,                // Buffer para recibir la respuesta (si hay)
        ReplyLength,                // Puntero al tama�o del buffer de respuesta / tama�o real
        &timeout                    // Timeout para la operaci�n
    );

    // Si se asign� un buffer intermedio para incluir FILTER_MESSAGE_HEADER, liberarlo.
    if (ReplyBuffer != NULL && messageToSendBuffer != PayloadHeader) {
        CS_FREE_POOL(messageToSendBuffer);
    }

    if (NT_SUCCESS(status)) {
        // InterlockedIncrement64(&g_Context.MessagesSentToUserMode); // Se incrementa en el llamador (SendFileOperationNotification)
        CS_LOG_TRACE("Message (type %u) sent to user service. Status: 0x%08X", PayloadHeader->MessageType, status);
        if (ReplyBuffer != NULL && NT_SUCCESS(status)) {
            CS_LOG_TRACE("Reply received from user service. Length: %u", (ReplyLength ? *ReplyLength : 0));
        }
    }
    else {
        if (status == STATUS_TIMEOUT) {
            CS_LOG_WARNING("Timeout sending message (type %u) to user service.", PayloadHeader->MessageType);
        }
        else if (status == STATUS_PORT_DISCONNECTED) {
            CS_LOG_WARNING("User service port disconnected while sending message (type %u).", PayloadHeader->MessageType);
            // Marcar como desconectado si FltSendMessage lo indica.
            // DisconnectNotifyCallback deber�a manejar la limpieza final de g_Context.ClientPort.
            ExEnterCriticalRegionAndAcquireResourceExclusive(&g_Context.PortResource);
            if (g_Context.ClientConnected) { // Solo si no se ha desconectado ya
                g_Context.ClientConnected = FALSE;
                // g_Context.ClientPort = NULL; // No hacer NULL aqu� directamente, DisconnectNotifyCallback lo har�.
                                                // FltCloseClientPort lo hace el Filter Manager.
            }
            ExReleaseResourceAndLeaveCriticalRegion(&g_Context.PortResource);
        }
        else {
            CS_LOG_WARNING("Failed to send message (type %u) to user service. Status: 0x%08X",
                PayloadHeader->MessageType, status);
        }
    }
    return status;
}