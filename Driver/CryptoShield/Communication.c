/**
 * @file Communication.c
 * @brief Kernel-User communication implementation
 * @details Handles communication port callbacks and message processing
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "CryptoShield.h"

 /**
  * @brief Client connection notification callback
  * @details Called when a user-mode client connects to the communication port
  *
  * @param ClientPort Client port handle
  * @param ServerPortCookie Server port context
  * @param ConnectionContext Connection context from client
  * @param SizeOfContext Size of connection context
  * @param ConnectionCookie Output connection identifier
  * @return STATUS_SUCCESS to accept connection, error code to reject
  */
NTSTATUS CryptoShieldConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie
)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    CS_INFO("Client connection request received");

    // Acquire exclusive access to port
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_Context.PortResource, TRUE);

    __try {
        // Check if we already have a client connected
        if (g_Context.ClientConnected) {
            CS_WARNING("Client already connected, rejecting new connection");
            status = STATUS_ALREADY_REGISTERED;
            __leave;
        }

        // Validate client port
        if (ClientPort == NULL) {
            CS_ERROR("Invalid client port");
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        // Store client port handle
        g_Context.ClientPort = ClientPort;

        // Set connection cookie (we use a simple pointer to our context)
        *ConnectionCookie = (PVOID)&g_Context;

        // Mark client as connected
        InterlockedExchange8((CHAR*)&g_Context.ClientConnected, TRUE);

        CS_INFO("Client connected successfully");

    }
    __finally {
        ExReleaseResourceLite(&g_Context.PortResource);
        KeLeaveCriticalRegion();
    }

    return status;
}

/**
 * @brief Client disconnection notification callback
 * @details Called when a user-mode client disconnects from the communication port
 *
 * @param ConnectionCookie Connection identifier from connect callback
 */
VOID CryptoShieldDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    CS_INFO("Client disconnecting");

    // Acquire exclusive access to port
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&g_Context.PortResource, TRUE);

    // Mark client as disconnected
    InterlockedExchange8((CHAR*)&g_Context.ClientConnected, FALSE);

    // Clear client port
    g_Context.ClientPort = NULL;

    ExReleaseResourceLite(&g_Context.PortResource);
    KeLeaveCriticalRegion();

    CS_INFO("Client disconnected");
}

/**
 * @brief Message notification callback
 * @details Processes messages received from user-mode client
 *
 * @param PortCookie Port context
 * @param InputBuffer Input message buffer
 * @param InputBufferLength Input buffer size
 * @param OutputBuffer Output buffer for reply
 * @param OutputBufferLength Output buffer size
 * @param ReturnOutputBufferLength Actual output size
 * @return STATUS_SUCCESS on success, appropriate error code on failure
 */
NTSTATUS CryptoShieldMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PCRYPTOSHIELD_MESSAGE message = NULL;
    ULONG messageType = 0;

    UNREFERENCED_PARAMETER(PortCookie);

    // Initialize output
    *ReturnOutputBufferLength = 0;

    // Validate input parameters
    if (InputBuffer == NULL || InputBufferLength < sizeof(ULONG)) {
        CS_ERROR("Invalid input buffer");
        return STATUS_INVALID_PARAMETER;
    }

    // Cast input buffer to message structure
    message = (PCRYPTOSHIELD_MESSAGE)InputBuffer;

    // Validate message size
    if (InputBufferLength < FIELD_OFFSET(CRYPTOSHIELD_MESSAGE, FilePath)) {
        CS_ERROR("Input buffer too small");
        return STATUS_BUFFER_TOO_SMALL;
    }

    messageType = message->MessageType;
    CS_TRACE("Received message type: %d", messageType);

    // Update statistics
    InterlockedIncrement(&g_Context.MessagesReceived);

    // Process message based on type
    switch (messageType) {
    case MSG_STATUS_REQUEST:
        status = HandleStatusRequest(OutputBuffer,
            OutputBufferLength,
            ReturnOutputBufferLength);
        break;

    case MSG_CONFIG_UPDATE:
        status = HandleConfigUpdate(message,
            InputBufferLength);
        break;

    case MSG_SHUTDOWN_REQUEST:
        status = HandleShutdownRequest();
        break;

    default:
        CS_WARNING("Unknown message type: %d", messageType);
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}

/**
 * @brief Handles status request from user mode
 * @details Provides current driver status and statistics
 *
 * @param OutputBuffer Buffer to receive status
 * @param OutputBufferLength Size of output buffer
 * @param ReturnOutputBufferLength Actual size of output
 * @return STATUS_SUCCESS on success
 */
NTSTATUS HandleStatusRequest(
    _Out_writes_bytes_to_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    typedef struct _STATUS_REPLY {
        BOOLEAN MonitoringEnabled;
        ULONG DetectionSensitivity;
        ULONG FileOperationCount;
        ULONG MessagesSent;
        ULONG MessagesReceived;
    } STATUS_REPLY, * PSTATUS_REPLY;

    PSTATUS_REPLY reply = NULL;
    KIRQL oldIrql;

    // Check buffer size
    if (OutputBufferLength < sizeof(STATUS_REPLY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    reply = (PSTATUS_REPLY)OutputBuffer;
    RtlZeroMemory(reply, sizeof(STATUS_REPLY));

    // Get configuration with lock
    KeAcquireSpinLock(&g_Context.ConfigLock, &oldIrql);
    reply->MonitoringEnabled = g_Context.MonitoringEnabled;
    reply->DetectionSensitivity = g_Context.DetectionSensitivity;
    KeReleaseSpinLock(&g_Context.ConfigLock, oldIrql);

    // Get statistics with lock
    KeAcquireSpinLock(&g_Context.StatisticsLock, &oldIrql);
    reply->FileOperationCount = g_Context.FileOperationCount;
    reply->MessagesSent = g_Context.MessagesSent;
    reply->MessagesReceived = g_Context.MessagesReceived;
    KeReleaseSpinLock(&g_Context.StatisticsLock, oldIrql);

    *ReturnOutputBufferLength = sizeof(STATUS_REPLY);

    CS_INFO("Status request handled - Ops: %d, Sent: %d, Recv: %d",
        reply->FileOperationCount, reply->MessagesSent, reply->MessagesReceived);

    return STATUS_SUCCESS;
}

/**
 * @brief Handles configuration update from user mode
 * @details Updates driver configuration settings
 *
 * @param Message Configuration message
 * @param MessageLength Message size
 * @return STATUS_SUCCESS on success
 */
NTSTATUS HandleConfigUpdate(
    _In_ PCRYPTOSHIELD_MESSAGE Message,
    _In_ ULONG MessageLength
)
{
    typedef struct _CONFIG_UPDATE {
        CRYPTOSHIELD_MESSAGE Header;
        BOOLEAN MonitoringEnabled;
        ULONG DetectionSensitivity;
    } CONFIG_UPDATE, * PCONFIG_UPDATE;

    PCONFIG_UPDATE config = NULL;
    KIRQL oldIrql;

    // Validate message size
    if (MessageLength < sizeof(CONFIG_UPDATE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    config = (PCONFIG_UPDATE)Message;

    // Validate configuration values
    if (config->DetectionSensitivity > 100) {
        CS_WARNING("Invalid detection sensitivity: %d", config->DetectionSensitivity);
        return STATUS_INVALID_PARAMETER;
    }

    // Update configuration with lock
    KeAcquireSpinLock(&g_Context.ConfigLock, &oldIrql);
    g_Context.MonitoringEnabled = config->MonitoringEnabled;
    g_Context.DetectionSensitivity = config->DetectionSensitivity;
    KeReleaseSpinLock(&g_Context.ConfigLock, oldIrql);

    CS_INFO("Configuration updated - Monitoring: %s, Sensitivity: %d",
        config->MonitoringEnabled ? "Enabled" : "Disabled",
        config->DetectionSensitivity);

    return STATUS_SUCCESS;
}

/**
 * @brief Handles shutdown request from user mode
 * @details Prepares driver for clean shutdown
 *
 * @return STATUS_SUCCESS
 */
NTSTATUS HandleShutdownRequest(VOID)
{
    CS_INFO("Shutdown request received");

    // Set monitoring to disabled to stop new operations
    InterlockedExchange8((CHAR*)&g_Context.MonitoringEnabled, FALSE);

    // Note: Actual unload will be handled by FilterUnload callback
    // We just prepare for shutdown here

    return STATUS_SUCCESS;
}

/**
 * @brief Sends alert message to user mode
 * @details Used for high-priority notifications
 *
 * @param AlertType Type of alert
 * @param Description Alert description
 * @return STATUS_SUCCESS on success
 */
NTSTATUS SendAlertMessage(
    _In_ ULONG AlertType,
    _In_ PCWSTR Description
)
{
    typedef struct _ALERT_MESSAGE {
        CRYPTOSHIELD_MESSAGE Header;
        ULONG AlertType;
        WCHAR Description[256];
    } ALERT_MESSAGE, * PALERT_MESSAGE;

    NTSTATUS status = STATUS_SUCCESS;
    PALERT_MESSAGE alert = NULL;
    LARGE_INTEGER timeout = { 0 };
    ULONG replyLength = 0;
    CRYPTOSHIELD_REPLY reply = { 0 };

    // Check if client is connected
    if (!g_Context.ClientConnected || g_Context.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }

    // Allocate alert message
    alert = (PALERT_MESSAGE)CS_ALLOC_POOL(sizeof(ALERT_MESSAGE));
    if (alert == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        // Initialize alert message
        RtlZeroMemory(alert, sizeof(ALERT_MESSAGE));
        alert->Header.MessageType = MSG_FILE_OPERATION;  // Reuse for now
        alert->AlertType = AlertType;

        // Copy description
        if (Description != NULL) {
            wcscpy_s(alert->Description,
                sizeof(alert->Description) / sizeof(WCHAR),
                Description);
        }

        // Set timeout (50ms for alerts)
        timeout.QuadPart = -500000;

        // Send alert
        status = FltSendMessage(g_Context.FilterHandle,
            &g_Context.ClientPort,
            alert,
            sizeof(ALERT_MESSAGE),
            &reply,
            &replyLength,
            &timeout);

        if (!NT_SUCCESS(status)) {
            CS_WARNING("Failed to send alert: 0x%08x", status);
        }

    }
    __finally {
        if (alert != NULL) {
            CS_FREE_POOL(alert);
        }
    }

    return status;
}