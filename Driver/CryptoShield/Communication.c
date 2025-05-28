#include "CryptoShield.h" // For g_CryptoShieldContext, message types, CRYPTOSHIELD_TAG
#include <fltKernel.h>    // For FLT_PORT, FltCloseClientPort, etc.
// ntstrsafe.h is not strictly needed for this implementation but often included.
// #include <ntstrsafe.h> 

// ConnectNotifyCallback: Called when a user-mode application connects to the filter's communication port.
NTSTATUS ConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie, // Context passed when FltCreateCommunicationPort was called (g_CryptoShieldContext)
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, // Context from the connecting user-mode application (optional)
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie // Output: cookie to identify this connection later (e.g., in Disconnect)
) {
    UNREFERENCED_PARAMETER(ServerPortCookie); // We use g_CryptoShieldContext directly
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    PAGED_CODE();

    KdPrint(("CryptoShield: ConnectNotifyCallback - Client attempting to connect.\n"));

    if (g_CryptoShieldContext == NULL) {
        // This should ideally not happen if the port is up and driver is loaded.
        KdPrint(("CryptoShield: ConnectNotifyCallback - Global context is NULL.\n"));
        return STATUS_FLT_INSTANCE_NOT_FOUND; 
    }

    // Allow only one client connection at a time for simplicity.
    // Use InterlockedCompareExchangePointer to safely check and set ClientPort.
    if (InterlockedCompareExchangePointer(
            (PVOID volatile *)&g_CryptoShieldContext->ClientPort, // Destination (must be volatile PVOID*)
            ClientPort,                               // Exchange (new value if condition met)
            NULL                                      // Comperand (expected current value: no client connected)
        ) != NULL) {
        // If g_CryptoShieldContext->ClientPort was not NULL, another client is already connected.
        KdPrint(("CryptoShield: ConnectNotifyCallback - Connection attempt denied. ClientPort already set to %p.\n", g_CryptoShieldContext->ClientPort));
        return STATUS_FLT_ALREADY_CONNECTED; 
    }
    
    // Store the client port handle in our global context. Done by InterlockedCompareExchangePointer.

    // The ConnectionCookie will be passed to DisconnectNotifyCallback.
    // We use the ClientPort handle itself as the cookie.
    *ConnectionCookie = ClientPort; 

    KdPrint(("CryptoShield: ConnectNotifyCallback - Client connected successfully. ClientPort: %p, ConnectionCookie set to %p\n", ClientPort, *ConnectionCookie));
    return STATUS_SUCCESS;
}

// DisconnectNotifyCallback: Called when the connection is terminated.
VOID DisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie // The cookie returned by ConnectNotifyCallback (ClientPort handle)
) {
    PAGED_CODE();

    KdPrint(("CryptoShield: DisconnectNotifyCallback - Client disconnecting. ConnectionCookie (ClientPort): %p\n", ConnectionCookie));

    if (g_CryptoShieldContext == NULL) {
        KdPrint(("CryptoShield: DisconnectNotifyCallback - Global context is NULL.\n"));
        return;
    }
    
    if (ConnectionCookie == NULL) {
        KdPrint(("CryptoShield: DisconnectNotifyCallback - Warning: Received NULL ConnectionCookie.\n"));
        return;
    }

    // ConnectionCookie is the ClientPort that was stored.
    // Clear our stored client port handle, ensuring it matches the disconnecting port.
    // InterlockedCompareExchangePointer ensures atomicity.
    PVOID previousClientPort = InterlockedCompareExchangePointer(
                                    (PVOID volatile *)&g_CryptoShieldContext->ClientPort, // Destination
                                    NULL,                       // Set to NULL
                                    ConnectionCookie            // Expected current value (the disconnecting port)
                                );

    if (previousClientPort == ConnectionCookie) {
        // Successfully cleared the ClientPort that matched the ConnectionCookie.
        // The Filter Manager will close the ClientPort handle implicitly after this callback returns.
        KdPrint(("CryptoShield: DisconnectNotifyCallback - ClientPort %p cleared from context. Filter Manager will close the handle.\n", ConnectionCookie));
    } else if (previousClientPort != NULL) {
        // This case means g_CryptoShieldContext->ClientPort was some other non-NULL value
        // when we tried to clear it. This could indicate a logic issue or race if not expected.
        KdPrint(("CryptoShield: DisconnectNotifyCallback - Warning: ClientPort in context (%p) did not match ConnectionCookie (%p) during clear attempt.\n",
                 previousClientPort, ConnectionCookie));
    } else { // previousClientPort was NULL
        KdPrint(("CryptoShield: DisconnectNotifyCallback - ClientPort was already NULL when trying to clear for ConnectionCookie %p.\n", ConnectionCookie));
    }
}

// MessageNotifyCallback: Called when the user-mode application sends a message to the filter.
NTSTATUS MessageNotifyCallback(
    _In_opt_ PVOID PortCookie, // The ConnectionCookie from ConnectNotifyCallback (ClientPort)
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer, // Message from user mode
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer, // Buffer for reply
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength   // Length of the reply
) {
    UNREFERENCED_PARAMETER(PortCookie); // PortCookie is the ClientPort. We use g_CryptoShieldContext for global state.
    PFILTER_MESSAGE requestMessage = NULL;
    NTSTATUS status = STATUS_SUCCESS; // Default to success

    PAGED_CODE();

    KdPrint(("CryptoShield: MessageNotifyCallback - Received message. InputBufferLength: %lu, OutputBufferLength: %lu\n", InputBufferLength, OutputBufferLength));

    *ReturnOutputBufferLength = 0; // Initialize to no reply

    if (g_CryptoShieldContext == NULL) {
        KdPrint(("CryptoShield: MessageNotifyCallback - Global context is NULL.\n"));
        return STATUS_FLT_INSTANCE_NOT_FOUND; 
    }
    // Optionally check g_CryptoShieldContext->MonitoringEnabled here if messages should only be processed when enabled.

    if (InputBuffer == NULL || InputBufferLength < sizeof(FILTER_MESSAGE_HEADER)) {
        KdPrint(("CryptoShield: MessageNotifyCallback - Invalid input buffer or too small for header. Length: %lu\n", InputBufferLength));
        return STATUS_INVALID_PARAMETER;
    }
    
    // For now, we assume all messages fit the FILTER_MESSAGE structure or at least its header.
    // A more robust check for specific message types might be needed if they vary greatly in size.
    // if (InputBufferLength < sizeof(FILTER_MESSAGE)) {
    //     KdPrint(("CryptoShield: MessageNotifyCallback - Input buffer too small for FILTER_MESSAGE structure. Length: %lu\n", InputBufferLength));
    //     // Depending on message types, this might be too strict or not strict enough.
    //     // return STATUS_BUFFER_TOO_SMALL; // Or STATUS_INVALID_PARAMETER
    // }

    requestMessage = (PFILTER_MESSAGE)InputBuffer;

    switch (requestMessage->MessageType) {
        case MSG_STATUS_REQUEST:
            KdPrint(("CryptoShield: MessageNotifyCallback - Received MSG_STATUS_REQUEST.\n"));
            if (OutputBuffer != NULL && OutputBufferLength >= sizeof(ULONG)) {
                // Example: Reply with FileOperationCount.
                // This assumes FileOperationCount is updated atomically (e.g., InterlockedIncrement).
                // If StatisticsLock protects it for writes, it should ideally be used for reads too for consistency.
                // For simplicity, direct read:
                *(PULONG)OutputBuffer = g_CryptoShieldContext->FileOperationCount;
                *ReturnOutputBufferLength = sizeof(ULONG);
                status = STATUS_SUCCESS;
                KdPrint(("CryptoShield: MessageNotifyCallback - Responded to MSG_STATUS_REQUEST with FileOperationCount: %lu\n", *(PULONG)OutputBuffer));
            } else {
                KdPrint(("CryptoShield: MessageNotifyCallback - Output buffer too small for MSG_STATUS_REQUEST reply. Required: %zu, Available: %lu\n", sizeof(ULONG), OutputBufferLength));
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        case MSG_CONFIG_UPDATE:
            KdPrint(("CryptoShield: MessageNotifyCallback - Received MSG_CONFIG_UPDATE.\n"));
            // Placeholder for configuration update.
            // A real implementation would:
            // 1. Define the structure of the config update message (e.g., within FILTER_MESSAGE or a new struct).
            // 2. Validate InputBufferLength for the specific config message.
            // 3. Extract config values from requestMessage.
            // 4. Acquire a spinlock (e.g., g_CryptoShieldContext->StatisticsLock or a dedicated config lock)
            //    before updating shared g_CryptoShieldContext members like MonitoringEnabled or DetectionSensitivity.
            // 5. Update the context.
            // 6. Release the spinlock.
            // Example (conceptual, assuming config data is part of FILTER_MESSAGE.FilePath for demo):
            // if (InputBufferLength >= FIELD_OFFSET(FILTER_MESSAGE, FilePath) + sizeof(BOOLEAN)) {
            //    BOOLEAN newMonitoringState = *(BOOLEAN*)((PCHAR)requestMessage + FIELD_OFFSET(FILTER_MESSAGE, FilePath));
            //    KIRQL oldIrql;
            //    KeAcquireSpinLock(&g_CryptoShieldContext->StatisticsLock, &oldIrql); // Use appropriate lock
            //    g_CryptoShieldContext->MonitoringEnabled = newMonitoringState;
            //    KeReleaseSpinLock(&g_CryptoShieldContext->StatisticsLock, oldIrql);
            //    KdPrint(("CryptoShield: MessageNotifyCallback - MonitoringEnabled hypothetically updated to %d.\n", newMonitoringState));
            // } else {
            //    KdPrint(("CryptoShield: MessageNotifyCallback - MSG_CONFIG_UPDATE too short for payload.\n"));
            //    status = STATUS_INVALID_PARAMETER;
            // }
            status = STATUS_SUCCESS; // Acknowledge, even if not fully implemented
            break;

        default:
            KdPrint(("CryptoShield: MessageNotifyCallback - Received unknown message type: %lu.\n", requestMessage->MessageType));
            status = STATUS_INVALID_PARAMETER; // Or STATUS_FLT_INVALID_MESSAGE_RECEIVED
            break;
    }

    return status;
}
