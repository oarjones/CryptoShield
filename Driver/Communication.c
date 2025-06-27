#include "CryptoShield.h"
#include "Communication.h"

// Declaración adelantada de la rutina del Work Item
VOID ProcessTamperAlertQueueWorkRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context);

// Esta función es llamada por la DPC para encolar un trabajo.
// Es la única función de este fichero que necesita ser exportada en Communication.h.
NTSTATUS QueueTamperAlert(ULONG TamperType)
{
    PTAMPER_ALERT_WORK_ITEM workItem;
    KIRQL oldIrql;

    // Asignar memoria para el work item desde un pool no paginado, ya que se llama desde DISPATCH_LEVEL
    workItem = (PTAMPER_ALERT_WORK_ITEM)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TAMPER_ALERT_WORK_ITEM), CRYPTOSHIELD_POOL_TAG);
    if (workItem == NULL) {
        CS_LOG_ERROR("Fallo al asignar memoria para el work item de alerta de tampering.");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Rellenar el payload
    workItem->AlertPayload.Header.MessageType = MSG_TYPE_TAMPER_DETECTED;
    workItem->AlertPayload.Header.PayloadSize = sizeof(CS_TAMPER_ALERT_PAYLOAD);
    workItem->AlertPayload.TamperType = TamperType;

    // Poner el trabajo en la cola de forma segura
    KeAcquireSpinLock(&g_Context.TamperAlertQueueLock, &oldIrql);
    InsertTailList(&g_Context.TamperAlertQueue, &workItem->ListEntry);

    // Planificar la ejecución del worker thread si no está ya planificado
    if (!g_Context.IsWorkItemScheduled) {
        g_Context.IsWorkItemScheduled = TRUE;
        IoQueueWorkItem(g_Context.TamperAlertWorkItem, ProcessTamperAlertQueueWorkRoutine, DelayedWorkQueue, NULL);
    }
    KeReleaseSpinLock(&g_Context.TamperAlertQueueLock, oldIrql);

    return STATUS_SUCCESS;
}

// Esta es la rutina que se ejecuta en PASSIVE_LEVEL
VOID ProcessTamperAlertQueueWorkRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    PAGED_CODE();

    while (TRUE) {
        PLIST_ENTRY listEntry;
        PTAMPER_ALERT_WORK_ITEM workItem;
        KIRQL oldIrql;

        KeAcquireSpinLock(&g_Context.TamperAlertQueueLock, &oldIrql);
        if (IsListEmpty(&g_Context.TamperAlertQueue)) {
            g_Context.IsWorkItemScheduled = FALSE; // Ya no hay trabajo
            KeReleaseSpinLock(&g_Context.TamperAlertQueueLock, oldIrql);
            break; // Salir del bucle
        }
        listEntry = RemoveHeadList(&g_Context.TamperAlertQueue);
        KeReleaseSpinLock(&g_Context.TamperAlertQueueLock, oldIrql);

        workItem = CONTAINING_RECORD(listEntry, TAMPER_ALERT_WORK_ITEM, ListEntry);

        if (g_Context.ClientConnected) {
            SendMessageToUserService(
                (PCS_MESSAGE_PAYLOAD_HEADER)&workItem->AlertPayload,
                sizeof(CS_TAMPER_ALERT_PAYLOAD),
                NULL,
                NULL
            );
        }
        CS_FREE_POOL(workItem);
    }
}


// El resto de funciones de callbacks de puerto se quedan igual
NTSTATUS ConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie
)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    CS_LOG_INFO("Peticion de conexion del servicio de usuario recibida.");

    ExEnterCriticalRegionAndAcquireResourceExclusive(&g_Context.PortResource);
    if (g_Context.ClientConnected) {
        ExReleaseResourceAndLeaveCriticalRegion(&g_Context.PortResource);
        CS_LOG_WARNING("Un cliente ya esta conectado. Rechazando nueva conexion.");
        return STATUS_TOO_MANY_SESSIONS;
    }

    g_Context.ClientPort = ClientPort;
    g_Context.ClientConnected = TRUE;
    *ConnectionCookie = (PVOID)ClientPort;
    ExReleaseResourceAndLeaveCriticalRegion(&g_Context.PortResource);

    CS_LOG_INFO("Servicio de usuario conectado correctamente. ClientPort: 0x%p", ClientPort);
    return STATUS_SUCCESS;
}

VOID DisconnectNotifyCallback(_In_opt_ PVOID ConnectionCookie)
{
    PAGED_CODE();
    CS_LOG_INFO("Servicio de usuario desconectandose. ConnectionCookie: 0x%p", ConnectionCookie);

    ExEnterCriticalRegionAndAcquireResourceExclusive(&g_Context.PortResource);
    if (g_Context.ClientConnected && (PFLT_PORT)ConnectionCookie == g_Context.ClientPort) {
        g_Context.ClientConnected = FALSE;
        FltCloseClientPort(g_Context.FilterHandle, &g_Context.ClientPort);
        g_Context.ClientPort = NULL;
        CS_LOG_INFO("Servicio de usuario desconectado correctamente.");
    }
    ExReleaseResourceAndLeaveCriticalRegion(&g_Context.PortResource);
}

NTSTATUS MessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    // Esta función puede permanecer como está para manejar mensajes del servicio al driver.
    // Por ahora, su contenido no es crítico para la compilación.
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
    return STATUS_SUCCESS;
}

NTSTATUS SendMessageToUserService(
    _In_ PCS_MESSAGE_PAYLOAD_HEADER PayloadHeader,
    _In_ ULONG PayloadSize,
    _Out_opt_ PVOID ReplyBuffer,
    _Inout_opt_ PULONG ReplyLength
)
{
    NTSTATUS status;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -(500LL * 10000LL); // 500 ms

    if (g_Context.IsUnloading || !g_Context.ClientConnected || g_Context.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }

    status = FltSendMessage(
        g_Context.FilterHandle,
        &g_Context.ClientPort,
        (PVOID)PayloadHeader,
        PayloadSize,
        ReplyBuffer,
        ReplyLength,
        &timeout
    );

    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_Context.MessagesSentToUserMode);
    }

    return status;
}