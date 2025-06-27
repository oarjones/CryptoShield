#pragma once

#ifndef _COMMUNICATION_H_
#define _COMMUNICATION_H_

#include "CryptoShield.h" // Necesario para PCS_MESSAGE_PAYLOAD_HEADER, etc.

// Prototipo para la función de encolado de alertas
NTSTATUS QueueTamperAlert(ULONG TamperType);

// Prototipo para el envío de mensajes
NTSTATUS SendMessageToUserService(
    _In_ PCS_MESSAGE_PAYLOAD_HEADER PayloadHeader,
    _In_ ULONG PayloadSize,
    _Out_opt_ PVOID ReplyBuffer,
    _Inout_opt_ PULONG ReplyLength
);

// Prototipos para los callbacks del puerto
NTSTATUS ConnectNotifyCallback(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie, _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, _In_ ULONG SizeOfContext, _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie);
VOID DisconnectNotifyCallback(_In_opt_ PVOID ConnectionCookie);
NTSTATUS MessageNotifyCallback(_In_opt_ PVOID PortCookie, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer, _In_ ULONG InputBufferLength, _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength);

#endif // _COMMUNICATION_H_