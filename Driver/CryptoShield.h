#pragma once

#ifndef _CRYPTOSHIELD_H_
#define _CRYPTOSHIELD_H_

// --- Inclusiones de Cabeceras del WDK ---
// Estas cabeceras definen todos los tipos de datos y funciones del kernel necesarios.
#include <fltKernel.h>
#include <ntddk.h>
#include <suppress.h>
#include <ntstrsafe.h>

// --- Definiciones Compartidas con el User-Mode ---
#include "../Common/Shared.h"

// --- Definiciones Propias del Driver ---
#define CRYPTOSHIELD_POOL_TAG 'SdSC' // Pool Tag para asignaciones de memoria
#define MAX_CLIENT_CONNECTIONS 1

// Macros de Logging
#if DBG
#define CS_DBG_PRINT(Level, Fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, Level, "[CryptoShield] (%s:%d) " Fmt "\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#else
#define CS_DBG_PRINT(Level, Fmt, ...)
#endif

#define CS_LOG_ERROR(Fmt, ...)   CS_DBG_PRINT(DPFLTR_ERROR_LEVEL, Fmt, __VA_ARGS__)
#define CS_LOG_WARNING(Fmt, ...) CS_DBG_PRINT(DPFLTR_WARNING_LEVEL, Fmt, __VA_ARGS__)
#define CS_LOG_INFO(Fmt, ...)    CS_DBG_PRINT(DPFLTR_INFO_LEVEL, Fmt, __VA_ARGS__)
#define CS_LOG_TRACE(Fmt, ...)   CS_DBG_PRINT(DPFLTR_TRACE_LEVEL, Fmt, __VA_ARGS__)

// Macros de Gestión de Memoria
#define CS_ALLOCATE_POOL(PoolFlags, Size) \
    ExAllocatePool2(PoolFlags, Size, CRYPTOSHIELD_POOL_TAG)

#define CS_FREE_POOL(Buffer) \
    ExFreePoolWithTag(Buffer, CRYPTOSHIELD_POOL_TAG)

// Macro de Verificación de IRQL
#define CS_ASSERT_IRQL_PASSIVE() NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL)

// Estructura para la cola de alertas de manipulación.
typedef struct _TAMPER_ALERT_WORK_ITEM {
    LIST_ENTRY ListEntry;
    CS_TAMPER_ALERT_PAYLOAD AlertPayload;
} TAMPER_ALERT_WORK_ITEM, * PTAMPER_ALERT_WORK_ITEM;

// --- Estructura de Contexto Global del Driver ---
typedef struct _CRYPTOSHIELD_CONTEXT {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;

    // Estado y Configuración
    BOOLEAN MonitoringEnabled;
    ULONG DetectionSensitivity;
    ULONG ActiveConfigFlags;
    ULONG ActiveResponseActions;
    BOOLEAN IsUnloading;
    BOOLEAN ClientConnected;
    LARGE_INTEGER DriverLoadTime;
    ULONG UserModeProcessId;

    // Estadísticas
    volatile LONG64 FileOperationsMonitored;
    volatile LONG64 MessagesSentToUserMode;
    volatile LONG64 MessagesReceivedFromUserMode;
    volatile LONG64 OperationsBlockedByDriver;
    volatile LONG64 ThreatsDetectedByDriver;

    // Sincronización
    KSPIN_LOCK StatisticsLock;
    KSPIN_LOCK ConfigLock;
    ERESOURCE PortResource;

    // Protección de Callbacks e Integridad
    PVOID CallbackTableBackup;
    ULONG CallbackTableSize;
    KTIMER IntegrityTimer;
    KDPC IntegrityDpc;
    PVOID DriverImageBase;
    ULONG DriverImageSize;
    ULONG64 InitialDriverChecksum;

    // Hilo de Alertas de Manipulación
    KSPIN_LOCK TamperAlertQueueLock;
    LIST_ENTRY TamperAlertQueue;
    HANDLE TamperAlertThreadHandle;
    PETHREAD TamperAlertThreadObject;
    KEVENT TamperAlertQueueEvent;
    BOOLEAN TerminateTamperAlertThread;
    BOOLEAN IsWorkItemScheduled; // <-- AÑADIDO PARA LA LÓGICA DE IoWorkItem
    PIO_WORKITEM TamperAlertWorkItem; // <-- AÑADIDO PARA LA LÓGICA DE IoWorkItem

} CRYPTOSHIELD_CONTEXT, * PCRYPTOSHIELD_CONTEXT;

// --- Variable de Contexto Global ---
extern CRYPTOSHIELD_CONTEXT g_Context;

// --- Prototipos de Funciones Principales ---
DRIVER_INITIALIZE DriverEntry;
NTSTATUS FilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

// Callbacks del Minifiltro
FLT_PREOP_CALLBACK_STATUS PreOperationCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);
NTSTATUS InstanceSetupCallback(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
NTSTATUS InstanceQueryTeardownCallback(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

#endif // _CRYPTOSHIELD_H_