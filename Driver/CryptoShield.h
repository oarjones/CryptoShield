/**
 * @file CryptoShield.h
 * @brief Main header file for CryptoShield minifilter driver
 * @details Contains core definitions, structures and function declarations
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

 // <<<--- AÑADIR ESTAS LÍNEAS ---<<<
#ifndef _CRYPTOSHIELD_H_
#define _CRYPTOSHIELD_H_
// --- FIN DE LÍNEAS A AÑADIR ---<<<

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>    // Para RtlStringCchPrintfW y similares
#include "../Common/Shared.h"

 // Driver identification (podrían ir en Shared.h si el servicio también necesita el nombre exacto)
#define CRYPTOSHIELD_DRIVER_NAME_INTERNAL L"CryptoShield" // Nombre para logs, etc.
#define CRYPTOSHIELD_POOL_TAG             'SdSC'  // "CSdS" CryptoShield Driver Stack

// Communication port settings (MAX_PORT_CONNECTIONS ya está en Shared.h si se quiere)
#define MAX_CLIENT_CONNECTIONS      1 // Número máximo de servicios de usuario conectados

// Configuration defaults (DEFAULT_MONITORING_ENABLED, DEFAULT_DETECTION_SENSITIVITY ya en Shared.h)

// Driver context structure (del documento técnico, ajustado)
typedef struct _CRYPTOSHIELD_CONTEXT {
    PFLT_FILTER FilterHandle;       // Handle del filtro obtenido de FltRegisterFilter
    PFLT_PORT ServerPort;           // Puerto del servidor para escuchar conexiones del user-mode
    PFLT_PORT ClientPort;           // Puerto del cliente conectado (solo 1 según MAX_CLIENT_CONNECTIONS)

    // Configuración (cargada o por defecto, modificable por el servicio)
    BOOLEAN MonitoringEnabled;      // Habilita/deshabilita el monitoreo de archivos
    ULONG DetectionSensitivity;     // Nivel de sensibilidad para la detección (0-100)
    ULONG ActiveConfigFlags;        // Flags de CONFIG_FLAG_* actualmente activos
    ULONG ActiveResponseActions;    // Acciones ACTION_* actualmente activas para amenazas

    // Estadísticas (contadores volátiles)
    volatile LONG64 FileOperationsMonitored; // Usar LONG64 para contadores grandes
    volatile LONG64 MessagesSentToUserMode;
    volatile LONG64 MessagesReceivedFromUserMode;
    volatile LONG64 OperationsBlockedByDriver;
    volatile LONG64 ThreatsDetectedByDriver;
    // Añadir más según sea necesario

    // Sincronización
    KSPIN_LOCK StatisticsLock;      // Spinlock para proteger el acceso a las estadísticas
    KSPIN_LOCK ConfigLock;          // Spinlock para proteger el acceso a la configuración
    ERESOURCE PortResource;         // Recurso para proteger ClientPort y ClientConnected
    // (ExInitializeResourceLite, ExAcquireResourceExclusiveLite, etc.)
// Estado
    BOOLEAN IsUnloading;            // Flag para indicar que el driver se está descargando
    BOOLEAN ClientConnected;        // Flag para indicar si un cliente de user-mode está conectado
    LARGE_INTEGER DriverLoadTime;   // Momento en que el driver fue cargado
    // ULONG MonitoredProcessesCount; // Si se lleva cuenta de procesos específicos
    // ULONG CurrentMemoryUsageKB;  // Si se monitorea el uso de memoria
    ULONG UserModeProcessId; // <-- AÑADE ESTA LÍNEA

    // Callback Table Protection
    PVOID CallbackTableBackup;      // Backup de la tabla de callbacks
    ULONG CallbackTableSize;        // Tamaño de la tabla
    KTIMER IntegrityTimer;          // Timer para la verificación periódica
    KDPC IntegrityDpc;              // DPC para ejecutar la verificación

    // Driver Memory Integrity
    PVOID DriverImageBase;          // Base address of the driver image
    ULONG DriverImageSize;          // Size of the driver image
    ULONG64 InitialDriverChecksum;  // Checksum of the driver image calculated at load time

    // --- INICIO DE NUEVOS MIEMBROS PARA WORKER THREAD ---
    KSPIN_LOCK TamperAlertQueueLock;      // Spinlock para proteger la cola
    LIST_ENTRY TamperAlertQueue;          // Cabeza de la lista (la cola)
    PIO_WORKITEM TamperAlertWorkItem;       // El work item que procesará la cola
    BOOLEAN IsWorkItemScheduled;          // Flag para evitar encolar trabajos si ya hay uno pendiente
    // --- FIN DE NUEVOS MIEMBROS ---
} CRYPTOSHIELD_CONTEXT, *PCRYPTOSHIELD_CONTEXT;

// Estructura para cada elemento de trabajo
typedef struct _TAMPER_ALERT_WORK_ITEM {
    LIST_ENTRY ListEntry; // Para enlazar en la cola
    CS_TAMPER_ALERT_PAYLOAD AlertPayload;
} TAMPER_ALERT_WORK_ITEM, *PTAMPER_ALERT_WORK_ITEM;

// Global driver context
extern CRYPTOSHIELD_CONTEXT g_Context;


// Estructura para el buffer de respuesta que el KERNEL espera del USUARIO
// cuando se usa FltSendMessage con un ReplyBuffer.
// El payload es CS_USER_REPLY_PAYLOAD de Shared.h.
typedef struct _KERNEL_EXPECTED_USER_REPLY {
    FILTER_REPLY_HEADER FilterReplyHeader; // Encabezado estándar para FltSendMessage
    CS_USER_REPLY_PAYLOAD UserPayload;     // El payload definido en Shared.h
} KERNEL_EXPECTED_USER_REPLY, * PKERNEL_EXPECTED_USER_REPLY;


// ----- Function Declarations -----

// Driver Entry and Unload (nombres según documento técnico y convenciones)
DRIVER_INITIALIZE DriverEntry;
NTSTATUS FilterUnloadCallback( // Cambiado de CryptoShieldUnload
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

// Minifilter Operation Callbacks (nombres según documento técnico)
FLT_PREOP_CALLBACK_STATUS PreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// Minifilter Instance Setup/Teardown Callbacks
NTSTATUS InstanceSetupCallback( // Nombre genérico más descriptivo
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS InstanceQueryTeardownCallback( // Nombre genérico
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);
// NTSTATUS InstanceTeardownStartCallback(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags);
// NTSTATUS InstanceTeardownCompleteCallback(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags);


// Communication Port Callbacks (nombres según documento técnico)
NTSTATUS ConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, // Contexto enviado por el cliente al conectar
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie // Cookie para esta conexión específica
);

VOID DisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie // El cookie devuelto por ConnectNotifyCallback
);

NTSTATUS MessageNotifyCallback(
    _In_opt_ PVOID PortCookie, // ServerPortCookie (NULL en este caso) o ConnectionCookie si se configuró
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer, // Mensaje del cliente
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer, // Buffer para la respuesta al cliente
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);


// ----- Funciones Internas / de Utilidad del Driver -----

// Funciones de Comunicación (Communication.c)
NTSTATUS SendMessageToUserService(
    _In_ PCS_MESSAGE_PAYLOAD_HEADER PayloadHeader, // Puntero al inicio del payload a enviar (debe ser un tipo de Shared.h)
    _In_ ULONG PayloadSize,                        // Tamaño del payload
    _Out_opt_ PVOID ReplyBuffer,                   // Buffer para la respuesta del servicio (si se espera)
    _Inout_opt_ PULONG ReplyLength                 // Tamaño del buffer de respuesta / tamaño devuelto
);

// Worker routine for processing tamper alerts from the queue
VOID ProcessTamperAlertQueueWorkRoutine(_In_ PVOID Context);


// Tamper Alert Worker Thread functions (Communication.c or a new file like TamperAlert.c)
// These are now mostly handled by the IoWorkItem mechanism directly in DriverEntry/FilterUnload
// and the DPC queuing logic. The functions below might be obsolete or refactored.
// NTSTATUS InitializeTamperAlertThread(VOID); // Replaced by direct init in DriverEntry
// VOID ShutdownTamperAlertThread(VOID);   // Replaced by direct cleanup in FilterUnload
// VOID TamperAlertThreadRoutine(_In_ PVOID StartContext); // Replaced by ProcessTamperAlertQueueWorkRoutine
NTSTATUS QueueTamperAlert(_In_ ULONG TamperType); // This logic will be part of IntegrityCheckDpcRoutine


// Funciones de Monitoreo de Archivos (FileMonitor.c)
NTSTATUS GetNormalizedFileNameInformation( // Renombrado de GetFileNameInformation
    _In_ PFLT_CALLBACK_DATA Data,
    _Outptr_ PFLT_FILE_NAME_INFORMATION* FileNameInfo // Devuelve la estructura para ser liberada por el llamador
);

// Funciones de Utilidad (Utilities.c)
BOOLEAN IsFileSystemSupported(
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

BOOLEAN ShouldMonitorFileByPath( // Renombrado de ShouldMonitorFile
    _In_ PFLT_FILE_NAME_INFORMATION FileNameInfo
);

// Prototipos para funciones de Utilities.c que se usan internamente en el driver si son necesarias en varios .c
// NTSTATUS DuplicateUnicodeString_Kernel(PUNICODE_STRING Dest, PCUNICODE_STRING Source, POOL_TYPE PoolType, ULONG Tag);
// VOID FreeUnicodeString_Kernel(PUNICODE_STRING String, ULONG Tag);
// ... etc. (FltFindUnicodeString ya está en Shared.h o aquí si es solo kernel)


// ----- Macros de Ayuda del Driver -----

// Debug/Logging (ya definidos en el código original)
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


// Memory Allocation (usando el tag definido arriba)
#define CS_ALLOCATE_POOL(PoolFlags, Size) \
    ExAllocatePool2(PoolFlags, Size, CRYPTOSHIELD_POOL_TAG)

#define CS_FREE_POOL(Buffer) \
    ExFreePoolWithTag(Buffer, CRYPTOSHIELD_POOL_TAG) // ExFreePool no necesita tag, pero ExFreePoolWithTag es más explícito si se mantiene el tag

// IRQL Verification
#define CS_ASSERT_IRQL_PASSIVE() NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL)
#define CS_ASSERT_IRQL_DISPATCH_LEVEL_OR_BELOW() NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL)
// Añadir más según sea necesario

#endif // _CRYPTOSHIELD_H_