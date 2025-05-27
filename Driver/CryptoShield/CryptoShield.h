#ifndef CRYPTOSHIELD_H
#define CRYPTOSHIELD_H

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

//
// Versión del driver
//
#define CRYPTOSHIELD_MAJOR_VERSION 1
#define CRYPTOSHIELD_MINOR_VERSION 0
#define CRYPTOSHIELD_BUILD_VERSION 0

//
// Tags para pool allocation
//
#define CRYPTOSHIELD_TAG 'CSRP'
#define TEMPORAL_GRAPH_TAG 'TGRP'
#define PROTECTION_TAG 'PROT'
#define COMMUNICATION_TAG 'COMM'

//
// Constantes de configuración
//
#define MAX_FILE_OPERATIONS 10000
#define MAX_PROCESS_OPERATIONS 5000
#define MAX_REGISTRY_OPERATIONS 2000
#define ENTROPY_ANALYSIS_BUFFER_SIZE 4096
#define TEMPORAL_WINDOW_SIZE 60 // segundos

//
// Enumeraciones
//
typedef enum _OPERATION_TYPE {
    OPERATION_FILE_CREATE = 1,
    OPERATION_FILE_WRITE,
    OPERATION_FILE_READ,
    OPERATION_FILE_DELETE,
    OPERATION_FILE_RENAME,
    OPERATION_PROCESS_CREATE,
    OPERATION_PROCESS_TERMINATE,
    OPERATION_REGISTRY_WRITE,
    OPERATION_REGISTRY_DELETE
} OPERATION_TYPE;

typedef enum _THREAT_LEVEL {
    THREAT_LEVEL_NONE = 0,
    THREAT_LEVEL_LOW,
    THREAT_LEVEL_MEDIUM,
    THREAT_LEVEL_HIGH,
    THREAT_LEVEL_CRITICAL
} THREAT_LEVEL;

//
// Contexto global del driver
//
typedef struct _CRYPTOSHIELD_CONTEXT {
    PFLT_FILTER FilterHandle;

    // Configuración
    BOOLEAN MonitoringEnabled;
    BOOLEAN SelfProtectionEnabled;
    ULONG DetectionSensitivity;

    // Comunicación con user mode
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;

    // Estadísticas
    ULONG FileOperationCount;
    ULONG ProcessOperationCount;
    ULONG RegistryOperationCount;

} CRYPTOSHIELD_CONTEXT, * PCRYPTOSHIELD_CONTEXT;

//
// Funciones exportadas
//
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
NTSTATUS FilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

//
// Callbacks de minifilter
//
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

//
// Variables globales
//
extern CRYPTOSHIELD_CONTEXT g_CryptoShieldContext;

#endif // CRYPTOSHIELD_H