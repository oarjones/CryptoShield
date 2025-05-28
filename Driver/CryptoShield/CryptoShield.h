#pragma once

#include <fltKernel.h> // Required for PFLT_FILTER, PFLT_PORT, KSPIN_LOCK etc.
#include <ntdef.h>     // Required for WCHAR, LARGE_INTEGER, ULONG, BOOLEAN etc.

// Context global del driver
typedef struct _CRYPTOSHIELD_CONTEXT {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort; // Should be volatile if accessed by multiple threads without further sync
    
    // Configuración
    BOOLEAN MonitoringEnabled; // Should be volatile or protected by a lock if changed dynamically
    ULONG DetectionSensitivity; // Same as above
    
    // Estadísticas
    ULONG FileOperationCount; // Use InterlockedIncrement for atomic updates or protect with StatisticsLock
    ULONG MessagesSent;       // Same as above
    
    // Sincronización
    KSPIN_LOCK StatisticsLock; // Used to protect access to statistics if not using interlocked operations
    
} CRYPTOSHIELD_CONTEXT, *PCRYPTOSHIELD_CONTEXT;

// Mensaje de comunicación
typedef struct _FILTER_MESSAGE {
    FILTER_MESSAGE_HEADER Header; // Standard header for filter communication
    ULONG MessageType;
    ULONG ProcessId;
    ULONG ThreadId;
    LARGE_INTEGER Timestamp;
    WCHAR FilePath[260]; // MAX_PATH typical value
    ULONG FilePathLength; // Length of FilePath in characters, not bytes
    ULONG OperationType; // Custom defined operation types
} FILTER_MESSAGE, *PFILTER_MESSAGE;

// Tipos de mensaje
#define MSG_FILE_OPERATION    1
#define MSG_STATUS_REQUEST    2
#define MSG_CONFIG_UPDATE     3

// Pool tag for memory allocations
#define CRYPTOSHIELD_TAG 'hSyC' // "CySh" in ASCII, useful for debugging

// Global driver context variable (declaration)
extern PCRYPTOSHIELD_CONTEXT g_CryptoShieldContext;
