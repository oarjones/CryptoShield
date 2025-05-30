/**
 * @file Shared.h
 * @brief Shared definitions between kernel driver and user service
 * @details Common structures and constants used by both components
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

 // <<<--- AÑADIR ESTAS LÍNEAS ---<<<
#ifndef _CRYPTOSHIELD_SHARED_H_
#define _CRYPTOSHIELD_SHARED_H_
// --- FIN DE LÍNEAS A AÑADIR ---<<<

 // Ensure we can compile in both kernel and user mode
#ifdef _KERNEL_MODE
#include <ntddk.h> // Para tipos como ULONG, LARGE_INTEGER, etc.
#define SHARED_API
#else
#include <windows.h> // Para tipos equivalentes en user-mode
#define SHARED_API __declspec(dllexport) // O __declspec(dllimport) para el consumidor
#endif

// Version information (ejemplo, puede expandirse)
#define CRYPTOSHIELD_VERSION_MAJOR  1
#define CRYPTOSHIELD_VERSION_MINOR  0
#define CRYPTOSHIELD_VERSION_BUILD  0
#define CRYPTOSHIELD_VERSION_STRING L"1.0.0"

// Communication port name (del documento técnico y código existente)
#define CRYPTOSHIELD_PORT_NAME      L"\\CryptoShieldPort"

// Maximum path length (Unicode) - MAX_PATH (260) es un buen estándar para FilePath.
// El documento técnico usa 260 para FilePath en FILTER_MESSAGE.
// El código original usaba 520 (MAX_PATH * 2). Se usará 260 según el doc.
#define MAX_FILE_PATH_CHARS         260
#define MAX_FILE_PATH_BYTES         (MAX_FILE_PATH_CHARS * sizeof(WCHAR))

// Message types for kernel-user communication (del documento técnico y código existente)
// Estos son los tipos que irán en el campo MessageType de las estructuras de mensaje.
#define MSG_TYPE_BASE               0 // Para evitar conflictos con otros sistemas de mensajes si los hubiera
#define MSG_TYPE_FILE_OPERATION     (MSG_TYPE_BASE + 1) // Corresponde a MSG_FILE_OPERATION del doc.
#define MSG_TYPE_STATUS_REQUEST     (MSG_TYPE_BASE + 2) // Corresponde a MSG_STATUS_REQUEST del doc.
#define MSG_TYPE_CONFIG_UPDATE      (MSG_TYPE_BASE + 3) // Corresponde a MSG_CONFIG_UPDATE del doc.
#define MSG_TYPE_SHUTDOWN_REQUEST   (MSG_TYPE_BASE + 4) // Del código original
#define MSG_TYPE_ALERT              (MSG_TYPE_BASE + 5) // Del código original
#define MSG_TYPE_THREAT_DETECTED    (MSG_TYPE_BASE + 6) // Del código original
// Añadir MSG_TYPE_STATUS_REPLY y MSG_TYPE_CONFIG_REPLY si el servicio espera una respuesta específica con estos tipos.

// File operation types (del código original, el documento no los detalla tanto)
#define FILE_OP_TYPE_CREATE              1
#define FILE_OP_TYPE_WRITE               2
#define FILE_OP_TYPE_DELETE              3
#define FILE_OP_TYPE_RENAME              4
#define FILE_OP_TYPE_SET_INFORMATION     5
#define FILE_OP_TYPE_CLEANUP             6

// Alert severity levels (del código original)
#define ALERT_SEVERITY_LOW          1
#define ALERT_SEVERITY_MEDIUM       2
#define ALERT_SEVERITY_HIGH         3
#define ALERT_SEVERITY_CRITICAL     4

// Detection sensitivity ranges (del código original)
#define MIN_DETECTION_SENSITIVITY   0
#define MAX_DETECTION_SENSITIVITY   100
#define DEFAULT_DETECTION_SENSITIVITY 50
#define DEFAULT_MONITORING_ENABLED  TRUE // <<< --- AÑADIR ESTA LÍNEA

// Process classification (del código original)
#define PROCESS_TYPE_UNKNOWN        0
#define PROCESS_TYPE_TRUSTED        1
#define PROCESS_TYPE_SUSPICIOUS     2
#define PROCESS_TYPE_MALICIOUS      3

// Response actions (del código original)
#define ACTION_ALLOW                0x00000001
#define ACTION_BLOCK                0x00000002
#define ACTION_QUARANTINE           0x00000004
#define ACTION_TERMINATE_PROCESS    0x00000008
#define ACTION_ALERT_USER           0x00000010
#define ACTION_LOG_ONLY             0x00000020

// Error codes specific to CryptoShield (del código original)
#define CRYPTOSHIELD_ERROR_BASE                 0xE0000000
#define CRYPTOSHIELD_ERROR_DRIVER_NOT_LOADED    (CRYPTOSHIELD_ERROR_BASE + 1)
#define CRYPTOSHIELD_ERROR_PORT_COMMUNICATION   (CRYPTOSHIELD_ERROR_BASE + 2)
#define CRYPTOSHIELD_ERROR_INVALID_MESSAGE      (CRYPTOSHIELD_ERROR_BASE + 3)
#define CRYPTOSHIELD_ERROR_QUEUE_FULL           (CRYPTOSHIELD_ERROR_BASE + 4)
#define CRYPTOSHIELD_ERROR_ANALYSIS_FAILED      (CRYPTOSHIELD_ERROR_BASE + 5)

// Configuration flags (del código original)
#define CONFIG_FLAG_MONITORING_ENABLED      0x00000001
#define CONFIG_FLAG_REALTIME_PROTECTION     0x00000002
#define CONFIG_FLAG_BEHAVIORAL_ANALYSIS     0x00000004
#define CONFIG_FLAG_MACHINE_LEARNING        0x00000008
#define CONFIG_FLAG_CLOUD_LOOKUP            0x00000010
#define CONFIG_FLAG_AUTO_QUARANTINE         0x00000020
#define CONFIG_FLAG_SILENT_MODE             0x00000040

// Statistics IDs (del código original, pueden usarse para identificar qué estadística se actualiza/consulta)
#define STAT_TOTAL_OPERATIONS               1
#define STAT_BLOCKED_OPERATIONS             2
#define STAT_DETECTED_THREATS               3
#define STAT_FALSE_POSITIVES                4
#define STAT_QUARANTINED_FILES              5


// Estructura base para mensajes que se envían/reciben y que *no* son el buffer directo de FltSendMessage.
// Esta es la cabecera del *payload* lógico.
// El documento técnico menciona FILTER_MESSAGE_HEADER para los mensajes kernel->usuario
// y una cabecera implícita para usuario->kernel.
// El Shared.h original tenía CRYPTOSHIELD_MESSAGE_HEADER. Vamos a unificar.

#pragma pack(push, 1) // Asegura el empaquetado byte a byte

/**
 * @brief Encabezado común para los *payloads* de mensajes lógicos entre kernel y usuario.
 * Nota: Cuando el kernel envía a usuario esperando respuesta (usando FltSendMessage),
 * el buffer real comienza con FILTER_MESSAGE_HEADER (de fltKernel.h), seguido por
 * una estructura de payload que puede usar esta CS_MESSAGE_PAYLOAD_HEADER.
 * Cuando el usuario envía al kernel, el InputBuffer en MessageNotifyCallback
 * será directamente el payload, que puede comenzar con esta cabecera.
 */
typedef struct _CS_MESSAGE_PAYLOAD_HEADER {
    ULONG MessageType;          // Uno de los MSG_TYPE_* definidos arriba.
    ULONG MessageId;            // Identificador único de mensaje (opcional, para correlación).
    ULONG PayloadSize;          // Tamaño total de este payload, incluyendo esta cabecera.
} CS_MESSAGE_PAYLOAD_HEADER, * PCS_MESSAGE_PAYLOAD_HEADER;


/**
 * @brief Payload para notificación de operación de archivo (Kernel -> Usuario).
 * El documento técnico la llama FILTER_MESSAGE y la ubica en CryptoShield.h,
 * pero es más un tipo de payload de Shared.h.
 */
typedef struct _CS_FILE_OPERATION_PAYLOAD {
    CS_MESSAGE_PAYLOAD_HEADER Header; // MessageType será MSG_TYPE_FILE_OPERATION

    // Datos específicos de la operación de archivo
    ULONG ProcessId;
    ULONG ThreadId;
    LARGE_INTEGER Timestamp;        // Momento de la operación
    ULONG OperationType;            // Uno de los FILE_OP_TYPE_*
    ULONG FileAttributes;           // Atributos del archivo (opcional, si se obtiene)
    LARGE_INTEGER FileSize;         // Tamaño del archivo (opcional, si se obtiene)
    USHORT FilePathLength;          // Longitud de FilePath en *caracteres* (sin incluir el NUL)
    WCHAR FilePath[MAX_FILE_PATH_CHARS]; // Path del archivo (terminado en NUL)
    // Aquí se podrían añadir más campos si son necesarios y se obtienen en el pre/post op.
} CS_FILE_OPERATION_PAYLOAD, * PCS_FILE_OPERATION_PAYLOAD;


/**
 * @brief Payload para la solicitud de estado (Usuario -> Kernel).
 * El cuerpo de este mensaje puede estar vacío si solo se necesita el MessageType.
 */
typedef struct _CS_STATUS_REQUEST_PAYLOAD {
    CS_MESSAGE_PAYLOAD_HEADER Header; // MessageType será MSG_TYPE_STATUS_REQUEST
    // Sin cuerpo adicional por ahora, la solicitud es implícita por el tipo.
} CS_STATUS_REQUEST_PAYLOAD, * PCS_STATUS_REQUEST_PAYLOAD;

/**
 * @brief Payload para la respuesta de estado (Kernel -> Usuario).
 * Similar a _CRYPTOSHIELD_STATUS del código original.
 */
typedef struct _CS_STATUS_REPLY_PAYLOAD {
    CS_MESSAGE_PAYLOAD_HEADER Header; // MessageType podría ser MSG_TYPE_STATUS_REQUEST o un nuevo MSG_TYPE_STATUS_REPLY

    // Datos de la respuesta de estado
    ULONG DriverVersionMajor;
    ULONG DriverVersionMinor;
    ULONG DriverVersionBuild;
    ULONG CurrentConfigFlags;       // CONFIG_FLAG_* actuales
    ULONG CurrentDetectionSensitivity;

    // Estadísticas
    ULONGLONG TotalOperationsMonitored;
    ULONGLONG OperationsBlocked;
    ULONGLONG ThreatsDetected;
    ULONGLONG FilesQuarantined;
    ULONGLONG KernelMessagesSent;     // Mensajes enviados por el kernel
    ULONGLONG KernelMessagesReceived; // Mensajes recibidos por el kernel

    // Información del sistema (ejemplos)
    ULONG MonitoredProcessesCount;
    ULONG DriverMemoryUsageKB;
    LARGE_INTEGER DriverLoadTime;
} CS_STATUS_REPLY_PAYLOAD, * PCS_STATUS_REPLY_PAYLOAD;


/**
 * @brief Payload para la actualización de configuración (Usuario -> Kernel).
 * Similar a _CRYPTOSHIELD_CONFIG_UPDATE del código original.
 */
typedef struct _CS_CONFIG_UPDATE_PAYLOAD {
    CS_MESSAGE_PAYLOAD_HEADER Header; // MessageType será MSG_TYPE_CONFIG_UPDATE

    // Datos de configuración a actualizar
    ULONG NewConfigFlags;           // Nuevos CONFIG_FLAG_* a aplicar
    ULONG NewDetectionSensitivity;  // Nueva sensibilidad (0-100)
    ULONG NewResponseActions;       // Nuevas ACTION_* a aplicar (para amenazas detectadas)
    // ULONG Reserved[4]; // Mantenido del original si se prevé uso futuro
} CS_CONFIG_UPDATE_PAYLOAD, * PCS_CONFIG_UPDATE_PAYLOAD;

/**
 * @brief Payload para la respuesta a una actualización de configuración (Kernel -> Usuario).
 * (Opcional, si el usuario espera una confirmación detallada).
 */
typedef struct _CS_CONFIG_UPDATE_REPLY_PAYLOAD {
    CS_MESSAGE_PAYLOAD_HEADER Header; // MessageType podría ser MSG_TYPE_CONFIG_UPDATE o un nuevo MSG_TYPE_CONFIG_REPLY
    NTSTATUS UpdateStatus;          // Estado de la operación de actualización
} CS_CONFIG_UPDATE_REPLY_PAYLOAD, * PCS_CONFIG_UPDATE_REPLY_PAYLOAD;


/**
 * @brief Payload para una alerta genérica (Kernel -> Usuario).
 * Similar a _CRYPTOSHIELD_ALERT del código original.
 */
typedef struct _CS_ALERT_PAYLOAD {
    CS_MESSAGE_PAYLOAD_HEADER Header; // MessageType será MSG_TYPE_ALERT

    ULONG Severity;                 // ALERT_SEVERITY_*
    ULONG AlertSpecificCode;        // Un código definido por la aplicación para este tipo de alerta
    ULONG ProcessId;                // PID relacionado, si aplica (0 si no)
    LARGE_INTEGER Timestamp;        // Momento de la alerta

    USHORT DescriptionLength;       // Longitud de Description en *caracteres* (sin NUL)
    USHORT FilePathLength;          // Longitud de FilePath en *caracteres* (sin NUL), 0 si no aplica
    // Los datos variables (Description y FilePath) siguen inmediatamente a esta estructura en el buffer.
    // Ejemplo: WCHAR VariableData[1]; // NO USAR ASÍ DIRECTAMENTE CON ESTA CABECERA FIJA
    // En su lugar, el payload se asigna con tamaño (sizeof(CS_ALERT_PAYLOAD) - sizeof(WCHAR) + total_len_bytes_strings)
    // y se accede con offsets. O bien, se envían por separado o en una estructura más compleja.
    // Para simplificar aquí, asumiremos longitudes máximas o campos fijos si no se quiere variabilidad compleja.
    // O, más comúnmente:
    // WCHAR Data[1]; // Y el PayloadSize en Header indica el tamaño total.
    // El acceso sería: PWCHAR descriptionStart = (PWCHAR)((PUCHAR)this + sizeof(CS_ALERT_PAYLOAD));
    // PWCHAR filePathStart = (PWCHAR)((PUCHAR)descriptionStart + (DescriptionLength + 1) * sizeof(WCHAR));
    // Esta es la forma más flexible pero requiere manejo cuidadoso de buffers.
    // Por ahora, para mantener la estructura más simple como en el original:
    WCHAR Description[256];         // Descripción fija (incluye NUL)
    WCHAR FilePath[MAX_FILE_PATH_CHARS]; // Path fijo (incluye NUL), vacío si no aplica
} CS_ALERT_PAYLOAD, * PCS_ALERT_PAYLOAD;


/**
 * @brief Payload para notificación de amenaza detectada (Kernel -> Usuario).
 * Similar a _CRYPTOSHIELD_THREAT del código original.
 */
typedef struct _CS_THREAT_DETECTED_PAYLOAD {
    CS_MESSAGE_PAYLOAD_HEADER Header; // MessageType será MSG_TYPE_THREAT_DETECTED

    ULONG ThreatId;                 // Identificador único de la amenaza (interno al motor de detección)
    ULONG ThreatType;               // Tipo de amenaza (ej. Ransomware, Malware, PUA)
    ULONG Confidence;               // Confianza de la detección (0-100)
    ULONG ProcessId;                // PID del proceso malicioso
    ULONG RecommendedAction;        // Una o más ACTION_* sugeridas
    LARGE_INTEGER Timestamp;        // Momento de la detección

    USHORT ThreatNameLength;        // Longitud de ThreatName en *caracteres* (sin NUL)
    USHORT FilePathLength;          // Longitud de FilePath en *caracteres* (sin NUL)
    // WCHAR Data[1]; // Misma consideración que para CS_ALERT_PAYLOAD para datos variables
    WCHAR ThreatName[128];          // Nombre de la amenaza (fijo, incluye NUL)
    WCHAR FilePath[MAX_FILE_PATH_CHARS]; // Path del archivo afectado (fijo, incluye NUL)
} CS_THREAT_DETECTED_PAYLOAD, * PCS_THREAT_DETECTED_PAYLOAD;


/**
 * @brief Estructura de respuesta genérica que el kernel podría esperar del servicio de usuario
 * para mensajes enviados con FltSendMessage que requieren una acción de vuelta.
 * El documento técnico no detalla una respuesta del user-mode al kernel.
 * CryptoShield.h original tenía _CRYPTOSHIELD_REPLY que incluía FILTER_REPLY_HEADER.
 * Shared.h original tenía _CRYPTOSHIELD_REPLY que era solo (Status, Action, Reserved).
 * Esta es la parte del *payload* de la respuesta. El FILTER_REPLY_HEADER lo maneja FltMgr.
 */
typedef struct _CS_USER_REPLY_PAYLOAD {
    NTSTATUS Status;                // NTSTATUS code (resultado de la operación en user-mode)
    ULONG ActionTaken;              // ACTION_* flags (qué hizo o qué sugiere que haga el kernel)
    // ULONG Reserved[2];
} CS_USER_REPLY_PAYLOAD, * PCS_USER_REPLY_PAYLOAD;


#pragma pack(pop) // Restaura el empaquetado por defecto

// Helper para calcular el tamaño total de un payload que tiene datos variables al final
// Ejemplo de uso: totalSize = CS_CALCULATE_PAYLOAD_SIZE_WITH_VARIABLE_DATA(CS_ALERT_PAYLOAD, Description, totalDescBytes + totalFilePathBytes);
// Donde 'Description' es el nombre del campo WCHAR[<max_len>] en la estructura base.
// Este macro es más para payloads con un único campo de datos variables al final del tipo WCHAR Data[1].
// Dadas las estructuras fijas de arriba, no es estrictamente necesario ahora.
/*
#define CS_CALCULATE_PAYLOAD_SIZE_WITH_VARIABLE_DATA(struct_type, last_fixed_field_name, variable_data_bytes) \
    (FIELD_OFFSET(struct_type, last_fixed_field_name) + sizeof(((struct_type*)0)->last_fixed_field_name) + (variable_data_bytes))
*/
// Ejemplo más simple si WCHAR Data[1] es el último campo y representa el inicio de los datos variables:
// #define CS_PAYLOAD_SIZE_VAR(base_struct_size, var_data_len_bytes) \
//    ((base_struct_size) - sizeof(WCHAR) + (var_data_len_bytes))


// Common macros (del código original Shared.h)
#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifdef _KERNEL_MODE
    // En kernel, wcsnlen_s no está disponible directamente. Se puede usar RtlUpcaseUnicodeString etc.
    // o bucles manuales seguros. Por ahora, esta macro se usará principalmente en user-mode.
    // Podríamos tener una versión kernel si es necesario.
#else
#ifndef SAFE_STRING_LENGTH_CHARS // Longitud en caracteres, sin incluir NUL
#define SAFE_STRING_LENGTH_CHARS(s, max_chars) \
            ((s) ? wcsnlen_s((s), (max_chars)) : 0)
#endif
#endif


// Version check macro (del código original Shared.h)
#define CRYPTOSHIELD_VERSION_COMPATIBLE(major, minor) \
    ((major) == CRYPTOSHIELD_VERSION_MAJOR && \
     (minor) <= CRYPTOSHIELD_VERSION_MINOR)

#endif // _CRYPTOSHIELD_SHARED_H_