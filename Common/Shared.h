/**
 * @file Shared.h
 * @brief Shared definitions between kernel driver and user service
 * @details Common structures and constants used by both components
 * 
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

// Ensure we can compile in both kernel and user mode
#ifdef _KERNEL_MODE
    #include <ntddk.h>
    #define SHARED_API
#else
    #include <windows.h>
    #define SHARED_API __declspec(dllexport)
#endif

// Version information
#define CRYPTOSHIELD_VERSION_MAJOR  1
#define CRYPTOSHIELD_VERSION_MINOR  0
#define CRYPTOSHIELD_VERSION_BUILD  0
#define CRYPTOSHIELD_VERSION_STRING L"1.0.0"

// Communication port name
#define CRYPTOSHIELD_PORT_NAME      L"\\CryptoShieldPort"

// Message types for kernel-user communication
#define MSG_FILE_OPERATION          1
#define MSG_STATUS_REQUEST          2
#define MSG_CONFIG_UPDATE           3
#define MSG_SHUTDOWN_REQUEST        4
#define MSG_ALERT                   5
#define MSG_THREAT_DETECTED         6

// File operation types
#define FILE_OP_CREATE              1
#define FILE_OP_WRITE               2
#define FILE_OP_DELETE              3
#define FILE_OP_RENAME              4
#define FILE_OP_SET_INFORMATION     5
#define FILE_OP_CLEANUP             6

// Alert severity levels
#define ALERT_SEVERITY_LOW          1
#define ALERT_SEVERITY_MEDIUM       2
#define ALERT_SEVERITY_HIGH         3
#define ALERT_SEVERITY_CRITICAL     4

// Detection sensitivity ranges
#define MIN_DETECTION_SENSITIVITY   0
#define MAX_DETECTION_SENSITIVITY   100
#define DEFAULT_DETECTION_SENSITIVITY 50

// Maximum path length (Unicode)
#define MAX_FILE_PATH_LENGTH        520  // MAX_PATH * 2

// Process classification
#define PROCESS_TYPE_UNKNOWN        0
#define PROCESS_TYPE_TRUSTED        1
#define PROCESS_TYPE_SUSPICIOUS     2
#define PROCESS_TYPE_MALICIOUS      3

// Response actions
#define ACTION_ALLOW                0x00000001
#define ACTION_BLOCK                0x00000002
#define ACTION_QUARANTINE           0x00000004
#define ACTION_TERMINATE_PROCESS    0x00000008
#define ACTION_ALERT_USER           0x00000010
#define ACTION_LOG_ONLY             0x00000020

// Error codes specific to CryptoShield
#define CRYPTOSHIELD_ERROR_BASE                 0xE0000000
#define CRYPTOSHIELD_ERROR_DRIVER_NOT_LOADED    (CRYPTOSHIELD_ERROR_BASE + 1)
#define CRYPTOSHIELD_ERROR_PORT_COMMUNICATION   (CRYPTOSHIELD_ERROR_BASE + 2)
#define CRYPTOSHIELD_ERROR_INVALID_MESSAGE      (CRYPTOSHIELD_ERROR_BASE + 3)
#define CRYPTOSHIELD_ERROR_QUEUE_FULL           (CRYPTOSHIELD_ERROR_BASE + 4)
#define CRYPTOSHIELD_ERROR_ANALYSIS_FAILED      (CRYPTOSHIELD_ERROR_BASE + 5)

// Configuration flags
#define CONFIG_FLAG_MONITORING_ENABLED      0x00000001
#define CONFIG_FLAG_REALTIME_PROTECTION     0x00000002
#define CONFIG_FLAG_BEHAVIORAL_ANALYSIS     0x00000004
#define CONFIG_FLAG_MACHINE_LEARNING        0x00000008
#define CONFIG_FLAG_CLOUD_LOOKUP            0x00000010
#define CONFIG_FLAG_AUTO_QUARANTINE         0x00000020
#define CONFIG_FLAG_SILENT_MODE             0x00000040

// Statistics IDs
#define STAT_TOTAL_OPERATIONS               1
#define STAT_BLOCKED_OPERATIONS             2
#define STAT_DETECTED_THREATS               3
#define STAT_FALSE_POSITIVES                4
#define STAT_QUARANTINED_FILES              5

#pragma pack(push, 1)

/**
 * @brief Basic message header
 * @note Must be compatible with FILTER_MESSAGE_HEADER
 */
typedef struct _CRYPTOSHIELD_MESSAGE_HEADER {
    ULONG MessageSize;          // Total size of message including header
    ULONGLONG MessageId;        // Unique message identifier
} CRYPTOSHIELD_MESSAGE_HEADER, *PCRYPTOSHIELD_MESSAGE_HEADER;

/**
 * @brief File operation message
 */
typedef struct _CRYPTOSHIELD_FILE_OPERATION {
    CRYPTOSHIELD_MESSAGE_HEADER Header;
    ULONG MessageType;          // MSG_FILE_OPERATION
    ULONG ProcessId;            // Process performing operation
    ULONG ThreadId;             // Thread performing operation
    LARGE_INTEGER Timestamp;    // Operation timestamp
    ULONG OperationType;        // FILE_OP_*
    ULONG FileAttributes;       // File attributes
    LARGE_INTEGER FileSize;     // File size
    USHORT FilePathLength;      // Length of file path in bytes
    WCHAR FilePath[MAX_FILE_PATH_LENGTH];  // File path
} CRYPTOSHIELD_FILE_OPERATION, *PCRYPTOSHIELD_FILE_OPERATION;

/**
 * @brief Configuration update message
 */
typedef struct _CRYPTOSHIELD_CONFIG_UPDATE {
    CRYPTOSHIELD_MESSAGE_HEADER Header;
    ULONG MessageType;          // MSG_CONFIG_UPDATE
    ULONG ConfigFlags;          // CONFIG_FLAG_*
    ULONG DetectionSensitivity; // 0-100
    ULONG ResponseActions;      // ACTION_* flags
    ULONG Reserved[4];          // Future use
} CRYPTOSHIELD_CONFIG_UPDATE, *PCRYPTOSHIELD_CONFIG_UPDATE;

/**
 * @brief Status request/reply message
 */
typedef struct _CRYPTOSHIELD_STATUS {
    CRYPTOSHIELD_MESSAGE_HEADER Header;
    ULONG MessageType;          // MSG_STATUS_REQUEST
    
    // Reply data (filled by driver)
    ULONG DriverVersion;        // Driver version
    ULONG ConfigFlags;          // Current configuration
    ULONG DetectionSensitivity; // Current sensitivity
    
    // Statistics
    ULONGLONG TotalOperations;  // Total file operations
    ULONGLONG BlockedOperations;// Operations blocked
    ULONGLONG DetectedThreats;  // Threats detected
    ULONGLONG QuarantinedFiles; // Files quarantined
    
    // System info
    ULONG ActiveProcesses;      // Processes being monitored
    ULONG MemoryUsage;          // Memory usage in KB
    LARGE_INTEGER DriverLoadTime; // When driver was loaded
} CRYPTOSHIELD_STATUS, *PCRYPTOSHIELD_STATUS;

/**
 * @brief Alert message
 */
typedef struct _CRYPTOSHIELD_ALERT {
    CRYPTOSHIELD_MESSAGE_HEADER Header;
    ULONG MessageType;          // MSG_ALERT
    ULONG Severity;             // ALERT_SEVERITY_*
    ULONG ProcessId;            // Related process
    LARGE_INTEGER Timestamp;    // Alert time
    USHORT DescriptionLength;   // Length of description
    USHORT FilePathLength;      // Length of file path
    WCHAR Data[1];              // Variable data: Description + FilePath
} CRYPTOSHIELD_ALERT, *PCRYPTOSHIELD_ALERT;

/**
 * @brief Threat detection message
 */
typedef struct _CRYPTOSHIELD_THREAT {
    CRYPTOSHIELD_MESSAGE_HEADER Header;
    ULONG MessageType;          // MSG_THREAT_DETECTED
    ULONG ThreatId;             // Unique threat identifier
    ULONG ThreatType;           // Type of threat
    ULONG Confidence;           // Detection confidence (0-100)
    ULONG ProcessId;            // Malicious process
    ULONG RecommendedAction;    // ACTION_* flags
    LARGE_INTEGER Timestamp;    // Detection time
    USHORT ThreatNameLength;    // Length of threat name
    USHORT FilePathLength;      // Length of file path
    WCHAR Data[1];              // Variable data: ThreatName + FilePath
} CRYPTOSHIELD_THREAT, *PCRYPTOSHIELD_THREAT;

/**
 * @brief Generic reply structure
 */
typedef struct _CRYPTOSHIELD_REPLY {
    ULONG Status;               // NTSTATUS code
    ULONG Action;               // ACTION_* flags
    ULONG Reserved[2];          // Future use
} CRYPTOSHIELD_REPLY, *PCRYPTOSHIELD_REPLY;

#pragma pack(pop)

/**
 * @brief Helper to calculate message size
 */
#define CRYPTOSHIELD_MESSAGE_SIZE(type, extra) \
    (sizeof(type) + (extra))

/**
 * @brief Helper to get variable data pointer
 */
#define CRYPTOSHIELD_GET_VARIABLE_DATA(msg) \
    ((PWCHAR)((PUCHAR)(msg) + sizeof(*(msg))))

// Performance thresholds
#define PERF_MAX_LATENCY_MS         100     // Maximum acceptable latency
#define PERF_MAX_CPU_PERCENT        5       // Maximum CPU usage
#define PERF_MAX_MEMORY_MB          100     // Maximum memory usage

// Logging levels (shared between kernel and user)
#define LOG_LEVEL_ERROR             1
#define LOG_LEVEL_WARNING           2
#define LOG_LEVEL_INFO              3
#define LOG_LEVEL_DEBUG             4
#define LOG_LEVEL_TRACE             5

// Common macros
#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef SAFE_STRING_LENGTH
#define SAFE_STRING_LENGTH(s, max) \
    ((s) ? wcsnlen_s((s), (max)) : 0)
#endif

// Version check macro
#define CRYPTOSHIELD_VERSION_COMPATIBLE(major, minor) \
    ((major) == CRYPTOSHIELD_VERSION_MAJOR && \
     (minor) <= CRYPTOSHIELD_VERSION_MINOR)

#endif // _CRYPTOSHIELD_SHARED_H_