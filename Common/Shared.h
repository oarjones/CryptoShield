#ifndef SHARED_H
#define SHARED_H

//#include <cstring>  // Para C++ (memset, memcpy)

#define WIN32_LEAN_AND_MEAN // <-- Add this line
#include <windows.h>
#include <vector>
#include <string>
#include <chrono>

//
// Versión del proyecto
//
#define CRYPTOSHIELD_VERSION_MAJOR 1
#define CRYPTOSHIELD_VERSION_MINOR 0
#define CRYPTOSHIELD_VERSION_BUILD 0

//
// Constantes compartidas
//
#define CRYPTOSHIELD_SERVICE_NAME L"CryptoShield"
#define CRYPTOSHIELD_DISPLAY_NAME L"CryptoShield Anti-Ransomware"
#define CRYPTOSHIELD_DRIVER_NAME L"CryptoShield.sys"

//
// Tipos de operación (sincronizado con kernel)
//
enum class OperationType {
    FILE_CREATE = 1,
    FILE_WRITE,
    FILE_READ,
    FILE_DELETE,
    FILE_RENAME,
    PROCESS_CREATE,
    PROCESS_FINALIZE,
    REGISTRY_WRITE,
    REGISTRY_DELETE
};

//
// Niveles de amenaza
//
enum class ThreatLevel {
    NONE = 0,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

//
// Estructuras de datos compartidas
//
struct FileOperation {
    std::chrono::steady_clock::time_point timestamp;
    uint32_t process_id;
    uint32_t thread_id;
    OperationType operation_type;
    std::wstring file_path;
    uint64_t file_size;
    double entropy_before;
    double entropy_after;
    bool suspicious;
};

struct ProcessOperation {
    std::chrono::steady_clock::time_point timestamp;
    uint32_t process_id;
    uint32_t parent_process_id;
    std::wstring process_name;
    std::wstring command_line;
    OperationType operation_type;
    bool suspicious;
};

struct DetectionResult {
    double confidence_score;
    ThreatLevel threat_level;
    std::vector<std::string> detected_patterns;
    std::string description;
    uint32_t source_process_id;
    std::string source_file_path;
    std::chrono::steady_clock::time_point timestamp;
    bool is_suspicious;
};

//
// Utilidades
//
std::wstring GetCurrentTimestamp();
std::string WStringToString(const std::wstring& wstr);
std::wstring StringToWString(const std::string& str);

#endif // SHARED_H