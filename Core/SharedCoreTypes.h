#pragma once

#include <windows.h>
#include <string>

namespace CryptoShield {

    // Definimos el enum y la estructura aquí para que sean un punto único de verdad.
    enum class FileOperationType : ULONG {
        Create = 1,
        Write = 2,
        Delete = 3,
        Rename = 4,
        SetInformation = 5
    };

    struct FileOperationInfo {
        FileOperationType type;
        ULONG process_id;
        ULONG thread_id;
        std::wstring file_path;
        std::wstring new_file_path; // Para operaciones de renombrado
        FILETIME timestamp;

        // Declaramos los métodos aquí
        std::wstring GetOperationTypeString() const;
        std::wstring GetFormattedTimestamp() const;
    };

} // namespace CryptoShield