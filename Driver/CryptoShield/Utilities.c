/**
 * @file Utilities.c
 * @brief Utility functions for CryptoShield driver
 * @details Common helper functions for string manipulation, memory, and time.
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "CryptoShield.h" // Incluye Shared.h y ntstrsafe.h

 // Nota: FltFindUnicodeSubstring se ha trasladado a CryptoShield.h para su prototipo
 // y su implementación puede permanecer aquí o moverse a otro archivo si es muy genérica.
 // La implementación de FltFindUnicodeSubstring del código original es razonable.

 // ----- Implementación de FltFindUnicodeSubstring (si se mantiene aquí) -----
 // (La implementación de FltFindUnicodeSubstring del código original se puede mantener aquí)
 // Ejemplo:
BOOLEAN FltFindUnicodeSubstring_Implemented( // Renombrar si el prototipo está en otro sitio y se quiere mantener aquí
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR SubStringText, // Renombrado para claridad
    _In_ BOOLEAN CaseInsensitive
)
{
    UNICODE_STRING subStringUnicode;
    //PWCHAR findLocation;

    PAGED_CODE(); // Las operaciones de cadenas suelen ser paginables.

    if (String == NULL || String->Buffer == NULL || SubStringText == NULL) {
        return FALSE;
    }
    if (String->Length == 0) { // No se puede encontrar nada en una cadena vacía
        return (*SubStringText == L'\0'); // A menos que la subcadena también esté vacía
    }
    if (*SubStringText == L'\0') { // Subcadena vacía se considera encontrada (o no, según definición)
        return TRUE;
    }

    RtlInitUnicodeString(&subStringUnicode, SubStringText);
    if (subStringUnicode.Length == 0) return TRUE; // Consistente con lo anterior
    if (subStringUnicode.Length > String->Length) return FALSE;


    // RtlFindUnicodeSubstring es una función de WDK que hace esto.
    // Necesita ser llamada en PASSIVE_LEVEL.
    // BOOLEAN RtlFindUnicodeSubstring(     // Esta no existe, es de user mode o Ntdll
    //    IN PUNICODE_STRING FullString,
    //    IN PUNICODE_STRING SearchString,
    //    IN BOOLEAN CaseInsensitive );
    // La implementación manual es necesaria o usar FsRtlIsNameInExpression.

    // Implementación manual (similar a la original):
    ULONG i = 0;
    UNICODE_STRING tempSubString;
    USHORT mainLenChars = String->Length / sizeof(WCHAR);
    USHORT subLenChars = subStringUnicode.Length / sizeof(WCHAR);

    if (subLenChars == 0) return TRUE; // Ya cubierto
    if (mainLenChars < subLenChars) return FALSE; // Ya cubierto

    //for (i = 0; i <= mainLenChars - subLenChars; i++) {
    for (i = 0; i <= (ULONG)(mainLenChars - subLenChars); i++) {
        tempSubString.Buffer = &String->Buffer[i];
        tempSubString.Length = subStringUnicode.Length; // En bytes
        tempSubString.MaximumLength = subStringUnicode.Length;

        if (RtlCompareUnicodeString(&tempSubString, &subStringUnicode, CaseInsensitive) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}


/**
 * @brief Checks if the given filesystem type is supported for monitoring.
 */
BOOLEAN IsFileSystemSupported(
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    PAGED_CODE();
    // Lista de sistemas de archivos soportados
    switch (VolumeFilesystemType) {
    case FLT_FSTYPE_NTFS:
    case FLT_FSTYPE_REFS:
        // case FLT_FSTYPE_FAT: // FAT/EXFAT si se quieren soportar
        // case FLT_FSTYPE_EXFAT:
        return TRUE;
    default:
        return FALSE;
    }
}

/**
 * @brief Checks if a file (based on its name information) should be monitored.
 * Implementa lógica de filtrado para reducir el ruido (archivos de sistema, etc.).
 */
BOOLEAN ShouldMonitorFileByPath(
    _In_ PFLT_FILE_NAME_INFORMATION FileNameInfo
)
{
    PAGED_CODE();

    if (FileNameInfo == NULL || FileNameInfo->Name.Length == 0) {
        return TRUE; // Si no hay nombre, por defecto se monitoriza (o FALSE, según política)
    }

    // Ejemplo de exclusiones (usando FltFindUnicodeSubstring_Implemented o similar)
    // Hay que tener cuidado con la normalización del path (ej. \SystemRoot\ vs C:\Windows\)
    // FileNameInfo->Name es el path completo normalizado.

    // Omitir archivos en directorios del sistema comunes
    // (Esta lógica es simplista y puede necesitar refinamiento)
    if (FltFindUnicodeSubstring_Implemented(&FileNameInfo->Name, L"\\Windows\\System32\\", TRUE)) {
        // Podría haber excepciones, ej. si algo en System32 escribe en Documentos.
        // El chequeo es sobre el path del *archivo accedido*.
        // Si es un archivo DENTRO de System32, probablemente no interese.
        // CS_LOG_TRACE("Skipping monitoring for path in System32: %wZ", &FileNameInfo->Name);
        // return FALSE;
    }
    if (FltFindUnicodeSubstring_Implemented(&FileNameInfo->Name, L"\\System Volume Information\\", TRUE)) {
        // CS_LOG_TRACE("Skipping monitoring for path in System Volume Information: %wZ", &FileNameInfo->Name);
        return FALSE;
    }
    if (FltFindUnicodeSubstring_Implemented(&FileNameInfo->Name, L"pagefile.sys", TRUE)) {
        // CS_LOG_TRACE("Skipping monitoring for pagefile.sys: %wZ", &FileNameInfo->Name);
        return FALSE;
    }
    // Añadir más exclusiones según sea necesario (ej. archivos de log del propio CryptoShield).

    return TRUE; // Por defecto, monitorizar si no cae en una exclusión.
}

// Otras funciones de utilidad del código original (GetFileExtension, IsSystemProcess, etc.)
// pueden permanecer aquí si son necesarias, ajustando su uso de memoria y cadenas.
// Por ejemplo, DuplicateUnicodeString y FreeUnicodeString se pueden mantener si se necesitan
// copias de UNICODE_STRING con gestión de memoria específica.

// La función FormatSystemTime del código original es útil para logging.
// Su implementación usando RtlStringCchPrintfW es correcta.

// La función HashUnicodeString del código original es un hash simple y puede ser útil.

// SafeCopyMemory es un wrapper, pero RtlCopyMemory con SEH es la forma estándar.
// Si se mantiene, asegurar que los parámetros sean correctos.

// IsUserDirectory puede ser útil para enfocar el monitoreo.
// Su implementación con FltFindUnicodeSubstring_Implemented es correcta.

// ValidateProcessAccess puede ser útil para comprobaciones de seguridad,
// aunque su uso exacto depende del contexto. La corrección para usar PsIsProcessTerminating
// y la desreferenciación de PEPROCESS son importantes.