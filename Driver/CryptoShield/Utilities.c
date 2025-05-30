/**
 * @file Utilities.c
 * @brief Utility functions for CryptoShield driver
 * @details Common helper functions for string manipulation, memory, and time
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "CryptoShield.h"

 /**
  * @brief Finds a substring in a Unicode string (case-insensitive)
  * @details Helper function for pattern matching in file paths
  *
  * @param String String to search in
  * @param SubString String to search for
  * @param CaseInsensitive TRUE for case-insensitive search
  * @return TRUE if substring found, FALSE otherwise
  */
BOOLEAN FltFindUnicodeSubstring(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR SubString,
    _In_ BOOLEAN CaseInsensitive
)
{
    UNICODE_STRING subStr = { 0 };
    UNICODE_STRING tempStr = { 0 };
    ULONG i = 0;
    USHORT subLen = 0;

    // Validate parameters
    if (String == NULL || SubString == NULL || String->Buffer == NULL) {
        return FALSE;
    }

    // Initialize substring
    RtlInitUnicodeString(&subStr, SubString);
    subLen = subStr.Length / sizeof(WCHAR);

    // Check if substring is longer than main string
    if (subStr.Length > String->Length) {
        return FALSE;
    }

    // Search for substring
    for (i = 0; i <= (String->Length - subStr.Length) / sizeof(WCHAR); i++) {
        tempStr.Buffer = &String->Buffer[i];
        tempStr.Length = subStr.Length;
        tempStr.MaximumLength = subStr.Length;

        if (RtlCompareUnicodeString(&tempStr, &subStr, CaseInsensitive) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Gets file extension from file name
 * @details Extracts extension for file type analysis
 *
 * @param FileName File name to analyze
 * @param Extension Buffer to receive extension
 * @param ExtensionSize Size of extension buffer in bytes
 * @return STATUS_SUCCESS on success
 */
NTSTATUS GetFileExtension(
    _In_ PCUNICODE_STRING FileName,
    _Out_writes_bytes_(ExtensionSize) PWCHAR Extension,
    _In_ ULONG ExtensionSize
)
{
    USHORT i = 0;
    USHORT lastDot = 0;
    USHORT length = 0;

    // Validate parameters
    if (FileName == NULL || Extension == NULL || ExtensionSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize output
    RtlZeroMemory(Extension, ExtensionSize);

    // Find last dot in file name
    for (i = 0; i < FileName->Length / sizeof(WCHAR); i++) {
        if (FileName->Buffer[i] == L'.') {
            lastDot = i;
        }
    }

    // Check if extension found
    if (lastDot == 0 || lastDot == (FileName->Length / sizeof(WCHAR) - 1)) {
        return STATUS_NOT_FOUND;
    }

    // Calculate extension length
    length = (FileName->Length / sizeof(WCHAR)) - lastDot - 1;
    if (length * sizeof(WCHAR) >= ExtensionSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Copy extension
    RtlCopyMemory(Extension,
        &FileName->Buffer[lastDot + 1],
        length * sizeof(WCHAR));

    return STATUS_SUCCESS;
}

/**
 * @brief Checks if process is system process
 * @details Identifies system processes to avoid monitoring
 *
 * @param ProcessId Process ID to check
 * @return TRUE if system process, FALSE otherwise
 */
BOOLEAN IsSystemProcess(
    _In_ ULONG ProcessId
)
{
    // System process PIDs
    if (ProcessId == 0 || ProcessId == 4) {
        return TRUE;
    }

    // Check for other known system processes
    // This is a simplified check - production would be more comprehensive
    if (ProcessId < 100) {
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief Allocates and copies a Unicode string
 * @details Helper for string duplication with proper memory management
 *
 * @param Destination Destination string structure
 * @param Source Source string to copy
 * @param PoolType Type of pool to allocate from
 * @return STATUS_SUCCESS on success
 */
NTSTATUS DuplicateUnicodeString(
    _Out_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source,
    _In_ POOL_TYPE PoolType
)
{
    // Validate parameters
    if (Destination == NULL || Source == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize destination
    Destination->Length = 0;
    Destination->MaximumLength = 0;
    Destination->Buffer = NULL;

    // Check for empty source
    if (Source->Length == 0) {
        return STATUS_SUCCESS;
    }

    // Allocate buffer
    Destination->MaximumLength = Source->Length + sizeof(WCHAR);
    Destination->Buffer = (PWCHAR)ExAllocatePoolWithTag(PoolType,
        Destination->MaximumLength,
        CRYPTOSHIELD_POOL_TAG);

    if (Destination->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Copy string
    RtlCopyUnicodeString(Destination, Source);

    // Ensure null termination
    Destination->Buffer[Destination->Length / sizeof(WCHAR)] = L'\0';

    return STATUS_SUCCESS;
}

/**
 * @brief Frees a duplicated Unicode string
 * @details Cleanup function for DuplicateUnicodeString
 *
 * @param String String to free
 */
VOID FreeUnicodeString(
    _Inout_ PUNICODE_STRING String
)
{
    if (String != NULL && String->Buffer != NULL) {
        ExFreePoolWithTag(String->Buffer, CRYPTOSHIELD_POOL_TAG);
        String->Buffer = NULL;
        String->Length = 0;
        String->MaximumLength = 0;
    }
}

/**
 * @brief Gets current system time in readable format
 * @details Converts system time to local time for logging
 *
 * @param SystemTime System time to convert
 * @param TimeString Buffer to receive formatted time
 * @param TimeStringSize Size of buffer in characters
 * @return STATUS_SUCCESS on success
 */
NTSTATUS FormatSystemTime(
    _In_ PLARGE_INTEGER SystemTime,
    _Out_writes_(TimeStringSize) PWCHAR TimeString,
    _In_ ULONG TimeStringSize
)
{
    TIME_FIELDS timeFields = { 0 };
    LARGE_INTEGER localTime = { 0 };

    // Validate parameters
    if (SystemTime == NULL || TimeString == NULL || TimeStringSize < 20) {
        return STATUS_INVALID_PARAMETER;
    }

    // Convert to local time
    ExSystemTimeToLocalTime(SystemTime, &localTime);

    // Convert to time fields
    RtlTimeToTimeFields(&localTime, &timeFields);

    // Format as string
    swprintf_s(TimeString, TimeStringSize,
        L"%04d-%02d-%02d %02d:%02d:%02d",
        timeFields.Year,
        timeFields.Month,
        timeFields.Day,
        timeFields.Hour,
        timeFields.Minute,
        timeFields.Second);

    return STATUS_SUCCESS;
}

/**
 * @brief Calculates simple hash of a string
 * @details Used for quick comparisons and caching
 *
 * @param String String to hash
 * @return 32-bit hash value
 */
ULONG HashUnicodeString(
    _In_ PCUNICODE_STRING String
)
{
    ULONG hash = 5381;
    USHORT i = 0;

    if (String == NULL || String->Buffer == NULL) {
        return 0;
    }

    // DJB2 hash algorithm
    for (i = 0; i < String->Length / sizeof(WCHAR); i++) {
        hash = ((hash << 5) + hash) + (ULONG)String->Buffer[i];
    }

    return hash;
}

/**
 * @brief Safely copies memory with bounds checking
 * @details Wrapper around RtlCopyMemory with additional validation
 *
 * @param Destination Destination buffer
 * @param DestinationSize Size of destination buffer
 * @param Source Source buffer
 * @param SourceSize Size to copy
 * @return STATUS_SUCCESS on success
 */
NTSTATUS SafeCopyMemory(
    _Out_writes_bytes_(DestinationSize) PVOID Destination,
    _In_ SIZE_T DestinationSize,
    _In_reads_bytes_(SourceSize) PVOID Source,
    _In_ SIZE_T SourceSize
)
{
    // Validate parameters
    if (Destination == NULL || Source == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Check buffer sizes
    if (SourceSize > DestinationSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Perform copy
    __try {
        RtlCopyMemory(Destination, Source, SourceSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Checks if file path is in user directory
 * @details Used to focus monitoring on user data
 *
 * @param FilePath Path to check
 * @return TRUE if in user directory, FALSE otherwise
 */
BOOLEAN IsUserDirectory(
    _In_ PCUNICODE_STRING FilePath
)
{
    // Check common user directories
    if (FltFindUnicodeSubstring(FilePath, L"\\Users\\", TRUE) ||
        FltFindUnicodeSubstring(FilePath, L"\\Documents and Settings\\", TRUE)) {
        return TRUE;
    }

    // Check for user profile environment paths
    if (FltFindUnicodeSubstring(FilePath, L"\\Desktop\\", TRUE) ||
        FltFindUnicodeSubstring(FilePath, L"\\Documents\\", TRUE) ||
        FltFindUnicodeSubstring(FilePath, L"\\Downloads\\", TRUE) ||
        FltFindUnicodeSubstring(FilePath, L"\\Pictures\\", TRUE)) {
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief Validates process access rights
 * @details Ensures process has appropriate permissions
 *
 * @param ProcessId Process ID to validate
 * @param DesiredAccess Required access rights
 * @return STATUS_SUCCESS if access allowed
 */
NTSTATUS ValidateProcessAccess(
    _In_ ULONG ProcessId,
    _In_ ACCESS_MASK DesiredAccess
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    HANDLE processHandle = NULL;

    // Get process object
    status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        // Check if process is terminating
        if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
            status = STATUS_PROCESS_IS_TERMINATING;
            __leave;
        }

        // Try to open process with desired access
        status = ObOpenObjectByPointer(process,
            OBJ_KERNEL_HANDLE,
            NULL,
            DesiredAccess,
            *PsProcessType,
            KernelMode,
            &processHandle);

        if (!NT_SUCCESS(status)) {
            __leave;
        }

        // Access is allowed
        status = STATUS_SUCCESS;

    }
    __finally {
        if (processHandle != NULL) {
            ZwClose(processHandle);
        }

        if (process != NULL) {
            ObDereferenceObject(process);
        }
    }

    return status;
}