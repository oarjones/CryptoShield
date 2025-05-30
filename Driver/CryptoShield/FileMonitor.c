/**
 * @file FileMonitor.c
 * @brief File operation monitoring and analysis implementation
 * @details Handles file name resolution and operation message creation
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "CryptoShield.h"

 /**
  * @brief Gets normalized file name information
  * @details Retrieves and normalizes file path for consistent processing
  *
  * @param Data Callback data containing file information
  * @param FileNameBuffer Buffer to receive file name
  * @param FileNameBufferSize Size of the buffer in bytes
  * @param ReturnedLength Actual length of file name
  * @return STATUS_SUCCESS on success, appropriate error code on failure
  */
NTSTATUS GetFileNameInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_writes_bytes_(FileNameBufferSize) PWCHAR FileNameBuffer,
    _In_ ULONG FileNameBufferSize,
    _Out_ PULONG ReturnedLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG bytesToCopy = 0;

    // Validate parameters
    if (!Data || !FileNameBuffer || !ReturnedLength) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize output
    *ReturnedLength = 0;
    RtlZeroMemory(FileNameBuffer, FileNameBufferSize);

    __try {
        // Get normalized name - use FLT_FILE_NAME_NORMALIZED for consistent paths
        status = FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED |
            FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo);

        if (!NT_SUCCESS(status)) {
            CS_WARNING("FltGetFileNameInformation failed: 0x%08x", status);
            __leave;
        }

        // Parse the file name information
        status = FltParseFileNameInformation(nameInfo);
        if (!NT_SUCCESS(status)) {
            CS_WARNING("FltParseFileNameInformation failed: 0x%08x", status);
            __leave;
        }

        // Calculate bytes to copy (including null terminator)
        bytesToCopy = nameInfo->Name.Length + sizeof(WCHAR);
        if (bytesToCopy > FileNameBufferSize) {
            // Truncate if necessary
            bytesToCopy = FileNameBufferSize - sizeof(WCHAR);
            status = STATUS_BUFFER_TOO_SMALL;
        }

        // Copy the file name
        RtlCopyMemory(FileNameBuffer, nameInfo->Name.Buffer, bytesToCopy - sizeof(WCHAR));

        // Ensure null termination
        FileNameBuffer[(bytesToCopy / sizeof(WCHAR)) - 1] = L'\0';

        *ReturnedLength = bytesToCopy;

        CS_TRACE("Retrieved file name: %ws", FileNameBuffer);

    }
    __finally {
        // Cleanup
        if (nameInfo != NULL) {
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    return status;
}

/**
 * @brief Sends file operation message to user mode
 * @details Creates and sends a message containing file operation details
 *
 * @param Data Callback data with operation information
 * @param OperationType Type of file operation
 * @return STATUS_SUCCESS on success, appropriate error code on failure
 */
NTSTATUS SendFileOperationMessage(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG OperationType
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PCRYPTOSHIELD_MESSAGE message = NULL;
    ULONG messageSize = 0;
    LARGE_INTEGER timeout = { 0 };
    ULONG replyLength = 0;
    CRYPTOSHIELD_REPLY reply = { 0 };
    ULONG fileNameLength = 0;
    PEPROCESS process = NULL;
    HANDLE processId = NULL;
    HANDLE threadId = NULL;

    // Check if client is connected
    if (!g_Context.ClientConnected || g_Context.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }

    // Allocate message buffer
    messageSize = sizeof(CRYPTOSHIELD_MESSAGE);
    message = (PCRYPTOSHIELD_MESSAGE)CS_ALLOC_POOL(messageSize);
    if (message == NULL) {
        CS_ERROR("Failed to allocate message buffer");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        // Initialize message
        RtlZeroMemory(message, messageSize);

        // Set message type and operation
        message->MessageType = MSG_FILE_OPERATION;
        message->OperationType = OperationType;

        // Get current time
        KeQuerySystemTime(&message->Timestamp);

        // Get process and thread information
        process = IoThreadToProcess(Data->Thread);
        processId = PsGetProcessId(process);
        threadId = PsGetThreadId(Data->Thread);

        message->ProcessId = HandleToULong(processId);
        message->ThreadId = HandleToULong(threadId);

        // Get file name
        status = GetFileNameInformation(Data,
            message->FilePath,
            sizeof(message->FilePath),
            &fileNameLength);

        if (!NT_SUCCESS(status)) {
            // Continue even if we couldn't get the file name
            CS_WARNING("Failed to get file name: 0x%08x", status);
            wcscpy_s(message->FilePath,
                sizeof(message->FilePath) / sizeof(WCHAR),
                L"<Unknown>");
            fileNameLength = (ULONG)wcslen(message->FilePath) * sizeof(WCHAR);
        }

        message->FilePathLength = (USHORT)fileNameLength;

        // Set timeout for sending message (100ms)
        timeout.QuadPart = -1000000; // 100ms in 100ns units

        // Send message to user mode
        status = FltSendMessage(g_Context.FilterHandle,
            &g_Context.ClientPort,
            message,
            messageSize,
            &reply,
            &replyLength,
            &timeout);

        if (!NT_SUCCESS(status)) {
            if (status == STATUS_TIMEOUT) {
                CS_WARNING("Send message timeout for PID %d", message->ProcessId);
            }
            else if (status == STATUS_PORT_DISCONNECTED) {
                CS_WARNING("Client disconnected");
                // Mark client as disconnected
                InterlockedExchange8((CHAR*)&g_Context.ClientConnected, FALSE);
            }
            else {
                CS_WARNING("Failed to send message: 0x%08x", status);
            }
        }
        else {
            // Update statistics
            InterlockedIncrement(&g_Context.MessagesSent);

            CS_TRACE("Sent message for operation %d, PID %d, File: %ws",
                OperationType, message->ProcessId, message->FilePath);
        }

    }
    __finally {
        // Cleanup
        if (message != NULL) {
            CS_FREE_POOL(message);
        }
    }

    return status;
}

/**
 * @brief Updates driver statistics
 * @details Thread-safe update of various statistics counters
 *
 * @param StatType Type of statistic to update
 */
VOID UpdateStatistics(
    _In_ ULONG StatType
)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_Context.StatisticsLock, &oldIrql);

    switch (StatType) {
    case MSG_FILE_OPERATION:
        g_Context.FileOperationCount++;
        break;
    case MSG_STATUS_REQUEST:
        g_Context.MessagesReceived++;
        break;
    default:
        break;
    }

    KeReleaseSpinLock(&g_Context.StatisticsLock, oldIrql);
}

/**
 * @brief Checks if file should be monitored
 * @details Implements filtering logic to reduce noise
 *
 * @param FileName File name to check
 * @return TRUE if file should be monitored, FALSE otherwise
 */
BOOLEAN ShouldMonitorFile(
    _In_ PCUNICODE_STRING FileName
)
{
    // Skip system files and directories
    if (FileName->Length > 0) {
        // Skip pagefile
        if (FltFindUnicodeSubstring(FileName, L"pagefile.sys", TRUE)) {
            return FALSE;
        }

        // Skip hibernation file
        if (FltFindUnicodeSubstring(FileName, L"hiberfil.sys", TRUE)) {
            return FALSE;
        }

        // Skip Windows directory (basic check)
        if (FltFindUnicodeSubstring(FileName, L"\\Windows\\", TRUE)) {
            // Allow monitoring of user profile within Windows
            if (!FltFindUnicodeSubstring(FileName, L"\\Users\\", TRUE)) {
                return FALSE;
            }
        }

        // Skip temporary internet files
        if (FltFindUnicodeSubstring(FileName, L"\\Temporary Internet Files\\", TRUE)) {
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * @brief Analyzes file operation patterns
 * @details Basic pattern analysis for suspicious behavior
 *
 * @param Data Callback data with operation information
 * @param OperationType Type of operation
 * @return Suspicion level (0-100)
 */
ULONG AnalyzeOperationPattern(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG OperationType
)
{
    ULONG suspicionLevel = 0;

    UNREFERENCED_PARAMETER(Data);

    // Basic heuristics for suspicious patterns
    switch (OperationType) {
    case FILE_OP_WRITE:
        // Multiple writes to same file could indicate encryption
        suspicionLevel = 10;
        break;

    case FILE_OP_DELETE:
        // Mass deletion could be suspicious
        suspicionLevel = 20;
        break;

    case FILE_OP_RENAME:
        // File extension changes could indicate ransomware
        suspicionLevel = 15;
        break;

    default:
        suspicionLevel = 0;
        break;
    }

    // This is a placeholder - real implementation would track patterns over time
    return suspicionLevel;
}