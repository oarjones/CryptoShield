/**
 * @file CommunicationManager.cpp
 * @brief Driver communication management implementation
 * @details Handles bidirectional communication with kernel driver
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include <windows.h>
#include <fltUser.h>
#include "Shared.h"   // For CS_MESSAGE_PAYLOAD_HEADER, CS_FILE_OPERATION_PAYLOAD, etc.
#include "CommunicationManager.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
//#include <ntstatus.h>


namespace CryptoShield {

    /**
     * @brief Constructor
     */
    CommunicationManager::CommunicationManager()
        : filter_port_(INVALID_HANDLE_VALUE)
        , completion_port_(INVALID_HANDLE_VALUE)
        , running_(false)
        , connected_(false)
        , statistics_{ 0, 0, 0, 0 }
    {
    }

    /**
     * @brief Destructor
     */
    CommunicationManager::~CommunicationManager()
    {
        Shutdown();
    }

    /**
     * @brief Initialize and connect to driver
     */
    bool CommunicationManager::Initialize(const std::wstring& port_name)
    {
        if (connected_.load()) {
            LogError("Initialize", ERROR_ALREADY_INITIALIZED);
            return false;
        }

        port_name_ = port_name;

        // Create completion port for async operations
        completion_port_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, MAX_THREAD_COUNT);
        if (completion_port_ == INVALID_HANDLE_VALUE) {
            LogError("CreateIoCompletionPort", GetLastError());
            return false;
        }

        // Connect to filter port
        HRESULT hr = FilterConnectCommunicationPort(
            port_name_.c_str(),
            0,                          // Options
            nullptr,                    // Context
            0,                          // Context size
            nullptr,                    // Security attributes
            &filter_port_
        );

        if (FAILED(hr)) {
            LogError("FilterConnectCommunicationPort", hr);
            CloseHandle(completion_port_);
            completion_port_ = INVALID_HANDLE_VALUE;
            return false;
        }

        // Associate filter port with completion port
        if (CreateIoCompletionPort(filter_port_, completion_port_, 0, 0) == nullptr) {
            LogError("CreateIoCompletionPort for filter port", GetLastError());
            CloseHandle(filter_port_);
            CloseHandle(completion_port_);
            filter_port_ = INVALID_HANDLE_VALUE;
            completion_port_ = INVALID_HANDLE_VALUE;
            return false;
        }

        // Start message processing thread
        running_ = true;
        message_thread_ = std::thread(&CommunicationManager::MessageThreadProc, this);

        connected_ = true;

        // Notify connection callback
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            if (connection_callback_) {
                connection_callback_(true);
            }
        }

        std::wcout << L"[CommunicationManager] Connected to driver successfully" << std::endl;
        return true;
    }

    /**
     * @brief Shutdown and disconnect
     */
    void CommunicationManager::Shutdown()
    {
        if (!connected_.load()) {
            return;
        }

        std::wcout << L"[CommunicationManager] Shutting down..." << std::endl;

        // Stop message thread
        running_ = false;

        // Post completion status to wake up thread
        if (completion_port_ != INVALID_HANDLE_VALUE) {
            PostQueuedCompletionStatus(completion_port_, 0, 0, nullptr);
        }

        // Wait for thread to finish
        if (message_thread_.joinable()) {
            message_thread_.join();
        }

        // Close handles
        if (filter_port_ != INVALID_HANDLE_VALUE) {
            CloseHandle(filter_port_);
            filter_port_ = INVALID_HANDLE_VALUE;
        }

        if (completion_port_ != INVALID_HANDLE_VALUE) {
            CloseHandle(completion_port_);
            completion_port_ = INVALID_HANDLE_VALUE;
        }

        connected_ = false;

        // Notify disconnection callback
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            if (connection_callback_) {
                connection_callback_(false);
            }
        }

        std::wcout << L"[CommunicationManager] Shutdown complete" << std::endl;
    }

    /**
     * @brief Update driver configuration
     * @param new_config_flags New configuration flags (CONFIG_FLAG_*)
     * @param new_detection_sensitivity New detection sensitivity (0-100)
     * @param new_response_actions New response actions (ACTION_*)
     * @return true on success
     */
    bool CommunicationManager::UpdateConfiguration(ULONG new_config_flags, ULONG new_detection_sensitivity, ULONG new_response_actions)
    {
        if (!connected_.load()) {
            LogError("UpdateConfiguration", ERROR_NOT_CONNECTED);
            return false;
        }

        // Validate parameters
        if (new_detection_sensitivity > MAX_DETECTION_SENSITIVITY) { // MAX_DETECTION_SENSITIVITY is 100 from Shared.h
            LogError("UpdateConfiguration", ERROR_INVALID_PARAMETER);
            std::wcerr << L"[CommunicationManager] Invalid detection sensitivity: " << new_detection_sensitivity << std::endl;
            return false;
        }

        CS_CONFIG_UPDATE_PAYLOAD payload = {};
        payload.Header.MessageType = MSG_TYPE_CONFIG_UPDATE;
        payload.Header.MessageId = 0; // Can be incremented or made unique if needed for specific tracking
        payload.Header.PayloadSize = sizeof(CS_CONFIG_UPDATE_PAYLOAD);

        payload.NewConfigFlags = new_config_flags;
        payload.NewDetectionSensitivity = new_detection_sensitivity;
        payload.NewResponseActions = new_response_actions;

        // SendMessage expects const void* for the message, its size,
        // optional reply buffer, reply size, LPDWORD out_bytes_returned, and timeout.
        // For config updates, we typically don't expect a direct reply payload here, so out_bytes_returned is nullptr.
        bool result = SendMessage(
            &payload,
            sizeof(CS_CONFIG_UPDATE_PAYLOAD), // Explicit size of the payload struct
            nullptr,                          // No reply buffer
            0,                                // Reply buffer size is 0
            nullptr,                          // No bytes returned needed
            1000                              // Timeout in ms
        );

        if (result) {
            std::wcout << L"[CommunicationManager] Configuration update sent - Flags: " << new_config_flags
                << L", Sensitivity: " << new_detection_sensitivity
                << L", Actions: " << new_response_actions << std::endl;
        } else {
            LogError("UpdateConfiguration - SendMessage failed", GetLastError()); // Or a specific error if SendMessage sets one
        }

        return result;
    }

    /**
     * @brief Request status from driver
     * @param status_reply_data Output structure to receive the status reply.
     * @return true on success
     */
    bool CommunicationManager::RequestStatus(CS_STATUS_REPLY_PAYLOAD& status_reply_data)
    {
        if (!connected_.load()) {
            LogError("RequestStatus", ERROR_NOT_CONNECTED);
            return false;
        }

        CS_STATUS_REQUEST_PAYLOAD request_payload = {};
        request_payload.Header.MessageType = MSG_TYPE_STATUS_REQUEST;
        request_payload.Header.MessageId = 0; // Or a unique ID
        request_payload.Header.PayloadSize = sizeof(CS_STATUS_REQUEST_PAYLOAD);

        // Prepare buffer for the reply. The driver's reply via FilterSendMessage includes
        // a FILTER_REPLY_HEADER followed by our CS_STATUS_REPLY_PAYLOAD.        

        const size_t calculated_reply_buffer_size = sizeof(FILTER_REPLY_HEADER) + sizeof(CS_STATUS_REPLY_PAYLOAD);
        std::vector<BYTE> reply_buffer(calculated_reply_buffer_size);
        DWORD bytes_returned = 0; // Variable to store the number of bytes returned

        // Call SendMessage.
        // Note: Current SendMessage wrapper doesn't return actual bytes_returned from FilterSendMessage.
        // We assume if SendMessage returns true, the reply_buffer contains the expected data up to reply_buffer_size.
        bool send_success = SendMessage(
            &request_payload,
            sizeof(request_payload),
            reply_buffer.data(),
            static_cast<DWORD>(reply_buffer.size()), // Pass the actual size of the vector's buffer as DWORD
            &bytes_returned,                         // Pass the address of bytes_returned
            1000                                     // Timeout in ms
        );

        if (!send_success) {
            LogError("RequestStatus - SendMessage failed", GetLastError());
            return false;
        }

        // Validate the received data using bytes_returned.
        // Check if enough data was returned for at least the FILTER_REPLY_HEADER and the CS_MESSAGE_PAYLOAD_HEADER within CS_STATUS_REPLY_PAYLOAD
        if (bytes_returned < (sizeof(FILTER_REPLY_HEADER) + sizeof(CS_MESSAGE_PAYLOAD_HEADER))) {
            LogError("RequestStatus - Reply too small for minimal headers based on bytes_returned", ERROR_INVALID_DATA);
            return false;
        }

        PCS_STATUS_REPLY_PAYLOAD actual_reply_payload =
            reinterpret_cast<PCS_STATUS_REPLY_PAYLOAD>(reply_buffer.data() + sizeof(FILTER_REPLY_HEADER));

        // Ensure the entire CS_STATUS_REPLY_PAYLOAD was received
        if (bytes_returned < (sizeof(FILTER_REPLY_HEADER) + sizeof(CS_STATUS_REPLY_PAYLOAD))) {
            LogError("RequestStatus - Reply too small for full CS_STATUS_REPLY_PAYLOAD based on bytes_returned", ERROR_INVALID_DATA);
            return false;
        }

        // Verify that the PayloadSize in the header matches the expected size and doesn't exceed the received data
        if (actual_reply_payload->Header.PayloadSize != sizeof(CS_STATUS_REPLY_PAYLOAD)) {
            LogError("RequestStatus - Reply payload Header.PayloadSize mismatch", ERROR_INVALID_DATA);
            std::wcerr << L"[CommunicationManager] Expected CS_STATUS_REPLY_PAYLOAD Header.PayloadSize " << sizeof(CS_STATUS_REPLY_PAYLOAD)
                << L", but received " << actual_reply_payload->Header.PayloadSize << std::endl;
            return false;
        }

        if (actual_reply_payload->Header.PayloadSize > (bytes_returned - sizeof(FILTER_REPLY_HEADER))) {
            LogError("RequestStatus - Header.PayloadSize indicates more data than actually received in reply", ERROR_INVALID_DATA);
            return false;
        }

        // If all checks pass, copy the data to the output parameter.
        status_reply_data = *actual_reply_payload;

        std::wcout << L"[CommunicationManager] Status received - Driver Version: "
                   << status_reply_data.DriverVersionMajor << L"."
                   << status_reply_data.DriverVersionMinor << L"."
                   << status_reply_data.DriverVersionBuild << std::endl;

        return true;
    }

    /**
     * @brief Send shutdown request to driver
     */
    bool CommunicationManager::RequestShutdown()
    {
        if (!connected_.load()) {
            // ERROR_NOT_CONNECTED (2250L) es un código de error estándar de Win32.
            // Debería estar disponible si <windows.h> está incluido correctamente.
            LogError("RequestShutdown", ERROR_NOT_CONNECTED);
            return false;
        }

        // Construir el payload para la solicitud de apagado.
        // Dado que Shared.h no define una estructura CS_SHUTDOWN_REQUEST_PAYLOAD específica
        // que contenga más que la cabecera, podemos usar CS_MESSAGE_PAYLOAD_HEADER
        // directamente o una estructura local simple que la envuelva.
        // Usaremos una estructura local para mantener la coherencia con cómo se manejan
        // otros payloads como CS_STATUS_REQUEST_PAYLOAD.

        struct ShutdownRequestPayload {
            CS_MESSAGE_PAYLOAD_HEADER Header;
            // No se necesitan campos adicionales para una solicitud de apagado simple.
        } request_payload = {}; // Inicializa a ceros

        request_payload.Header.MessageType = MSG_TYPE_SHUTDOWN_REQUEST; // Definido en Shared.h
        request_payload.Header.MessageId = 0; // O un ID único si se implementa seguimiento de mensajes
        request_payload.Header.PayloadSize = sizeof(request_payload); // Tamaño de nuestra estructura local

        // Enviar el mensaje al driver.
        // Las solicitudes de apagado generalmente no esperan un payload de datos como respuesta del driver;
        // el driver actúa sobre la solicitud.
        // La función SendMessage ya tiene manejo de errores y logging interno para fallos de FilterSendMessage.
        bool result = SendMessage(
            &request_payload,                // Puntero al payload
            sizeof(request_payload),         // Tamaño del payload
            nullptr,                         // No se espera un buffer de respuesta con datos
            0,                               // Tamaño del buffer de respuesta es 0
            nullptr,                         // No se necesita el número de bytes devueltos para esta llamada
            1000                             // Timeout en milisegundos (ej. 1 segundo)
        );

        if (result) {
            std::wcout << L"[CommunicationManager] Shutdown request sent successfully." << std::endl;
        }
        else {
            // SendMessage ya debería haber llamado a LogError si FilterSendMessage falló.
            // Se podría añadir un log específico aquí si 'result' es falso por otras razones,
            // aunque es improbable si SendMessage maneja bien todos los casos de error de la API.
            std::wcerr << L"[CommunicationManager] Failed to send shutdown request." << std::endl;
        }

        return result;
    }

    /**
     * @brief Set message callback
     */
    void CommunicationManager::SetMessageCallback(MessageCallback callback)
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        message_callback_ = callback;
    }

    /**
     * @brief Set connection state callback
     */
    void CommunicationManager::SetConnectionCallback(ConnectionCallback callback)
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        connection_callback_ = callback;
    }

    /**
     * @brief Get statistics
     */
    CommunicationManager::Statistics CommunicationManager::GetStatistics() const
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        return statistics_;
    }

    /**
     * @brief Message thread procedure
     */
    void CommunicationManager::MessageThreadProc()
    {
        std::wcout << L"[CommunicationManager] Message thread started" << std::endl;

        // Allocate message buffer
        auto buffer = std::make_unique<BYTE[]>(MESSAGE_BUFFER_SIZE);
        OVERLAPPED overlapped = {};
        // Correctly define message_header for use with FilterGetMessage
        PFILTER_MESSAGE_HEADER message_header = reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer.get());

        while (running_.load()) {
            // Reset overlapped structure
            ZeroMemory(&overlapped, sizeof(overlapped));

            // Get message from driver
            HRESULT hr = FilterGetMessage(
                filter_port_,
                message_header, // Use the PFILTER_MESSAGE_HEADER variable
                MESSAGE_BUFFER_SIZE,
                &overlapped
            );

            if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                // Wait for completion
                DWORD bytes_transferred = 0;
                ULONG_PTR completion_key = 0;
                LPOVERLAPPED completed_overlapped = nullptr;

                BOOL api_result = GetQueuedCompletionStatus(
                    completion_port_,
                    &bytes_transferred,
                    &completion_key,
                    &completed_overlapped,
                    INFINITE
                );

                if (!api_result) { // Changed variable name from result to api_result
                    DWORD error = GetLastError();
                    if (error == ERROR_OPERATION_ABORTED || !running_.load()) {
                        break;
                    }
                    LogError("GetQueuedCompletionStatus", error);
                    continue;
                }

                if (completed_overlapped == nullptr) {
                    // Shutdown signal (PostQueuedCompletionStatus with NULL overlapped)
                    break;
                }

                // Process the message
                // Basic validation for FILTER_MESSAGE_HEADER + CS_MESSAGE_PAYLOAD_HEADER
                if (bytes_transferred < (sizeof(FILTER_MESSAGE_HEADER) + sizeof(CS_MESSAGE_PAYLOAD_HEADER))) {
                    LogError("MessageThreadProc - Received message too small for CS_MESSAGE_PAYLOAD_HEADER", ERROR_INVALID_DATA);
                    continue;
                }

                // Calculate pointer to the actual CryptoShield payload header
                PCS_MESSAGE_PAYLOAD_HEADER actual_crypto_payload_header =
                    reinterpret_cast<PCS_MESSAGE_PAYLOAD_HEADER>(reinterpret_cast<PBYTE>(message_header) + sizeof(FILTER_MESSAGE_HEADER));

                switch (actual_crypto_payload_header->MessageType) {
                    case MSG_TYPE_FILE_OPERATION:
                    {
                        // Validate size for the specific payload: FILTER_MESSAGE_HEADER + CS_FILE_OPERATION_PAYLOAD
                        if (bytes_transferred < (sizeof(FILTER_MESSAGE_HEADER) + sizeof(CS_FILE_OPERATION_PAYLOAD))) {
                            LogError("MessageThreadProc - Received message too small for CS_FILE_OPERATION_PAYLOAD", ERROR_INVALID_DATA);
                            continue;
                        }

                        PCS_FILE_OPERATION_PAYLOAD file_op_payload = reinterpret_cast<PCS_FILE_OPERATION_PAYLOAD>(actual_crypto_payload_header);

                        // Further validation using PayloadSize from the header itself
                        // The total size should be at least FILTER_MESSAGE_HEADER + what the payload header claims its size is.
                        if (bytes_transferred < (sizeof(FILTER_MESSAGE_HEADER) + file_op_payload->Header.PayloadSize)) {
                             LogError("MessageThreadProc - Received message smaller than specified PayloadSize for CS_FILE_OPERATION_PAYLOAD", ERROR_INVALID_DATA);
                             continue;
                        }

                        // Call ProcessMessage (signature will be updated in a later step)
                        ProcessMessage(*file_op_payload); // This will cause a compile error until ProcessMessage is updated

                        // File operation notifications typically don't require a reply from this thread.
                        break;
                    }
                    default:
                    {
                        std::wcout << L"[CommunicationManager] Received unhandled message type: "
                                   << actual_crypto_payload_header->MessageType << std::endl;
                        // If a generic reply is needed for unhandled/unknown messages:
                        // FILTER_REPLY_HEADER replyHeader;
                        // replyHeader.Status = STATUS_SUCCESS; // Or an error like STATUS_INVALID_PARAMETER
                        // replyHeader.MessageId = message_header->MessageId; // message_header is PFILTER_MESSAGE_HEADER
                        // HRESULT reply_hr = FilterReplyMessage(filter_port_, &replyHeader, sizeof(FILTER_REPLY_HEADER));
                        // if (FAILED(reply_hr)) {
                        //    LogError("FilterReplyMessage for unhandled type", reply_hr);
                        // }
                        break;
                    }
                }
            }
            else if (FAILED(hr)) {
                 // HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) can occur if the port is closed during shutdown.
                 // HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) can also occur.
                if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) ||
                    hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) ||
                    !running_.load()) {
                    break;
                }
                LogError("FilterGetMessage", hr);
                HandleDisconnection();
                break;
            }
        }

        std::wcout << L"[CommunicationManager] Message thread stopped" << std::endl;
    }

    /**
     * @brief Process received message
     */
    // Signature changed from const FilterMessage& to const CS_FILE_OPERATION_PAYLOAD&
    void CommunicationManager::ProcessMessage(const CS_FILE_OPERATION_PAYLOAD& operation)
    {
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            statistics_.messages_received++;
        }

        FileOperationInfo file_op_info = {}; // Initialize with zeros/empty

        // Populate FileOperationInfo from CS_FILE_OPERATION_PAYLOAD
        file_op_info.process_id = operation.ProcessId;
        file_op_info.thread_id = operation.ThreadId; // Assuming FileOperationInfo has ThreadId

        // Convert OperationType (ULONG in CS_FILE_OPERATION_PAYLOAD) to FileOperationType (enum class)
        // Ensure that the enum values in FileOperationType align with FILE_OP_TYPE_* macros in Shared.h
        file_op_info.type = static_cast<FileOperationType>(operation.OperationType);

        // Convert Timestamp (LARGE_INTEGER in CS_FILE_OPERATION_PAYLOAD) to FILETIME
        file_op_info.timestamp.dwLowDateTime = operation.Timestamp.LowPart;
        file_op_info.timestamp.dwHighDateTime = operation.Timestamp.HighPart;

        // Copy FilePath
        // operation.FilePathLength is the number of characters, excluding NUL.
        // file_op_info.file_path is a WCHAR array of size MAX_FILE_PATH_CHARS.
        // wcsncpy_s with _TRUNCATE will copy at most MAX_FILE_PATH_CHARS-1 characters
        // from operation.FilePath and null-terminate.
        // If operation.FilePathLength is 0, it should result in an empty string.
        if (operation.FilePathLength > 0) {
            errno_t cpy_result = wcsncpy_s(file_op_info.file_path, MAX_FILE_PATH_CHARS, operation.FilePath, _TRUNCATE);
            if (cpy_result == STRUNCATE) {
                // Log that truncation occurred, though it's handled by null termination.
                std::wcerr << L"[CommunicationManager] FilePath truncated in ProcessMessage. Original length: "
                           << operation.FilePathLength << std::endl;
            } else if (cpy_result != 0) {
                // Log other wcsncpy_s error
                 std::wcerr << L"[CommunicationManager] wcsncpy_s failed in ProcessMessage with error: "
                           << cpy_result << std::endl;
                 // Potentially clear file_op_info.file_path or handle error further
                 file_op_info.file_path[0] = L'\0';
            }
        } else {
            file_op_info.file_path[0] = L'\0'; // Ensure empty path if length is 0
        }

        // Retrieve the callback under lock
        MessageCallback current_message_callback;
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            current_message_callback = message_callback_;
        }

        // Call the callback if it's set
        if (current_message_callback) {
            current_message_callback(file_op_info);
        } else {
            std::wcout << L"[CommunicationManager] Message callback not set. Message from PID "
                       << operation.ProcessId << L" for path " << operation.FilePath << L" not processed by a handler."
                       << std::endl;
        }
    }

    /**
     * @brief Send message to driver
     */
    // Refactored SendMessage to provide bytes_returned to the caller.
    bool CommunicationManager::SendMessage(
        const void* message_payload,      // Pointer to the CS_..._PAYLOAD structure
        DWORD message_payload_size,       // Size of the CS..._PAYLOAD structure (changed from size_t)
        LPVOID reply_buffer,              // Buffer for the reply (FILTER_REPLY_HEADER + CS_..._REPLY_PAYLOAD)
        DWORD reply_buffer_size,          // Size of the reply_buffer (changed from size_t)
        LPDWORD out_bytes_returned,       // Receives the actual number of bytes written to reply_buffer
        DWORD timeout_ms)                 // Currently unused by synchronous FilterSendMessage, kept for API consistency.
    {
        UNREFERENCED_PARAMETER(timeout_ms); // Mark timeout_ms as unreferenced for now.

        if (!connected_.load() || filter_port_ == INVALID_HANDLE_VALUE) {
            if (out_bytes_returned != nullptr) {
                *out_bytes_returned = 0; // Ensure 0 bytes on early exit if pointer is valid
            }
            return false;
        }

        // Determine the correct LPDWORD for FilterSendMessage based on whether a reply is expected.
        LPDWORD p_bytes_returned_for_api;
        if (reply_buffer != nullptr && reply_buffer_size > 0) {
            // If a reply buffer is provided, out_bytes_returned MUST be valid.
            if (out_bytes_returned == nullptr) {
                 // This is an invalid usage by the caller.
                 // Cannot proceed without a valid pointer to store bytes returned for a reply.
                LogError("SendMessage Error: out_bytes_returned is NULL but reply_buffer is provided.", ERROR_INVALID_PARAMETER);
                return false;
            }
            p_bytes_returned_for_api = out_bytes_returned;
        } else {
            // No reply buffer, or zero size buffer. FilterSendMessage expects lpBytesReturned to be NULL.
            // If caller provided an out_bytes_returned, ensure it's set to 0.
            if (out_bytes_returned != nullptr) {
                *out_bytes_returned = 0;
            }
            p_bytes_returned_for_api = nullptr;
        }

        // If reply_buffer_size is 0, treat reply_buffer as nullptr for FilterSendMessage consistency.
        LPVOID actual_reply_buffer = (reply_buffer_size > 0 && reply_buffer != nullptr) ? reply_buffer : nullptr;
        DWORD actual_reply_buffer_size = (actual_reply_buffer != nullptr) ? reply_buffer_size : 0;

        // If actual_reply_buffer is now effectively nullptr, then p_bytes_returned_for_api must also be nullptr.
        if (actual_reply_buffer == nullptr) {
            p_bytes_returned_for_api = nullptr;
        }

        HRESULT hr = FilterSendMessage(
            filter_port_,
            const_cast<LPVOID>(message_payload),
            message_payload_size,       // Already DWORD
            actual_reply_buffer,
            actual_reply_buffer_size,
            p_bytes_returned_for_api    // Use the determined LPDWORD
        );

        if (SUCCEEDED(hr)) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            statistics_.messages_sent++;
            // Note: If p_bytes_returned_for_api was nullptr (no reply expected),
            // out_bytes_returned (if provided by caller) would have been zeroed earlier.
            // If a reply was expected, *out_bytes_returned now holds the value from FilterSendMessage.
            return true;
        } else {
            if (out_bytes_returned != nullptr) {
                *out_bytes_returned = 0; // Ensure 0 bytes on error
            }
            LogError("FilterSendMessage", hr);
            // Added ERROR_FLT_DELETING_OBJECT as it's a common error during shutdown.
            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) || hr == HRESULT_FROM_WIN32(ERROR_FLT_DELETING_OBJECT)) {
                HandleDisconnection();
            }
            return false;
        }
    }

    /**
     * @brief Handle connection loss
     */
    void CommunicationManager::HandleDisconnection()
    {
        bool was_connected = connected_.exchange(false);
        if (was_connected) {
            std::wcout << L"[CommunicationManager] Connection lost" << std::endl;

            // Notify callback
            ConnectionCallback callback;
            {
                std::lock_guard<std::mutex> lock(callback_mutex_);
                callback = connection_callback_;
            }

            if (callback) {
                callback(false);
            }
        }
    }

    /**
     * @brief Log error with details
     */
    void CommunicationManager::LogError(const std::string& operation, DWORD error_code)
    {
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            statistics_.errors++;
        }

        wchar_t* error_message = nullptr;
        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            nullptr,
            error_code,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&error_message),
            0,
            nullptr
        );

        std::wcerr << L"[CommunicationManager] " << operation.c_str()
            << L" failed with error " << error_code;

        if (error_message) {
            std::wcerr << L": " << error_message;
            LocalFree(error_message);
        }
        else {
            std::wcerr << std::endl;
        }
    }

    // FileOperationInfo implementation

    /**
     * @brief Get operation type as string
     */
    std::wstring FileOperationInfo::GetOperationTypeString() const
    {
        switch (type) {
        case FileOperationType::Create: return L"Create";
        case FileOperationType::Write: return L"Write";
        case FileOperationType::Delete: return L"Delete";
        case FileOperationType::Rename: return L"Rename";
        case FileOperationType::SetInformation: return L"SetInfo";
        default: return L"Unknown";
        }
    }

    /**
     * @brief Get formatted timestamp
     */
    std::wstring FileOperationInfo::GetFormattedTimestamp() const
    {
        SYSTEMTIME st;
        FileTimeToSystemTime(&timestamp, &st);

        std::wostringstream oss;
        oss << std::setfill(L'0')
            << std::setw(4) << st.wYear << L"-"
            << std::setw(2) << st.wMonth << L"-"
            << std::setw(2) << st.wDay << L" "
            << std::setw(2) << st.wHour << L":"
            << std::setw(2) << st.wMinute << L":"
            << std::setw(2) << st.wSecond;

        return oss.str();
    }

} // namespace CryptoShield