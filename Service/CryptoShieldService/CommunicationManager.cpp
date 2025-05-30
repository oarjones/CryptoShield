/**
 * @file CommunicationManager.cpp
 * @brief Driver communication management implementation
 * @details Handles bidirectional communication with kernel driver
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "CommunicationManager.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>

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
     */
    bool CommunicationManager::UpdateConfiguration(bool monitoring_enabled, ULONG detection_sensitivity)
    {
        if (!connected_.load()) {
            return false;
        }

        // Validate parameters
        if (detection_sensitivity > 100) {
            LogError("UpdateConfiguration", ERROR_INVALID_PARAMETER);
            return false;
        }

        ConfigUpdate config = {};
        config.header.message_type = static_cast<ULONG>(MessageType::ConfigUpdate);
        config.monitoring_enabled = monitoring_enabled ? TRUE : FALSE;
        config.detection_sensitivity = detection_sensitivity;

        bool result = SendMessage(&config, sizeof(config));

        if (result) {
            std::wcout << L"[CommunicationManager] Configuration updated - Monitoring: "
                << (monitoring_enabled ? L"Enabled" : L"Disabled")
                << L", Sensitivity: " << detection_sensitivity << std::endl;
        }

        return result;
    }

    /**
     * @brief Request status from driver
     */
    bool CommunicationManager::RequestStatus(StatusReply& status)
    {
        if (!connected_.load()) {
            return false;
        }

        FilterMessage request = {};
        request.message_type = static_cast<ULONG>(MessageType::StatusRequest);

        bool result = SendMessage(&request, sizeof(request), &status, sizeof(status));

        if (result) {
            std::wcout << L"[CommunicationManager] Status received - Operations: "
                << status.file_operation_count << L", Sent: "
                << status.messages_sent << L", Received: "
                << status.messages_received << std::endl;
        }

        return result;
    }

    /**
     * @brief Send shutdown request to driver
     */
    bool CommunicationManager::RequestShutdown()
    {
        if (!connected_.load()) {
            return false;
        }

        FilterMessage request = {};
        request.message_type = static_cast<ULONG>(MessageType::ShutdownRequest);

        bool result = SendMessage(&request, sizeof(request));

        if (result) {
            std::wcout << L"[CommunicationManager] Shutdown request sent" << std::endl;
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

        while (running_.load()) {
            // Reset overlapped structure
            ZeroMemory(&overlapped, sizeof(overlapped));

            // Get message from driver
            HRESULT hr = FilterGetMessage(
                filter_port_,
                reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer.get()),
                MESSAGE_BUFFER_SIZE,
                &overlapped
            );

            if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                // Wait for completion
                DWORD bytes_transferred = 0;
                ULONG_PTR completion_key = 0;
                LPOVERLAPPED completed_overlapped = nullptr;

                BOOL result = GetQueuedCompletionStatus(
                    completion_port_,
                    &bytes_transferred,
                    &completion_key,
                    &completed_overlapped,
                    INFINITE
                );

                if (!result) {
                    DWORD error = GetLastError();
                    if (error == ERROR_OPERATION_ABORTED || !running_.load()) {
                        break;
                    }
                    LogError("GetQueuedCompletionStatus", error);
                    continue;
                }

                if (completed_overlapped == nullptr) {
                    // Shutdown signal
                    break;
                }

                // Process the message
                if (bytes_transferred >= sizeof(FILTER_MESSAGE_HEADER)) {
                    auto* message = reinterpret_cast<FilterMessage*>(buffer.get());
                    ProcessMessage(*message);

                    // Send reply
                    FilterReply reply = {};
                    reply.header.Status = 0;
                    reply.header.MessageId = message->header.MessageId;
                    reply.status = STATUS_SUCCESS;
                    reply.allow_operation = TRUE;

                    hr = FilterReplyMessage(
                        filter_port_,
                        reinterpret_cast<PFILTER_REPLY_HEADER>(&reply),
                        sizeof(reply)
                    );

                    if (FAILED(hr)) {
                        LogError("FilterReplyMessage", hr);
                    }
                }
            }
            else if (FAILED(hr)) {
                if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) || !running_.load()) {
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
    void CommunicationManager::ProcessMessage(const FilterMessage& message)
    {
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            statistics_.messages_received++;
        }

        // Handle file operation messages
        if (message.message_type == static_cast<ULONG>(MessageType::FileOperation)) {
            FileOperationInfo info;
            info.type = static_cast<FileOperationType>(message.operation_type);
            info.process_id = message.process_id;
            info.thread_id = message.thread_id;

            // Convert timestamp
            info.timestamp.dwLowDateTime = message.timestamp.LowPart;
            info.timestamp.dwHighDateTime = message.timestamp.HighPart;

            // Copy file path
            size_t path_length = message.file_path_length / sizeof(WCHAR);
            if (path_length > 0 && path_length < _countof(message.file_path)) {
                info.file_path.assign(message.file_path, path_length);
            }

            // Call callback
            MessageCallback callback;
            {
                std::lock_guard<std::mutex> lock(callback_mutex_);
                callback = message_callback_;
            }

            if (callback) {
                callback(info);
            }
        }
    }

    /**
     * @brief Send message to driver
     */
    bool CommunicationManager::SendMessage(const void* message,
        size_t message_size,
        void* reply,
        size_t reply_size,
        DWORD timeout_ms)
    {
        if (!connected_.load() || filter_port_ == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD bytes_returned = 0;
        HRESULT hr = FilterSendMessage(
            filter_port_,
            const_cast<LPVOID>(message),
            static_cast<DWORD>(message_size),
            reply,
            static_cast<DWORD>(reply_size),
            &bytes_returned
        );

        if (SUCCEEDED(hr)) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            statistics_.messages_sent++;
            return true;
        }
        else {
            LogError("FilterSendMessage", hr);
            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
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