#pragma once
/**
 * @file CommunicationManager.h
 * @brief Driver communication management interface
 * @details Handles bidirectional communication with kernel driver
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include <windows.h>
#include <fltuser.h>
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>
#include <queue>
#include <mutex>

 // Link with filter manager library
#pragma comment(lib, "fltlib.lib")

namespace CryptoShield {

    // Forward declarations
    struct FileOperationInfo;
    class MessageProcessor;

    /**
     * @brief Message types matching kernel definitions
     */
    enum class MessageType : ULONG {
        FileOperation = 1,
        StatusRequest = 2,
        ConfigUpdate = 3,
        ShutdownRequest = 4
    };

    /**
     * @brief File operation types matching kernel definitions
     */
    enum class FileOperationType : ULONG {
        Create = 1,
        Write = 2,
        Delete = 3,
        Rename = 4,
        SetInformation = 5
    };

    /**
     * @brief Filter message structure (must match kernel structure)
     */
#pragma pack(push, 1)
    struct FilterMessage {
        FILTER_MESSAGE_HEADER header;
        ULONG message_type;
        ULONG process_id;
        ULONG thread_id;
        LARGE_INTEGER timestamp;
        ULONG operation_type;
        USHORT file_path_length;
        WCHAR file_path[520];  // MAX_PATH * 2
    };

    /**
     * @brief Filter reply structure
     */
    struct FilterReply {
        FILTER_REPLY_HEADER header;
        NTSTATUS status;
        BOOLEAN allow_operation;
    };
#pragma pack(pop)

    /**
     * @brief Configuration update structure
     */
    struct ConfigUpdate {
        FilterMessage header;
        BOOLEAN monitoring_enabled;
        ULONG detection_sensitivity;
    };

    /**
     * @brief Status reply structure
     */
    struct StatusReply {
        BOOLEAN monitoring_enabled;
        ULONG detection_sensitivity;
        ULONG file_operation_count;
        ULONG messages_sent;
        ULONG messages_received;
    };

    /**
     * @brief Communication manager class
     * @details Manages all communication with the kernel driver
     */
    class CommunicationManager {
    public:
        /**
         * @brief Message callback type
         */
        using MessageCallback = std::function<void(const FileOperationInfo&)>;

        /**
         * @brief Connection state callback type
         */
        using ConnectionCallback = std::function<void(bool connected)>;

        /**
         * @brief Constructor
         */
        CommunicationManager();

        /**
         * @brief Destructor
         */
        ~CommunicationManager();

        // Disable copy
        CommunicationManager(const CommunicationManager&) = delete;
        CommunicationManager& operator=(const CommunicationManager&) = delete;

        /**
         * @brief Initialize and connect to driver
         * @param port_name Name of the communication port
         * @return true on success
         */
        bool Initialize(const std::wstring& port_name = L"\\CryptoShieldPort");

        /**
         * @brief Shutdown and disconnect
         */
        void Shutdown();

        /**
         * @brief Check if connected to driver
         * @return true if connected
         */
        bool IsConnected() const { return connected_.load(); }

        /**
         * @brief Send configuration update to driver
         * @param monitoring_enabled Enable/disable monitoring
         * @param detection_sensitivity Detection sensitivity (0-100)
         * @return true on success
         */
        bool UpdateConfiguration(bool monitoring_enabled, ULONG detection_sensitivity);

        /**
         * @brief Request status from driver
         * @param status Output status structure
         * @return true on success
         */
        bool RequestStatus(StatusReply& status);

        /**
         * @brief Send shutdown request to driver
         * @return true on success
         */
        bool RequestShutdown();

        /**
         * @brief Set message callback
         * @param callback Function to call for each file operation
         */
        void SetMessageCallback(MessageCallback callback);

        /**
         * @brief Set connection state callback
         * @param callback Function to call on connection state change
         */
        void SetConnectionCallback(ConnectionCallback callback);

        /**
         * @brief Get statistics
         */
        struct Statistics {
            ULONG messages_received;
            ULONG messages_sent;
            ULONG errors;
            ULONG timeouts;
        };

        Statistics GetStatistics() const;

    private:
        /**
         * @brief Message thread procedure
         */
        void MessageThreadProc();

        /**
         * @brief Process received message
         * @param message Message from driver
         */
        void ProcessMessage(const FilterMessage& message);

        /**
         * @brief Send message to driver
         * @param message Message to send
         * @param reply Optional reply buffer
         * @param reply_size Size of reply buffer
         * @param timeout_ms Timeout in milliseconds
         * @return true on success
         */
        bool SendMessage(const void* message,
            size_t message_size,
            void* reply = nullptr,
            size_t reply_size = 0,
            DWORD timeout_ms = 1000);

        /**
         * @brief Handle connection loss
         */
        void HandleDisconnection();

        /**
         * @brief Log error with details
         * @param operation Operation that failed
         * @param error_code Windows error code
         */
        void LogError(const std::string& operation, DWORD error_code);

    private:
        // Communication handles
        HANDLE filter_port_;
        HANDLE completion_port_;

        // Threading
        std::thread message_thread_;
        std::atomic<bool> running_;
        std::atomic<bool> connected_;

        // Callbacks
        MessageCallback message_callback_;
        ConnectionCallback connection_callback_;
        mutable std::mutex callback_mutex_;

        // Statistics
        mutable std::mutex stats_mutex_;
        Statistics statistics_;

        // Configuration
        std::wstring port_name_;
        static constexpr DWORD MESSAGE_BUFFER_SIZE = 8192;
        static constexpr DWORD MAX_THREAD_COUNT = 2;
    };

    /**
     * @brief File operation information
     * @details Parsed file operation data
     */
    struct FileOperationInfo {
        FileOperationType type;
        ULONG process_id;
        ULONG thread_id;
        std::wstring file_path;
        FILETIME timestamp;

        /**
         * @brief Get operation type as string
         */
        std::wstring GetOperationTypeString() const;

        /**
         * @brief Get formatted timestamp
         */
        std::wstring GetFormattedTimestamp() const;
    };

} // namespace CryptoShield