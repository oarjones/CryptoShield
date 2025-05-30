/**
 * @file MessageProcessor.h
 * @brief Message processing and analysis interface
 * @details Processes file operation messages and manages analysis queue
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include "CommunicationManager.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <memory>
#include <chrono>
#include <unordered_map>
#include <vector>
#include <fstream>

namespace CryptoShield {

    /**
     * @brief Process information for tracking
     */
    struct ProcessInfo {
        ULONG process_id;
        std::wstring process_name;
        std::wstring process_path;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
        ULONG operation_count;
        ULONG suspicious_operations;
    };

    /**
     * @brief File operation statistics
     */
    struct FileOperationStats {
        ULONG total_operations;
        ULONG creates;
        ULONG writes;
        ULONG deletes;
        ULONG renames;
        ULONG set_information;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point last_operation;
    };

    /**
     * @brief Alert severity levels
     */
    enum class AlertSeverity {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    };

    /**
     * @brief Alert information
     */
    struct AlertInfo {
        AlertSeverity severity;
        std::wstring description;
        ULONG process_id;
        std::wstring file_path;
        std::chrono::steady_clock::time_point timestamp;
    };

    /**
     * @brief Message processor configuration
     */
    struct ProcessorConfig {
        bool enable_logging;
        std::wstring log_directory;
        ULONG max_queue_size;
        ULONG processing_threads;
        bool enable_alerts;
        ULONG alert_threshold;
    };

    /**
     * @brief Message processor class
     * @details Analyzes file operations and detects suspicious patterns
     */
    class MessageProcessor {
    public:
        /**
         * @brief Alert callback type
         */
        using AlertCallback = std::function<void(const AlertInfo&)>;

        /**
         * @brief Constructor
         */
        explicit MessageProcessor(const ProcessorConfig& config = {});

        /**
         * @brief Destructor
         */
        ~MessageProcessor();

        // Disable copy
        MessageProcessor(const MessageProcessor&) = delete;
        MessageProcessor& operator=(const MessageProcessor&) = delete;

        /**
         * @brief Start processing
         * @return true on success
         */
        bool Start();

        /**
         * @brief Stop processing
         */
        void Stop();

        /**
         * @brief Check if processor is running
         * @return true if running
         */
        bool IsRunning() const { return running_.load(); }

        /**
         * @brief Enqueue file operation for processing
         * @param operation Operation information
         */
        void EnqueueOperation(const FileOperationInfo& operation);

        /**
         * @brief Get current queue size
         * @return Number of operations in queue
         */
        size_t GetQueueSize() const;

        /**
         * @brief Get file operation statistics
         * @return Current statistics
         */
        FileOperationStats GetStatistics() const;

        /**
         * @brief Get process information
         * @param process_id Process ID
         * @return Process info if found
         */
        std::optional<ProcessInfo> GetProcessInfo(ULONG process_id) const;

        /**
         * @brief Get all tracked processes
         * @return Vector of process information
         */
        std::vector<ProcessInfo> GetAllProcesses() const;

        /**
         * @brief Set alert callback
         * @param callback Function to call for alerts
         */
        void SetAlertCallback(AlertCallback callback);

        /**
         * @brief Update configuration
         * @param config New configuration
         */
        void UpdateConfiguration(const ProcessorConfig& config);

        /**
         * @brief Clear operation history
         */
        void ClearHistory();

    private:
        /**
         * @brief Processing thread procedure
         */
        void ProcessingThreadProc();

        /**
         * @brief Process single operation
         * @param operation Operation to process
         */
        void ProcessOperation(const FileOperationInfo& operation);

        /**
         * @brief Update process information
         * @param operation Operation data
         */
        void UpdateProcessInfo(const FileOperationInfo& operation);

        /**
         * @brief Analyze operation for suspicious behavior
         * @param operation Operation to analyze
         * @return Suspicion level (0-100)
         */
        ULONG AnalyzeOperation(const FileOperationInfo& operation);

        /**
         * @brief Check for suspicious patterns
         * @param process_id Process to check
         * @return true if suspicious patterns detected
         */
        bool CheckSuspiciousPatterns(ULONG process_id);

        /**
         * @brief Generate alert
         * @param severity Alert severity
         * @param description Alert description
         * @param operation Related operation
         */
        void GenerateAlert(AlertSeverity severity,
            const std::wstring& description,
            const FileOperationInfo& operation);

        /**
         * @brief Log operation to file
         * @param operation Operation to log
         */
        void LogOperation(const FileOperationInfo& operation);

        /**
         * @brief Open log file for current date
         * @return true on success
         */
        bool OpenLogFile();

        /**
         * @brief Get process name from ID
         * @param process_id Process ID
         * @return Process name
         */
        std::wstring GetProcessName(ULONG process_id);

        /**
         * @brief Check if file extension is suspicious
         * @param file_path Path to check
         * @return true if extension is suspicious
         */
        bool IsSuspiciousExtension(const std::wstring& file_path);

        /**
         * @brief Calculate operation rate for process
         * @param process_id Process ID
         * @return Operations per second
         */
        double CalculateOperationRate(ULONG process_id);

    private:
        // Configuration
        ProcessorConfig config_;

        // Operation queue
        std::queue<FileOperationInfo> operation_queue_;
        mutable std::mutex queue_mutex_;
        std::condition_variable queue_cv_;

        // Processing threads
        std::vector<std::thread> processing_threads_;
        std::atomic<bool> running_;

        // Process tracking
        mutable std::mutex process_mutex_;
        std::unordered_map<ULONG, ProcessInfo> process_map_;

        // Statistics
        mutable std::mutex stats_mutex_;
        FileOperationStats statistics_;

        // Alert handling
        std::mutex alert_mutex_;
        AlertCallback alert_callback_;
        std::vector<AlertInfo> recent_alerts_;

        // Logging
        std::mutex log_mutex_;
        std::ofstream log_file_;
        std::wstring current_log_date_;

        // Pattern detection
        static constexpr ULONG SUSPICIOUS_WRITE_THRESHOLD = 100;
        static constexpr ULONG SUSPICIOUS_DELETE_THRESHOLD = 50;
        static constexpr ULONG SUSPICIOUS_RENAME_THRESHOLD = 20;
        static constexpr double SUSPICIOUS_RATE_THRESHOLD = 10.0; // ops/sec

        // Known suspicious extensions
        static const std::vector<std::wstring> SUSPICIOUS_EXTENSIONS;
    };

    /**
     * @brief File operation logger
     * @details Specialized logger for file operations
     */
    class FileOperationLogger {
    public:
        /**
         * @brief Constructor
         * @param log_directory Directory for log files
         */
        explicit FileOperationLogger(const std::wstring& log_directory);

        /**
         * @brief Destructor
         */
        ~FileOperationLogger();

        /**
         * @brief Log operation
         * @param operation Operation to log
         * @param process_name Name of process
         * @param suspicion_level Suspicion level (0-100)
         */
        void LogOperation(const FileOperationInfo& operation,
            const std::wstring& process_name,
            ULONG suspicion_level);

        /**
         * @brief Log alert
         * @param alert Alert to log
         */
        void LogAlert(const AlertInfo& alert);

        /**
         * @brief Rotate log files
         */
        void RotateLogs();

    private:
        std::wstring log_directory_;
        std::mutex log_mutex_;
        std::ofstream operation_log_;
        std::ofstream alert_log_;

        /**
         * @brief Ensure log directory exists
         */
        bool EnsureLogDirectory();

        /**
         * @brief Get current log filename
         * @param prefix File prefix
         * @return Full path to log file
         */
        std::wstring GetLogFilename(const std::wstring& prefix);
    };

} // namespace CryptoShield