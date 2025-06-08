#pragma once
/**
 * @file BehavioralDetector.h
 * @brief Behavioral pattern detection for ransomware identification
 * @details Detects mass file modifications, extension changes, and temporal patterns
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include "../CommunicationManager.h"
#include "DetectionConfig.h" // Added
#include <windows.h>
#include <vector>
#include <queue>
#include <set>
#include <map>
#include <string>
#include <chrono>
#include <mutex>
#include <atomic>
#include <memory>
#include <unordered_map>
#include <optional>

namespace CryptoShield::Detection {

    /**
     * @brief Behavioral analysis result
     */
    struct BehavioralAnalysisResult {
        bool is_suspicious;
        double confidence_score;
        std::wstring description;
        size_t operations_count;
        size_t directories_affected;
        size_t extensions_affected;
        double operations_per_second;
        std::vector<std::wstring> suspicious_patterns;
    };

    /**
     * @brief Extension change event
     */
    struct ExtensionChangeEvent {
        std::wstring file_path;
        std::wstring original_extension;
        std::wstring new_extension;
        std::chrono::steady_clock::time_point timestamp;
        ULONG process_id;
        bool is_suspicious;
        double suspicion_score;
    };

    /**
     * @brief Directory traversal pattern
     */
    struct DirectoryTraversalPattern {
        std::wstring root_directory;
        std::vector<std::wstring> traversed_directories;
        size_t depth;
        bool is_recursive;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point end_time;
        size_t files_affected;
    };

    /**
     * @brief Process behavior profile
     */
    struct ProcessBehaviorProfile {
        ULONG process_id;
        std::wstring process_name;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;

        // Operation statistics
        size_t total_operations;
        size_t write_operations;
        size_t delete_operations;
        size_t rename_operations;

        // Pattern indicators
        std::set<std::wstring> affected_directories;
        std::set<std::wstring> affected_extensions;
        std::set<std::wstring> created_extensions;

        // Behavioral scores
        double mass_modification_score;
        double extension_change_score;
        double directory_traversal_score;
        double temporal_pattern_score;
        double overall_suspicion_score;
    };

    /**
     * @brief Mass file modification detector
     * @details Detects rapid file modifications across multiple directories
     */
    class MassFileModificationDetector {
    public:
        /**
         * @brief Configuration for detection thresholds
         */
        struct Configuration {
            size_t min_operations_threshold = 50;
            size_t min_directories_threshold = 3;
            size_t min_extensions_threshold = 2;
            double max_operations_per_second = 10.0;
            std::chrono::seconds window_duration{ 60 };
            double suspicion_score_threshold = 0.7;
        };

        /**
         * @brief Constructor
         * @param config Detection configuration
         */
        explicit MassFileModificationDetector(const Configuration& config = {});

        /**
         * @brief Destructor
         */
        ~MassFileModificationDetector() = default;

        /**
         * @brief Analyze file operation
         * @param operation File operation to analyze
         * @return Detection result
         */
        BehavioralAnalysisResult AnalyzeOperation(const FileOperationInfo& operation);

        /**
         * @brief Reset detection window
         */
        void ResetWindow();

        /**
         * @brief Update configuration
         * @param config New configuration
         */
        void UpdateConfiguration(const Configuration& config);

        /**
         * @brief Get current window statistics
         */
        struct WindowStatistics {
            size_t operation_count;
            size_t directory_count;
            size_t extension_count;
            double operations_per_second;
            std::chrono::steady_clock::time_point window_start;
            std::chrono::steady_clock::time_point window_end;
        };

        WindowStatistics GetWindowStatistics() const;

    private:
        /**
         * @brief Operation window for temporal analysis
         */
        struct OperationWindow {
            std::chrono::steady_clock::time_point start_time;
            std::vector<FileOperationInfo> operations;
            std::set<std::wstring> affected_directories;
            std::set<std::wstring> file_extensions;
            std::map<ULONG, size_t> process_operation_count;
        };

        /**
         * @brief Calculate suspicion score
         * @return Score between 0 and 1
         */
        double CalculateSuspicionScore() const;

        /**
         * @brief Check if pattern matches rapid encryption
         * @return true if pattern is suspicious
         */
        bool IsRapidEncryptionPattern() const;

        /**
         * @brief Check if modifications are widespread
         * @return true if affecting many directories
         */
        bool IsWideSpreadModification() const;

        /**
         * @brief Extract directory from file path
         * @param file_path Full file path
         * @return Directory path
         */
        std::wstring ExtractDirectory(const std::wstring& file_path) const;

        /**
         * @brief Extract file extension
         * @param file_path Full file path
         * @return File extension
         */
        std::wstring ExtractExtension(const std::wstring& file_path) const;

    private:
        Configuration config_;
        OperationWindow current_window_;
        mutable std::mutex window_mutex_;
        std::chrono::steady_clock::time_point last_cleanup_;
    };

    /**
     * @brief File extension change monitor
     * @details Tracks and analyzes file extension modifications
     */
    class FileExtensionMonitor {
    public:
        // Modify constructor
        explicit FileExtensionMonitor(const CryptoShield::Detection::DetectionEngineConfig::BehavioralConfig& config);
        /**
         * @brief Destructor
         */
        ~FileExtensionMonitor() = default;

        /**
         * @brief Analyze file rename operation
         * @param old_path Original file path
         * @param new_path New file path
         * @param process_id Process performing the rename
         * @return Extension change event
         */
        ExtensionChangeEvent AnalyzeFileRename(const std::wstring& old_path,
            const std::wstring& new_path,
            ULONG process_id);

        /**
         * @brief Calculate extension suspicion score
         * @param extension File extension to analyze
         * @return Suspicion score (0-1)
         */
        double CalculateExtensionSuspicion(const std::wstring& extension) const;

        /**
         * @brief Check if extension is known ransomware indicator
         * @param extension File extension
         * @return true if known ransomware extension
         */
        bool IsKnownRansomwareExtension(const std::wstring& extension) const;

        /**
         * @brief Get recent extension changes
         * @param max_age Maximum age of events to return
         * @return Vector of recent extension changes
         */
        std::vector<ExtensionChangeEvent> GetRecentChanges(
            std::chrono::seconds max_age = std::chrono::seconds(300)) const;

        /**
         * @brief Clear old extension change records
         * @param max_age Maximum age to keep
         */
        void CleanupOldRecords(std::chrono::seconds max_age = std::chrono::seconds(3600));

    private:
        /**
         * @brief Check if extension matches suspicious pattern
         * @param extension Extension to check
         * @return true if matches pattern
         */
        bool MatchesSuspiciousPattern(const std::wstring& extension) const;

        /**
         * @brief Calculate Levenshtein distance between extensions
         * @param ext1 First extension
         * @param ext2 Second extension
         * @return Edit distance
         */
        size_t CalculateLevenshteinDistance(const std::wstring& ext1,
            const std::wstring& ext2) const;

    private:
        // Known ransomware extensions
        static const std::vector<std::wstring> RANSOMWARE_EXTENSIONS;
        static const std::vector<std::wstring> SUSPICIOUS_PATTERNS;

        // Extension change history
        std::vector<ExtensionChangeEvent> extension_changes_;
        mutable std::mutex changes_mutex_;

        // Original extension tracking
        std::unordered_map<std::wstring, std::wstring> original_extensions_;
        mutable std::mutex extensions_mutex_;

        // Add config member
        CryptoShield::Detection::DetectionEngineConfig::BehavioralConfig config_;
    };

    /**
     * @brief Directory traversal detector
     * @details Identifies recursive directory traversal patterns
     */
    class DirectoryTraversalDetector {
    public:
        /**
         * @brief Constructor
         */
        DirectoryTraversalDetector();

        /**
         * @brief Destructor
         */
        ~DirectoryTraversalDetector() = default;

        /**
         * @brief Analyze file operation for traversal patterns
         * @param operation File operation to analyze
         * @param process_id Process performing the operation
         */
        void AnalyzeOperation(const FileOperationInfo& operation, ULONG process_id);

        /**
         * @brief Get traversal pattern for process
         * @param process_id Process ID
         * @return Traversal pattern if detected
         */
        std::optional<DirectoryTraversalPattern> GetTraversalPattern(ULONG process_id) const;

        /**
         * @brief Check if process shows recursive traversal
         * @param process_id Process ID
         * @return true if recursive pattern detected
         */
        bool IsRecursiveTraversal(ULONG process_id) const;

        /**
         * @brief Calculate traversal suspicion score
         * @param pattern Traversal pattern
         * @return Suspicion score (0-1)
         */
        double CalculateTraversalSuspicion(const DirectoryTraversalPattern& pattern) const;

        /**
         * @brief Clear traversal data for process
         * @param process_id Process ID
         */
        void ClearProcessData(ULONG process_id);

    private:
        /**
         * @brief Process traversal information
         */
        struct ProcessTraversalInfo {
            std::set<std::wstring> visited_directories;
            std::wstring root_directory;
            size_t max_depth;
            size_t files_affected;
            std::chrono::steady_clock::time_point first_access;
            std::chrono::steady_clock::time_point last_access;
        };

        /**
         * @brief Calculate directory depth
         * @param directory Directory path
         * @return Depth from root
         */
        size_t CalculateDirectoryDepth(const std::wstring& directory) const;

        /**
         * @brief Find common root directory
         * @param directories Set of directories
         * @return Common root path
         */
        std::wstring FindCommonRoot(const std::set<std::wstring>& directories) const;

    private:
        std::map<ULONG, ProcessTraversalInfo> process_traversals_;
        mutable std::mutex traversal_mutex_;
    };

    /**
     * @brief Main behavioral detector class
     * @details Coordinates all behavioral detection components
     */
    class BehavioralDetector {
    public:
        // Modify constructor
        explicit BehavioralDetector(const CryptoShield::Detection::DetectionEngineConfig::BehavioralConfig& config);
        /**
         * @brief Destructor
         */
        ~BehavioralDetector();

        /**
         * @brief Analyze single file operation
         * @param operation File operation to analyze
         * @return Analysis result
         */
        BehavioralAnalysisResult AnalyzeOperation(const FileOperationInfo& operation);

        /**
         * @brief Analyze batch of operations
         * @param operations Vector of file operations
         * @return Comprehensive analysis result
         */
        BehavioralAnalysisResult AnalyzeBatch(const std::vector<FileOperationInfo>& operations);

        /**
         * @brief Configure detection thresholds
         * @param min_operations Minimum operations for detection
         * @param min_directories Minimum directories affected
         * @param min_extensions Minimum extensions affected
         * @param max_rate Maximum operations per second
         */
        void ConfigureThresholds(size_t min_operations,
            size_t min_directories,
            size_t min_extensions,
            double max_rate);

        /**
         * @brief Get process behavior profile
         * @param process_id Process ID
         * @return Process profile if available
         */
        std::optional<ProcessBehaviorProfile> GetProcessProfile(ULONG process_id) const;

        /**
         * @brief Clear process history
         * @param process_id Process ID (0 for all)
         */
        void ClearProcessHistory(ULONG process_id = 0);

        /**
         * @brief Get detector statistics
         */
        struct Statistics {
            size_t total_operations_analyzed;
            size_t suspicious_patterns_detected;
            size_t processes_tracked;
            double average_confidence_score;
        };

        Statistics GetStatistics() const;

    private:
        /**
         * @brief Update process profile
         * @param operation File operation
         */
        void UpdateProcessProfile(const FileOperationInfo& operation);

        /**
         * @brief Calculate combined suspicion score
         * @param profile Process profile
         * @return Combined score (0-1)
         */
        double CalculateCombinedScore(const ProcessBehaviorProfile& profile) const;

        /**
         * @brief Detect temporal anomalies
         * @param operations Recent operations
         * @return Anomaly score (0-1)
         */
        double DetectTemporalAnomalies(const std::vector<FileOperationInfo>& operations) const;

        /**
         * @brief Check for known attack patterns
         * @param profile Process profile
         * @return Vector of detected patterns
         */
        std::vector<std::wstring> CheckKnownPatterns(const ProcessBehaviorProfile& profile) const;

    private:
        // Detection components
        std::unique_ptr<MassFileModificationDetector> mass_modification_detector_;
        std::unique_ptr<FileExtensionMonitor> extension_monitor_;
        std::unique_ptr<DirectoryTraversalDetector> traversal_detector_;

        // Process profiles
        std::map<ULONG, ProcessBehaviorProfile> process_profiles_;
        mutable std::mutex profiles_mutex_;

        // Statistics
        mutable std::atomic<size_t> total_operations_analyzed_;
        mutable std::atomic<size_t> suspicious_patterns_detected_;

        // Configuration
        // MassFileModificationDetector::Configuration config_; // This line is replaced
        CryptoShield::Detection::DetectionEngineConfig::BehavioralConfig config_; // New config storage
    };

} // namespace CryptoShield::Detection