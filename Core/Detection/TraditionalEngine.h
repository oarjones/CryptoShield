#pragma once
/**
 * @file TraditionalEngine.h
 * @brief Traditional detection engine interface for ransomware detection
 * @details Core detection engine using probabilistic and behavioral analysis
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once
#include "DetectionConfig.h"
#include <windows.h>
#include <memory>
#include <vector>
#include <string>
#include <chrono>
#include <atomic>
#include <mutex>

namespace CryptoShield::Detection {

    // Forward declarations
    class AdvancedEntropyAnalysis;
    class BehavioralDetector;
    class SystemActivityMonitor;
    class ScoringEngine;
    class PatternDatabase;

    /**
     * @brief File type enumeration for adaptive detection
     */
    enum class FileType {
        TEXT_DOCUMENT,    // .txt, .doc, .pdf
        IMAGE,           // .jpg, .png, .gif
        EXECUTABLE,      // .exe, .dll, .sys
        COMPRESSED,      // .zip, .rar, .7z
        DATABASE,        // .db, .mdb, .sqlite
        MEDIA,           // .mp3, .mp4, .avi
        UNKNOWN          // Unknown file types
    };

    /**
     * @brief Threat level classification
     */
    enum class ThreatLevel {
        NONE = 0,
        LOW = 1,
        MEDIUM = 2,
        HIGH = 3,
        CRITICAL = 4
    };

    /**
     * @brief File operation information
     */
    struct FileOperation {
        std::wstring file_path;
        ULONG process_id;
        ULONG thread_id;
        ULONG operation_type;
        std::chrono::steady_clock::time_point timestamp;
        size_t data_size;
        double entropy_before;
        double entropy_after;
    };

    /**
     * @brief Detection result structure
     */
    struct DetectionResult {
        bool is_threat;
        ThreatLevel threat_level;
        double confidence_score;
        std::wstring primary_threat_name;
        std::vector<std::wstring> contributing_factors;
        std::chrono::steady_clock::time_point detection_time;
        ULONG process_id;
        std::vector<std::wstring> affected_files;
        std::wstring recommended_action;
    };

    /**
     * @brief Engine configuration
     */
    //struct EngineConfig {
    //    // Entropy analysis settings
    //    bool enable_entropy_analysis;
    //    double entropy_weight;

    //    // Behavioral detection settings
    //    bool enable_behavioral_detection;
    //    double behavioral_weight;
    //    size_t min_operations_for_detection;

    //    // System monitoring settings
    //    bool enable_system_monitoring;
    //    double system_activity_weight;

    //    // General settings
    //    size_t max_file_size_for_analysis;
    //    size_t analysis_thread_count;
    //    bool enable_false_positive_reduction;
    //    bool enable_detailed_logging;
    //};


    // Añade esta nueva estructura, puede estar fuera o dentro de la clase TraditionalEngine
    struct EngineStatsData {
        size_t operations_analyzed;
        size_t threats_detected;
        size_t false_positives_prevented;
        double average_analysis_time_ms;
        double average_confidence_score;
    };
    /**
     * @brief Traditional detection engine main class
     * @details Coordinates all detection components for comprehensive analysis
     */
    class TraditionalEngine {
    public:
        /**
         * @brief Constructor
         * @param config Engine configuration
         */
        explicit TraditionalEngine(const DetectionEngineConfig& config);

        /**
         * @brief Destructor
         */
        ~TraditionalEngine();

        // Disable copy
        TraditionalEngine(const TraditionalEngine&) = delete;
        TraditionalEngine& operator=(const TraditionalEngine&) = delete;

        /**
         * @brief Initialize the detection engine
         * @return true on success
         */
        bool Initialize();

        /**
         * @brief Shutdown the detection engine
         */
        void Shutdown();

        /**
         * @brief Analyze a file operation
         * @param operation File operation details
         * @return Detection result
         */
        DetectionResult AnalyzeOperation(const FileOperation& operation);

        /**
         * @brief Analyze a batch of operations
         * @param operations Vector of file operations
         * @return Comprehensive detection result
         */
        DetectionResult AnalyzeBatch(const std::vector<FileOperation>& operations);

        /**
         * @brief Update engine configuration
         * @param config New configuration
         */
        void UpdateConfiguration(const DetectionEngineConfig& config);

        /**
         * @brief Get current engine statistics
         */
        struct Statistics {
            std::atomic<size_t> operations_analyzed;
            std::atomic<size_t> threats_detected;
            std::atomic<size_t> false_positives_prevented;
            double average_analysis_time_ms;
            double average_confidence_score;
            std::chrono::steady_clock::time_point engine_start_time;
        };

        //Statistics GetStatistics() const;
        EngineStatsData GetStatistics() const;

        /**
         * @brief Get default engine configuration
         * @return Default configuration
         */
        /*static EngineConfig GetDefaultConfig();*/

        /**
         * @brief Load configuration from file
         * @param config_file Path to configuration file
         * @return Loaded configuration
         */
        /*static DetectionEngineConfig LoadConfiguration(const std::wstring& config_file);*/

    private:
        /**
         * @brief Perform entropy analysis
         * @param operation File operation to analyze
         * @return Entropy analysis score (0-1)
         */
        double PerformEntropyAnalysis(const FileOperation& operation);

        /**
         * @brief Perform behavioral analysis
         * @param operations Recent operations to analyze
         * @return Behavioral analysis score (0-1)
         */
        double PerformBehavioralAnalysis(const std::vector<FileOperation>& operations);

        /**
         * @brief Perform system activity analysis
         * @param process_id Process to analyze
         * @return System activity score (0-1)
         */
        double PerformSystemAnalysis(ULONG process_id);

        /**
         * @brief Combine analysis results
         * @param entropy_score Entropy analysis score
         * @param behavioral_score Behavioral analysis score
         * @param system_score System activity score
         * @return Combined detection result
         */
        DetectionResult CombineAnalysisResults(double entropy_score,
            double behavioral_score,
            double system_score,
            const FileOperation& operation);

        /**
         * @brief Classify threat level based on score
         * @param confidence_score Combined confidence score
         * @return Threat level
         */
        ThreatLevel ClassifyThreatLevel(double confidence_score) const;

        /**
         * @brief Apply false positive reduction
         * @param result Initial detection result
         * @return Adjusted detection result
         */
        DetectionResult ApplyFalsePositiveReduction(const DetectionResult& result);

        /**
         * @brief Update internal statistics
         * @param result Detection result
         * @param analysis_time Analysis duration
         */
        void UpdateStatistics(const DetectionResult& result,
            std::chrono::microseconds analysis_time);

    private:
        // Configuration
        DetectionEngineConfig config_;

        // Detection components
        std::unique_ptr<AdvancedEntropyAnalysis> entropy_analyzer_;
        std::unique_ptr<BehavioralDetector> behavioral_detector_;
        std::unique_ptr<SystemActivityMonitor> system_monitor_;
        std::unique_ptr<ScoringEngine> scoring_engine_;
        std::unique_ptr<PatternDatabase> pattern_database_;

        // State management
        std::atomic<bool> initialized_;
        std::atomic<bool> running_;
        mutable std::mutex engine_mutex_;

        // Statistics
        mutable Statistics statistics_;

        // Recent operations cache
        std::vector<FileOperation> recent_operations_;
        mutable std::mutex operations_mutex_;
        static constexpr size_t MAX_CACHED_OPERATIONS = 10000;
    };

} // namespace CryptoShield::Detection