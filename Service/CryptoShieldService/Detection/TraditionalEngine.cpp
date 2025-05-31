/**
 * @file TraditionalEngine.cpp
 * @brief Traditional detection engine implementation
 * @details Coordinates detection components for comprehensive ransomware analysis
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */
#define NOMINMAX
#include "TraditionalEngine.h"
#include "EntropyAnalyzer.h"
#include "BehavioralDetector.h"
#include "SystemActivityMonitor.h"
#include "ScoringEngine.h"
#include "PatternDatabase.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <nlohmann/json.hpp>

namespace CryptoShield::Detection {

    /**
     * @brief Constructor
     */
    TraditionalEngine::TraditionalEngine(const EngineConfig& config)
        : config_(config)
        , initialized_(false)
        , running_(false)
        , statistics_{}
    {
        statistics_.engine_start_time = std::chrono::steady_clock::now();
    }

    /**
     * @brief Destructor
     */
    TraditionalEngine::~TraditionalEngine()
    {
        if (running_.load()) {
            Shutdown();
        }
    }

    /**
     * @brief Initialize the detection engine
     */
    bool TraditionalEngine::Initialize()
    {
        std::lock_guard<std::mutex> lock(engine_mutex_);

        if (initialized_.load()) {
            return true;
        }

        try {
            // Initialize entropy analyzer
            entropy_analyzer_ = std::make_unique<AdvancedEntropyAnalysis>();

            // Initialize behavioral detector
            behavioral_detector_ = std::make_unique<BehavioralDetector>();
            behavioral_detector_->ConfigureThresholds(
                config_.min_operations_for_detection,
                3,  // min directories
                2,  // min extensions
                10.0 // max ops per second
            );

            // Initialize system activity monitor
            system_monitor_ = std::make_unique<SystemActivityMonitor>();

            // Initialize scoring engine
            ScoringEngine::WeightConfiguration weights;
            weights.entropy_weight = config_.entropy_weight;
            weights.behavioral_weight = config_.behavioral_weight;
            weights.system_activity_weight = config_.system_activity_weight;
            weights.temporal_weight = 0.2; // Fixed temporal weight

            scoring_engine_ = std::make_unique<ScoringEngine>();
            scoring_engine_->UpdateWeights(weights);

            // Initialize pattern database
            pattern_database_ = std::make_unique<PatternDatabase>();
            pattern_database_->LoadPatterns(L"patterns.db");

            initialized_ = true;
            running_ = true;

            std::wcout << L"[TraditionalEngine] Initialized successfully" << std::endl;
            return true;
        }
        catch (const std::exception& e) {
            std::wcerr << L"[TraditionalEngine] Initialization failed: " << e.what() << std::endl;
            return false;
        }
    }

    /**
     * @brief Shutdown the detection engine
     */
    void TraditionalEngine::Shutdown()
    {
        std::lock_guard<std::mutex> lock(engine_mutex_);

        if (!running_.load()) {
            return;
        }

        running_ = false;

        // Cleanup components
        entropy_analyzer_.reset();
        behavioral_detector_.reset();
        system_monitor_.reset();
        scoring_engine_.reset();
        pattern_database_.reset();

        initialized_ = false;

        std::wcout << L"[TraditionalEngine] Shutdown complete" << std::endl;
    }

    /**
     * @brief Analyze a file operation
     */
    DetectionResult TraditionalEngine::AnalyzeOperation(const FileOperation& operation)
    {
        if (!initialized_.load()) {
            DetectionResult result = {};
            result.is_threat = false;
            result.threat_level = ThreatLevel::NONE;
            result.confidence_score = 0.0;
            result.recommended_action = L"Engine not initialized";
            return result;
        }

        auto start_time = std::chrono::steady_clock::now();

        // Add to recent operations cache
        {
            std::lock_guard<std::mutex> lock(operations_mutex_);
            recent_operations_.push_back(operation);
            if (recent_operations_.size() > MAX_CACHED_OPERATIONS) {
                recent_operations_.erase(recent_operations_.begin());
            }
        }

        // Perform analysis components
        double entropy_score = 0.0;
        double behavioral_score = 0.0;
        double system_score = 0.0;

        // Entropy analysis
        if (config_.enable_entropy_analysis) {
            entropy_score = PerformEntropyAnalysis(operation);
        }

        // Behavioral analysis
        if (config_.enable_behavioral_detection) {
            std::lock_guard<std::mutex> lock(operations_mutex_);
            behavioral_score = PerformBehavioralAnalysis(recent_operations_);
        }

        // System activity analysis
        if (config_.enable_system_monitoring) {
            system_score = PerformSystemAnalysis(operation.process_id);
        }

        // Combine results
        DetectionResult result = CombineAnalysisResults(
            entropy_score,
            behavioral_score,
            system_score,
            operation
        );

        // Apply false positive reduction if enabled
        if (config_.enable_false_positive_reduction) {
            result = ApplyFalsePositiveReduction(result);
        }

        // Update statistics
        auto end_time = std::chrono::steady_clock::now();
        auto analysis_time = std::chrono::duration_cast<std::chrono::microseconds>(
            end_time - start_time
        );
        UpdateStatistics(result, analysis_time);

        return result;
    }

    /**
     * @brief Analyze a batch of operations
     */
    DetectionResult TraditionalEngine::AnalyzeBatch(const std::vector<FileOperation>& operations)
    {
        if (!initialized_.load() || operations.empty()) {
            DetectionResult result = {};
            result.is_threat = false;
            result.threat_level = ThreatLevel::NONE;
            result.confidence_score = 0.0;
            return result;
        }

        // Aggregate analysis results
        double max_confidence = 0.0;
        ThreatLevel max_threat_level = ThreatLevel::NONE;
        std::vector<std::wstring> all_factors;
        std::set<std::wstring> unique_files;

        for (const auto& operation : operations) {
            DetectionResult op_result = AnalyzeOperation(operation);

            if (op_result.confidence_score > max_confidence) {
                max_confidence = op_result.confidence_score;
                max_threat_level = op_result.threat_level;
            }

            all_factors.insert(all_factors.end(),
                op_result.contributing_factors.begin(),
                op_result.contributing_factors.end());

            unique_files.insert(operation.file_path);
        }

        // Create comprehensive result
        DetectionResult result;
        result.is_threat = max_threat_level >= ThreatLevel::HIGH;
        result.threat_level = max_threat_level;
        result.confidence_score = max_confidence;
        result.detection_time = std::chrono::steady_clock::now();
        result.affected_files = std::vector<std::wstring>(unique_files.begin(), unique_files.end());

        // Remove duplicate factors
        std::sort(all_factors.begin(), all_factors.end());
        all_factors.erase(std::unique(all_factors.begin(), all_factors.end()), all_factors.end());
        result.contributing_factors = all_factors;

        // Set recommended action based on threat level
        switch (result.threat_level) {
        case ThreatLevel::CRITICAL:
            result.recommended_action = L"IMMEDIATE ACTION: Isolate system and terminate suspicious processes";
            break;
        case ThreatLevel::HIGH:
            result.recommended_action = L"Block file operations and quarantine suspicious files";
            break;
        case ThreatLevel::MEDIUM:
            result.recommended_action = L"Monitor closely and prepare for remediation";
            break;
        case ThreatLevel::LOW:
            result.recommended_action = L"Continue monitoring, log for analysis";
            break;
        default:
            result.recommended_action = L"No action required";
        }

        return result;
    }

    /**
     * @brief Update engine configuration
     */
    void TraditionalEngine::UpdateConfiguration(const EngineConfig& config)
    {
        std::lock_guard<std::mutex> lock(engine_mutex_);

        config_ = config;

        // Update component configurations
        if (scoring_engine_) {
            ScoringEngine::WeightConfiguration weights;
            weights.entropy_weight = config.entropy_weight;
            weights.behavioral_weight = config.behavioral_weight;
            weights.system_activity_weight = config.system_activity_weight;
            scoring_engine_->UpdateWeights(weights);
        }

        if (behavioral_detector_) {
            behavioral_detector_->ConfigureThresholds(
                config.min_operations_for_detection,
                3, 2, 10.0
            );
        }

        std::wcout << L"[TraditionalEngine] Configuration updated" << std::endl;
    }

    /**
     * @brief Get engine statistics
     */
    TraditionalEngine::Statistics TraditionalEngine::GetStatistics() const
    {
        return statistics_;
    }

    /**
     * @brief Get default engine configuration
     */
    TraditionalEngine::EngineConfig TraditionalEngine::GetDefaultConfig()
    {
        EngineConfig config;

        // Entropy analysis settings
        config.enable_entropy_analysis = true;
        config.entropy_weight = 0.30;

        // Behavioral detection settings
        config.enable_behavioral_detection = true;
        config.behavioral_weight = 0.25;
        config.min_operations_for_detection = 50;

        // System monitoring settings
        config.enable_system_monitoring = true;
        config.system_activity_weight = 0.25;

        // General settings
        config.max_file_size_for_analysis = 100 * 1024 * 1024; // 100MB
        config.analysis_thread_count = 4;
        config.enable_false_positive_reduction = true;
        config.enable_detailed_logging = true;

        return config;
    }

    /**
     * @brief Load configuration from file
     */
    TraditionalEngine::EngineConfig TraditionalEngine::LoadConfiguration(const std::wstring& config_file)
    {
        try {
            std::ifstream file(config_file);
            if (!file.is_open()) {
                return GetDefaultConfig();
            }

            nlohmann::json j;
            file >> j;

            EngineConfig config;

            // Parse entropy settings
            if (j.contains("entropy_analysis")) {
                auto& ea = j["entropy_analysis"];
                config.enable_entropy_analysis = ea.value("enabled", true);
                config.entropy_weight = ea.value("weight", 0.30);
            }

            // Parse behavioral settings
            if (j.contains("behavioral_detection")) {
                auto& bd = j["behavioral_detection"];
                config.enable_behavioral_detection = bd.value("enabled", true);
                config.behavioral_weight = bd.value("weight", 0.25);
                config.min_operations_for_detection = bd.value("min_operations", 50);
            }

            // Parse system monitoring settings
            if (j.contains("system_monitoring")) {
                auto& sm = j["system_monitoring"];
                config.enable_system_monitoring = sm.value("enabled", true);
                config.system_activity_weight = sm.value("weight", 0.25);
            }

            // Parse general settings
            if (j.contains("general")) {
                auto& g = j["general"];
                config.max_file_size_for_analysis = g.value("max_file_size", 104857600);
                config.analysis_thread_count = g.value("thread_count", 4);
                config.enable_false_positive_reduction = g.value("false_positive_reduction", true);
                config.enable_detailed_logging = g.value("detailed_logging", true);
            }

            return config;
        }
        catch (const std::exception& e) {
            std::wcerr << L"[TraditionalEngine] Failed to load config: " << e.what() << std::endl;
            return GetDefaultConfig();
        }
    }

    /**
     * @brief Perform entropy analysis
     */
    double TraditionalEngine::PerformEntropyAnalysis(const FileOperation& operation)
    {
        if (!entropy_analyzer_) {
            return 0.0;
        }

        // Skip if no entropy change data
        if (operation.entropy_before == 0.0 && operation.entropy_after == 0.0) {
            return 0.0;
        }

        // Detect file type
        FileType file_type = FileTypeDetector::DetectFileType(operation.file_path);

        // Get adaptive threshold
        auto analyzer = entropy_analyzer_->shannon_analyzer_.get();
        double threshold = analyzer->GetAdaptiveThreshold(file_type);

        // Calculate suspicion based on entropy change
        double entropy_delta = std::abs(operation.entropy_after - operation.entropy_before);
        double suspicion_score = 0.0;

        // High entropy after modification is suspicious
        if (operation.entropy_after > threshold) {
            suspicion_score += 0.6;
        }

        // Large entropy increase is very suspicious
        if (entropy_delta > 2.0 && operation.entropy_after > operation.entropy_before) {
            suspicion_score += 0.4;
        }

        return std::min(suspicion_score, 1.0);
    }

    /**
     * @brief Perform behavioral analysis
     */
    double TraditionalEngine::PerformBehavioralAnalysis(const std::vector<FileOperation>& operations)
    {
        if (!behavioral_detector_ || operations.empty()) {
            return 0.0;
        }

        // Convert to behavioral detector format
        std::vector<CryptoShield::FileOperationInfo> detector_ops;
        for (const auto& op : operations) {
            CryptoShield::FileOperationInfo info;
            info.process_id = op.process_id;
            info.file_path = op.file_path;
            info.type = static_cast<CryptoShield::FileOperationType>(op.operation_type);

            // Convert timestamp
            auto time_since_epoch = op.timestamp.time_since_epoch();
            auto seconds = std::chrono::duration_cast<std::chrono::seconds>(time_since_epoch);
            info.timestamp.dwLowDateTime = static_cast<DWORD>(seconds.count() & 0xFFFFFFFF);
            info.timestamp.dwHighDateTime = static_cast<DWORD>((seconds.count() >> 32) & 0xFFFFFFFF);

            detector_ops.push_back(info);
        }

        // Analyze with behavioral detector
        auto result = behavioral_detector_->AnalyzeBatch(detector_ops);
        return result.confidence_score;
    }

    /**
     * @brief Perform system activity analysis
     */
    double TraditionalEngine::PerformSystemAnalysis(ULONG process_id)
    {
        if (!system_monitor_) {
            return 0.0;
        }

        // Get system activity score for process
        return system_monitor_->GetProcessSuspicionScore(process_id);
    }

    /**
     * @brief Combine analysis results
     */
    DetectionResult TraditionalEngine::CombineAnalysisResults(double entropy_score,
        double behavioral_score,
        double system_score,
        const FileOperation& operation)
    {
        DetectionResult result;
        result.detection_time = std::chrono::steady_clock::now();
        result.process_id = operation.process_id;

        // Calculate weighted score
        double total_weight = config_.entropy_weight +
            config_.behavioral_weight +
            config_.system_activity_weight +
            0.2; // temporal weight

        double weighted_score = (entropy_score * config_.entropy_weight +
            behavioral_score * config_.behavioral_weight +
            system_score * config_.system_activity_weight) / total_weight;

        result.confidence_score = weighted_score;
        result.threat_level = ClassifyThreatLevel(weighted_score);
        result.is_threat = result.threat_level >= ThreatLevel::HIGH;

        // Add contributing factors
        if (entropy_score > 0.5) {
            result.contributing_factors.push_back(L"High entropy detected");
        }
        if (behavioral_score > 0.5) {
            result.contributing_factors.push_back(L"Suspicious file operation patterns");
        }
        if (system_score > 0.5) {
            result.contributing_factors.push_back(L"Suspicious system activity");
        }

        // Set threat name based on pattern matching
        if (result.is_threat && pattern_database_) {
            result.primary_threat_name = pattern_database_->MatchPattern(
                result.contributing_factors
            );
        }

        return result;
    }

    /**
     * @brief Classify threat level based on score
     */
    ThreatLevel TraditionalEngine::ClassifyThreatLevel(double confidence_score) const
    {
        if (confidence_score >= 0.95) return ThreatLevel::CRITICAL;
        if (confidence_score >= 0.80) return ThreatLevel::HIGH;
        if (confidence_score >= 0.60) return ThreatLevel::MEDIUM;
        if (confidence_score >= 0.30) return ThreatLevel::LOW;
        return ThreatLevel::NONE;
    }

    /**
     * @brief Apply false positive reduction
     */
    DetectionResult TraditionalEngine::ApplyFalsePositiveReduction(const DetectionResult& result)
    {
        // TODO: Implement false positive reduction logic
        // For now, return original result
        return result;
    }

    /**
     * @brief Update internal statistics
     */
    void TraditionalEngine::UpdateStatistics(const DetectionResult& result,
        std::chrono::microseconds analysis_time)
    {
        statistics_.operations_analyzed++;

        if (result.is_threat) {
            statistics_.threats_detected++;
        }

        // Update average analysis time
        double current_avg = statistics_.average_analysis_time_ms;
        double new_time = analysis_time.count() / 1000.0; // Convert to ms
        statistics_.average_analysis_time_ms =
            (current_avg * (statistics_.operations_analyzed - 1) + new_time) /
            statistics_.operations_analyzed;

        // Update average confidence score
        double current_conf = statistics_.average_confidence_score;
        statistics_.average_confidence_score =
            (current_conf * (statistics_.operations_analyzed - 1) + result.confidence_score) /
            statistics_.operations_analyzed;
    }

} // namespace CryptoShield::Detection