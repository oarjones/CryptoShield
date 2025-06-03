#pragma once
/**
 * @file ScoringEngine.h
 * @brief Multi-criteria scoring system for threat level determination
 * @details Combines entropy, behavioral, and system activity scores with configurable weights
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include "TraditionalEngine.h"
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <optional>
#include <mutex>

namespace CryptoShield::Detection {

    /**
     * @brief Scoring engine configuration
     */
    struct ScoringEngineConfig {
        // Weight configuration
        double entropy_weight;
        double behavioral_weight;
        double system_activity_weight;
        double temporal_weight;

        // Threat level thresholds
        double threshold_low;
        double threshold_medium;
        double threshold_high;
        double threshold_critical;

        // False positive reduction
        bool enable_false_positive_reduction;
        double false_positive_weight;

        // Scoring options
        bool enable_detailed_explanation;
        bool enable_confidence_boosting;
        double confidence_boost_threshold;
    };

    /**
     * @brief Weight configuration for different analysis components
     */
    struct WeightConfiguration {
        double entropy_weight = 0.30;
        double behavioral_weight = 0.25;
        double system_activity_weight = 0.25;
        double temporal_weight = 0.20;

        /**
         * @brief Validate weights sum to 1.0
         * @return true if valid
         */
        bool IsValid() const;

        /**
         * @brief Normalize weights to sum to 1.0
         */
        void Normalize();
    };

    /**
     * @brief Individual component score
     */
    struct ComponentScore {
        double raw_score;
        double weighted_score;
        double confidence;
        std::string component_name;
        std::vector<std::string> indicators;
        std::chrono::steady_clock::time_point timestamp;
    };

    /**
     * @brief Comprehensive threat analysis result
     */
    struct ComprehensiveAnalysis {
        // Individual component scores
        ComponentScore entropy_score;
        ComponentScore behavioral_score;
        ComponentScore system_activity_score;
        ComponentScore temporal_score;

        // Combined results
        double overall_score;
        double overall_confidence;
        ThreatLevel threat_level;

        // Threat information
        std::wstring primary_threat_name;
        std::vector<std::wstring> threat_families;
        std::vector<std::wstring> contributing_factors;

        // Detailed explanation
        std::wstring summary;
        std::wstring detailed_explanation;
        std::vector<std::wstring> evidence_items;

        // Metadata
        std::chrono::steady_clock::time_point analysis_timestamp;
        std::chrono::milliseconds analysis_duration;
        ULONG primary_process_id;
        std::vector<std::wstring> affected_files;
        std::wstring recommended_action;

        // False positive analysis
        bool likely_false_positive;
        double false_positive_probability;
        std::wstring false_positive_reason;
    };

    /**
     * @brief Temporal pattern analysis
     */
    struct TemporalPattern {
        double operations_per_second;
        double burst_score;
        double regularity_score;
        double acceleration_score;
        bool automated_behavior_detected;
        std::chrono::steady_clock::time_point pattern_start;
        std::chrono::steady_clock::time_point pattern_end;
    };

    /**
     * @brief Threat classification
     */
    struct ThreatClassification {
        ThreatLevel level;
        std::wstring category;  // Crypto, Locker, Wiper, etc.
        std::wstring family;    // WannaCry, Ryuk, etc.
        double confidence;
        std::vector<std::wstring> behavioral_matches;
    };

    /**
     * @brief Main scoring engine class
     * @details Coordinates all scoring components and generates final threat assessment
     */
    class ScoringEngine {
    public:
        /**
         * @brief Constructor
         * @param config Engine configuration
         */
        explicit ScoringEngine(const ScoringEngineConfig& config = GetDefaultConfig());

        /**
         * @brief Destructor
         */
        ~ScoringEngine();

        // Disable copy
        ScoringEngine(const ScoringEngine&) = delete;
        ScoringEngine& operator=(const ScoringEngine&) = delete;

        /**
         * @brief Analyze comprehensively using all available data
         * @param entropy_result Entropy analysis result
         * @param behavioral_result Behavioral analysis result
         * @param system_result System activity result
         * @param recent_operations Recent file operations for temporal analysis
         * @return Comprehensive analysis with threat assessment
         */
        ComprehensiveAnalysis AnalyzeComprehensively(
            const EntropyAnalysisResult& entropy_result,
            const BehavioralAnalysisResult& behavioral_result,
            const SystemActivitySummary& system_result,
            const std::vector<FileOperation>& recent_operations
        );

        /**
         * @brief Update weight configuration
         * @param weights New weight configuration
         */
        void UpdateWeights(const WeightConfiguration& weights);

        /**
         * @brief Get current weight configuration
         * @return Current weights
         */
        WeightConfiguration GetWeights() const;

        /**
         * @brief Update engine configuration
         * @param config New configuration
         */
        void UpdateConfiguration(const ScoringEngineConfig& config);

        /**
         * @brief Classify threat level based on score
         * @param overall_score Combined score (0-1)
         * @return Threat level classification
         */
        ThreatLevel ClassifyThreatLevel(double overall_score) const;

        /**
         * @brief Get detailed threat classification
         * @param analysis Comprehensive analysis
         * @return Detailed threat classification
         */
        ThreatClassification ClassifyThreat(const ComprehensiveAnalysis& analysis) const;

        /**
         * @brief Generate recommended action based on threat level
         * @param threat_level Detected threat level
         * @param classification Threat classification
         * @return Recommended action string
         */
        std::wstring GenerateRecommendedAction(ThreatLevel threat_level,
            const ThreatClassification& classification) const;

        /**
         * @brief Get default configuration
         * @return Default scoring engine configuration
         */
        static ScoringEngineConfig GetDefaultConfig();

        /**
         * @brief Get engine statistics
         */
        struct Statistics {
            size_t total_analyses;
            size_t threats_detected;
            std::map<ThreatLevel, size_t> threat_level_distribution;
            double average_analysis_time_ms;
            double average_confidence_score;
            size_t false_positives_prevented;
        };

        Statistics GetStatistics() const;

    private:
        /**
         * @brief Calculate entropy component score
         * @param result Entropy analysis result
         * @return Component score
         */
        ComponentScore CalculateEntropyScore(const EntropyAnalysisResult& result) const;

        /**
         * @brief Calculate behavioral component score
         * @param result Behavioral analysis result
         * @return Component score
         */
        ComponentScore CalculateBehavioralScore(const BehavioralAnalysisResult& result) const;

        /**
         * @brief Calculate system activity score
         * @param result System activity summary
         * @return Component score
         */
        ComponentScore CalculateSystemActivityScore(const SystemActivitySummary& result) const;

        /**
         * @brief Calculate temporal pattern score
         * @param operations Recent file operations
         * @return Component score
         */
        ComponentScore CalculateTemporalScore(const std::vector<FileOperation>& operations) const;

        /**
         * @brief Analyze temporal patterns
         * @param operations File operations
         * @return Temporal pattern analysis
         */
        TemporalPattern AnalyzeTemporalPatterns(const std::vector<FileOperation>& operations) const;

        /**
         * @brief Combine component scores
         * @param entropy Entropy component score
         * @param behavioral Behavioral component score
         * @param system System activity score
         * @param temporal Temporal pattern score
         * @return Overall score and confidence
         */
        std::pair<double, double> CombineScores(const ComponentScore& entropy,
            const ComponentScore& behavioral,
            const ComponentScore& system,
            const ComponentScore& temporal) const;

        /**
         * @brief Apply confidence boosting
         * @param score Original score
         * @param confidence Original confidence
         * @param factors Contributing factors
         * @return Boosted score and confidence
         */
        std::pair<double, double> ApplyConfidenceBoosting(double score,
            double confidence,
            const std::vector<std::wstring>& factors) const;

        /**
         * @brief Apply false positive reduction
         * @param analysis Initial analysis
         * @return Analysis with FP reduction applied
         */
        ComprehensiveAnalysis ApplyFalsePositiveReduction(const ComprehensiveAnalysis& analysis) const;

        /**
         * @brief Generate detailed explanation
         * @param analysis Analysis results
         * @return Detailed explanation text
         */
        std::wstring GenerateDetailedExplanation(const ComprehensiveAnalysis& analysis) const;

        /**
         * @brief Generate summary
         * @param analysis Analysis results
         * @return Summary text
         */
        std::wstring GenerateSummary(const ComprehensiveAnalysis& analysis) const;

        /**
         * @brief Extract contributing factors
         * @param entropy Entropy score
         * @param behavioral Behavioral score
         * @param system System activity score
         * @param temporal Temporal score
         * @return List of contributing factors
         */
        std::vector<std::wstring> ExtractContributingFactors(const ComponentScore& entropy,
            const ComponentScore& behavioral,
            const ComponentScore& system,
            const ComponentScore& temporal) const;

        /**
         * @brief Match threat patterns
         * @param analysis Comprehensive analysis
         * @return Matched threat families
         */
        std::vector<std::wstring> MatchThreatPatterns(const ComprehensiveAnalysis& analysis) const;

        /**
         * @brief Update statistics
         * @param analysis Completed analysis
         * @param duration Analysis duration
         */
        void UpdateStatistics(const ComprehensiveAnalysis& analysis,
            std::chrono::milliseconds duration);

    private:
        // Configuration
        ScoringEngineConfig config_;
        WeightConfiguration weights_;

        // Statistics
        mutable std::mutex stats_mutex_;
        Statistics statistics_;

        // Pattern matching
        std::map<std::wstring, std::vector<std::string>> threat_patterns_;

        // Confidence boosting factors
        static constexpr double MULTIPLE_INDICATORS_BOOST = 0.1;
        static constexpr double HIGH_CONFIDENCE_THRESHOLD = 0.8;
        static constexpr double CRITICAL_INDICATOR_BOOST = 0.15;

        // Threat level names
        static const std::map<ThreatLevel, std::wstring> THREAT_LEVEL_NAMES;

        // Known threat families
        static const std::vector<std::wstring> KNOWN_THREAT_FAMILIES;
    };

    /**
     * @brief Confidence calculator utility
     */
    class ConfidenceCalculator {
    public:
        /**
         * @brief Calculate confidence based on multiple factors
         * @param scores Vector of individual scores
         * @param weights Weights for each score
         * @return Combined confidence (0-1)
         */
        static double CalculateCombinedConfidence(const std::vector<double>& scores,
            const std::vector<double>& weights);

        /**
         * @brief Calculate confidence variance
         * @param scores Vector of scores
         * @return Variance indicating agreement between components
         */
        static double CalculateConfidenceVariance(const std::vector<double>& scores);

        /**
         * @brief Adjust confidence based on evidence strength
         * @param base_confidence Base confidence
         * @param evidence_count Number of evidence items
         * @param evidence_quality Quality score of evidence (0-1)
         * @return Adjusted confidence
         */
        static double AdjustConfidenceByEvidence(double base_confidence,
            size_t evidence_count,
            double evidence_quality);
    };

} // namespace CryptoShield::Detection