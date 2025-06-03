/**
 * @file ScoringEngine.cpp
 * @brief Multi-criteria scoring system implementation
 * @details Implements threat scoring with configurable weights and false positive reduction
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */
#define NOMINMAX
#include "ScoringEngine.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <iomanip>
#include "EntropyAnalyzer.h"
#include "BehavioralDetector.h"
#include "SystemActivityMonitor.h"

namespace CryptoShield::Detection {

    // Static member definitions
    const std::map<ThreatLevel, std::wstring> ScoringEngine::THREAT_LEVEL_NAMES = {
        {ThreatLevel::NONE, L"None"},
        {ThreatLevel::LOW, L"Low"},
        {ThreatLevel::MEDIUM, L"Medium"},
        {ThreatLevel::HIGH, L"High"},
        {ThreatLevel::CRITICAL, L"Critical"}
    };

    const std::vector<std::wstring> ScoringEngine::KNOWN_THREAT_FAMILIES = {
        L"WannaCry", L"Locky", L"Cerber", L"CryptoLocker", L"CryptoWall",
        L"TeslaCrypt", L"Ryuk", L"Sodinokibi", L"GandCrab", L"Dharma",
        L"Maze", L"REvil", L"Conti", L"LockBit", L"BlackCat"
    };

    /**
     * @brief Validate weights sum to 1.0
     */
    bool WeightConfiguration::IsValid() const
    {
        double sum = entropy_weight + behavioral_weight +
            system_activity_weight + temporal_weight;
        return std::abs(sum - 1.0) < 0.001;
    }

    /**
     * @brief Normalize weights to sum to 1.0
     */
    void WeightConfiguration::Normalize()
    {
        double sum = entropy_weight + behavioral_weight +
            system_activity_weight + temporal_weight;
        if (sum > 0) {
            entropy_weight /= sum;
            behavioral_weight /= sum;
            system_activity_weight /= sum;
            temporal_weight /= sum;
        }
    }

    /**
     * @brief Constructor
     */
    ScoringEngine::ScoringEngine(const ScoringEngineConfig& config)
        : config_(config)
        , statistics_{}
    {
        // Initialize weights
        weights_.entropy_weight = config.entropy_weight;
        weights_.behavioral_weight = config.behavioral_weight;
        weights_.system_activity_weight = config.system_activity_weight;
        weights_.temporal_weight = config.temporal_weight;
        weights_.Normalize();

        // Initialize threat patterns
        threat_patterns_[L"WannaCry"] = {
            "wncry", "wcry", "wanacry", ".wnry", "tasksche.exe"
        };
        threat_patterns_[L"Locky"] = {
            ".locky", ".odin", ".shit", ".thor", ".aesir", ".zzzzz"
        };
        threat_patterns_[L"Cerber"] = {
            ".cerber", "cerber", "_READ_THIS_FILE_", "# DECRYPT MY FILES #"
        };
        // Add more patterns as needed
    }

    /**
     * @brief Destructor
     */
    ScoringEngine::~ScoringEngine() = default;

    /**
     * @brief Analyze comprehensively using all available data
     */
    ComprehensiveAnalysis ScoringEngine::AnalyzeComprehensively(
        const EntropyAnalysisResult& entropy_result,
        const BehavioralAnalysisResult& behavioral_result,
        const SystemActivitySummary& system_result,
        const std::vector<FileOperation>& recent_operations)
    {
        auto start_time = std::chrono::steady_clock::now();

        ComprehensiveAnalysis analysis;
        analysis.analysis_timestamp = start_time;

        // Calculate individual component scores
        analysis.entropy_score = CalculateEntropyScore(entropy_result);
        analysis.behavioral_score = CalculateBehavioralScore(behavioral_result);
        analysis.system_activity_score = CalculateSystemActivityScore(system_result);
        analysis.temporal_score = CalculateTemporalScore(recent_operations);

        // Combine scores
        auto [overall_score, overall_confidence] = CombineScores(
            analysis.entropy_score,
            analysis.behavioral_score,
            analysis.system_activity_score,
            analysis.temporal_score
        );

        analysis.overall_score = overall_score;
        analysis.overall_confidence = overall_confidence;

        // Extract contributing factors
        analysis.contributing_factors = ExtractContributingFactors(
            analysis.entropy_score,
            analysis.behavioral_score,
            analysis.system_activity_score,
            analysis.temporal_score
        );

        // Apply confidence boosting if enabled
        if (config_.enable_confidence_boosting &&
            analysis.contributing_factors.size() >= 3) {
            auto [boosted_score, boosted_confidence] = ApplyConfidenceBoosting(
                overall_score,
                overall_confidence,
                analysis.contributing_factors
            );
            analysis.overall_score = boosted_score;
            analysis.overall_confidence = boosted_confidence;
        }

        // Classify threat level
        analysis.threat_level = ClassifyThreatLevel(analysis.overall_score);

        // Get threat classification
        ThreatClassification classification = ClassifyThreat(analysis);
        analysis.primary_threat_name = classification.family;
        analysis.threat_families = MatchThreatPatterns(analysis);

        // Generate recommended action
        analysis.recommended_action = GenerateRecommendedAction(
            analysis.threat_level,
            classification
        );

        // Apply false positive reduction if enabled
        if (config_.enable_false_positive_reduction) {
            analysis = ApplyFalsePositiveReduction(analysis);
        }

        // Generate explanations if enabled
        if (config_.enable_detailed_explanation) {
            analysis.summary = GenerateSummary(analysis);
            analysis.detailed_explanation = GenerateDetailedExplanation(analysis);
        }

        // Set affected files and process ID
        if (!recent_operations.empty()) {
            analysis.primary_process_id = recent_operations.front().process_id;

            std::set<std::wstring> unique_files;
            for (const auto& op : recent_operations) {
                unique_files.insert(op.file_path);
            }
            analysis.affected_files = std::vector<std::wstring>(
                unique_files.begin(), unique_files.end()
            );
        }

        // Calculate analysis duration
        auto end_time = std::chrono::steady_clock::now();
        analysis.analysis_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time
        );

        // Update statistics
        UpdateStatistics(analysis, analysis.analysis_duration);

        return analysis;
    }

    /**
     * @brief Update weight configuration
     */
    void ScoringEngine::UpdateWeights(const WeightConfiguration& weights)
    {
        weights_ = weights;
        weights_.Normalize();
    }

    /**
     * @brief Get current weight configuration
     */
    WeightConfiguration ScoringEngine::GetWeights() const
    {
        return weights_;
    }

    /**
     * @brief Update engine configuration
     */
    void ScoringEngine::UpdateConfiguration(const ScoringEngineConfig& config)
    {
        config_ = config;

        // Update weights from config
        weights_.entropy_weight = config.entropy_weight;
        weights_.behavioral_weight = config.behavioral_weight;
        weights_.system_activity_weight = config.system_activity_weight;
        weights_.temporal_weight = config.temporal_weight;
        weights_.Normalize();
    }

    /**
     * @brief Classify threat level based on score
     */
    ThreatLevel ScoringEngine::ClassifyThreatLevel(double overall_score) const
    {
        if (overall_score >= config_.threshold_critical) {
            return ThreatLevel::CRITICAL;
        }
        else if (overall_score >= config_.threshold_high) {
            return ThreatLevel::HIGH;
        }
        else if (overall_score >= config_.threshold_medium) {
            return ThreatLevel::MEDIUM;
        }
        else if (overall_score >= config_.threshold_low) {
            return ThreatLevel::LOW;
        }
        else {
            return ThreatLevel::NONE;
        }
    }

    /**
     * @brief Get detailed threat classification
     */
    ThreatClassification ScoringEngine::ClassifyThreat(const ComprehensiveAnalysis& analysis) const
    {
        ThreatClassification classification;
        classification.level = analysis.threat_level;
        classification.confidence = analysis.overall_confidence;

        // Determine category based on behavior
        if (analysis.system_activity_score.raw_score > 0.7) {
            if (analysis.behavioral_score.indicators.size() > 0 &&
                std::any_of(analysis.behavioral_score.indicators.begin(),
                    analysis.behavioral_score.indicators.end(),
                    [](const std::string& s) {
                        return s.find("deletion") != std::string::npos;
                    })) {
                classification.category = L"Wiper";
            }
            else {
                classification.category = L"Crypto";
            }
        }
        else if (analysis.behavioral_score.raw_score > 0.8) {
            classification.category = L"Locker";
        }
        else {
            classification.category = L"Unknown";
        }

        // Try to identify family
        classification.family = L"Unknown";
        for (const auto& family : analysis.threat_families) {
            if (!family.empty()) {
                classification.family = family;
                break;
            }
        }

        // Add behavioral matches
        for (const auto& factor : analysis.contributing_factors) {
            classification.behavioral_matches.push_back(factor);
        }

        return classification;
    }

    /**
     * @brief Generate recommended action
     */
    std::wstring ScoringEngine::GenerateRecommendedAction(
        ThreatLevel threat_level,
        const ThreatClassification& classification) const
    {
        switch (threat_level) {
        case ThreatLevel::CRITICAL:
            return L"IMMEDIATE ACTION REQUIRED: Isolate system, terminate process, "
                L"initiate incident response, backup critical data if possible";

        case ThreatLevel::HIGH:
            return L"HIGH PRIORITY: Block file operations, quarantine suspicious files, "
                L"alert administrators, prepare for remediation";

        case ThreatLevel::MEDIUM:
            return L"ELEVATED ALERT: Monitor closely, restrict process privileges, "
                L"capture forensic data, prepare containment measures";

        case ThreatLevel::LOW:
            return L"MONITORING: Continue observation, log all activities, "
                L"collect behavioral data for analysis";

        case ThreatLevel::NONE:
        default:
            return L"No immediate action required - continue normal monitoring";
        }
    }

    /**
     * @brief Get default configuration
     */
    ScoringEngineConfig ScoringEngine::GetDefaultConfig()
    {
        ScoringEngineConfig config;

        // Weights
        config.entropy_weight = 0.30;
        config.behavioral_weight = 0.25;
        config.system_activity_weight = 0.25;
        config.temporal_weight = 0.20;

        // Thresholds
        config.threshold_low = 0.30;
        config.threshold_medium = 0.60;
        config.threshold_high = 0.80;
        config.threshold_critical = 0.95;

        // Options
        config.enable_false_positive_reduction = true;
        config.false_positive_weight = 0.15;
        config.enable_detailed_explanation = true;
        config.enable_confidence_boosting = true;
        config.confidence_boost_threshold = 0.8;

        return config;
    }

    /**
     * @brief Get engine statistics
     */
    ScoringEngine::Statistics ScoringEngine::GetStatistics() const
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        return statistics_;
    }

    /**
     * @brief Calculate entropy component score
     */
    ComponentScore ScoringEngine::CalculateEntropyScore(const EntropyAnalysisResult& result) const
    {
        ComponentScore score;
        score.component_name = "Entropy Analysis";
        score.timestamp = std::chrono::steady_clock::now();

        // Base score from entropy analysis
        score.raw_score = 0.0;
        if (result.is_high_entropy) {
            score.raw_score += 0.6;
            score.indicators.push_back("High entropy detected");
        }

        if (result.is_random_distribution) {
            score.raw_score += 0.3;
            score.indicators.push_back("Random byte distribution");
        }

        // Hamming distance indicates significant change
        if (result.hamming_distance > 0.7) {
            score.raw_score += 0.1;
            score.indicators.push_back("High Hamming distance");
        }

        // Calculate confidence
        score.confidence = result.confidence_score;

        // Apply weight
        score.weighted_score = score.raw_score * weights_.entropy_weight;

        return score;
    }

    /**
     * @brief Calculate behavioral component score
     */
    ComponentScore ScoringEngine::CalculateBehavioralScore(
        const BehavioralAnalysisResult& result) const
    {
        ComponentScore score;
        score.component_name = "Behavioral Analysis";
        score.timestamp = std::chrono::steady_clock::now();

        // Base score from behavioral analysis
        score.raw_score = result.confidence_score;

        // Add indicators
        for (const auto& pattern : result.suspicious_patterns) {
            score.indicators.push_back(std::string(pattern.begin(), pattern.end()));
        }

        // Boost score for multiple suspicious patterns
        if (result.suspicious_patterns.size() >= 3) {
            score.raw_score = std::min(score.raw_score + 0.1, 1.0);
        }

        // High operation rate is very suspicious
        if (result.operations_per_second > 50) {
            score.raw_score = std::min(score.raw_score + 0.2, 1.0);
            score.indicators.push_back("Extremely high operation rate");
        }

        score.confidence = result.is_suspicious ? 0.8 : 0.3;
        score.weighted_score = score.raw_score * weights_.behavioral_weight;

        return score;
    }

    /**
     * @brief Calculate system activity score
     */
    ComponentScore ScoringEngine::CalculateSystemActivityScore(
        const SystemActivitySummary& result) const
    {
        ComponentScore score;
        score.component_name = "System Activity";
        score.timestamp = std::chrono::steady_clock::now();

        // Shadow deletion is highly suspicious
        if (result.shadow_deletion_attempts > 0) {
            score.raw_score += 0.4;
            score.indicators.push_back("Shadow copy deletion attempts");
        }

        // Boot config changes
        if (result.boot_config_changes > 0) {
            score.raw_score += 0.3;
            score.indicators.push_back("Boot configuration changes");
        }

        // Registry modifications
        if (result.registry_modifications > 10) {
            score.raw_score += 0.2;
            score.indicators.push_back("Multiple registry modifications");
        }

        // Security bypass attempts
        if (result.security_bypass_attempts > 0) {
            score.raw_score += 0.1;
            score.indicators.push_back("Security bypass attempts");
        }

        score.raw_score = std::min(score.raw_score, 1.0);
        score.confidence = result.overall_system_threat_score;
        score.weighted_score = score.raw_score * weights_.system_activity_weight;

        return score;
    }

    /**
     * @brief Calculate temporal pattern score
     */
    ComponentScore ScoringEngine::CalculateTemporalScore(
        const std::vector<FileOperation>& operations) const
    {
        ComponentScore score;
        score.component_name = "Temporal Analysis";
        score.timestamp = std::chrono::steady_clock::now();

        if (operations.empty()) {
            score.raw_score = 0.0;
            score.confidence = 0.0;
            score.weighted_score = 0.0;
            return score;
        }

        // Analyze temporal patterns
        TemporalPattern pattern = AnalyzeTemporalPatterns(operations);

        // Automated behavior is suspicious
        if (pattern.automated_behavior_detected) {
            score.raw_score += 0.4;
            score.indicators.push_back("Automated behavior detected");
        }

        // High burst score
        if (pattern.burst_score > 0.7) {
            score.raw_score += 0.3;
            score.indicators.push_back("Burst activity pattern");
        }

        // High regularity (machine-like)
        if (pattern.regularity_score > 0.8) {
            score.raw_score += 0.2;
            score.indicators.push_back("Machine-like regularity");
        }

        // Acceleration pattern
        if (pattern.acceleration_score > 0.5) {
            score.raw_score += 0.1;
            score.indicators.push_back("Accelerating activity");
        }

        score.raw_score = std::min(score.raw_score, 1.0);
        score.confidence = 0.7;  // Temporal analysis confidence
        score.weighted_score = score.raw_score * weights_.temporal_weight;

        return score;
    }

    /**
     * @brief Analyze temporal patterns
     */
    TemporalPattern ScoringEngine::AnalyzeTemporalPatterns(
        const std::vector<FileOperation>& operations) const
    {
        TemporalPattern pattern = {};

        if (operations.size() < 2) {
            return pattern;
        }

        pattern.pattern_start = operations.front().timestamp;
        pattern.pattern_end = operations.back().timestamp;

        // Calculate operation rate
        auto duration = pattern.pattern_end - pattern.pattern_start;
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        pattern.operations_per_second = seconds > 0 ?
            static_cast<double>(operations.size()) / seconds : 0.0;

        // Calculate inter-operation intervals
        std::vector<double> intervals;
        for (size_t i = 1; i < operations.size(); ++i) {
            auto interval = operations[i].timestamp - operations[i - 1].timestamp;
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(interval).count();
            intervals.push_back(static_cast<double>(ms));
        }

        if (!intervals.empty()) {
            // Calculate regularity (low variance = high regularity)
            double mean = std::accumulate(intervals.begin(), intervals.end(), 0.0) / intervals.size();
            double variance = 0.0;
            for (double interval : intervals) {
                variance += (interval - mean) * (interval - mean);
            }
            variance /= intervals.size();
            double std_dev = std::sqrt(variance);

            // High regularity if std dev is low relative to mean
            pattern.regularity_score = mean > 0 ? 1.0 - std::min(std_dev / mean, 1.0) : 0.0;

            // Detect bursts (many operations with very short intervals)
            size_t burst_count = 0;
            for (double interval : intervals) {
                if (interval < 100) {  // Less than 100ms
                    burst_count++;
                }
            }
            pattern.burst_score = static_cast<double>(burst_count) / intervals.size();

            // Detect acceleration (intervals getting shorter)
            size_t accelerating = 0;
            for (size_t i = 1; i < intervals.size(); ++i) {
                if (intervals[i] < intervals[i - 1]) {
                    accelerating++;
                }
            }
            pattern.acceleration_score = static_cast<double>(accelerating) / (intervals.size() - 1);

            // Automated behavior detection
            pattern.automated_behavior_detected =
                pattern.regularity_score > 0.8 &&
                pattern.operations_per_second > 10;
        }

        return pattern;
    }

    /**
     * @brief Combine component scores
     */
    std::pair<double, double> ScoringEngine::CombineScores(
        const ComponentScore& entropy,
        const ComponentScore& behavioral,
        const ComponentScore& system,
        const ComponentScore& temporal) const
    {
        // Calculate weighted sum
        double overall_score = entropy.weighted_score +
            behavioral.weighted_score +
            system.weighted_score +
            temporal.weighted_score;

        // Calculate combined confidence
        std::vector<double> confidences = {
            entropy.confidence,
            behavioral.confidence,
            system.confidence,
            temporal.confidence
        };

        std::vector<double> weights = {
            weights_.entropy_weight,
            weights_.behavioral_weight,
            weights_.system_activity_weight,
            weights_.temporal_weight
        };

        double overall_confidence = ConfidenceCalculator::CalculateCombinedConfidence(
            confidences, weights
        );

        return { overall_score, overall_confidence };
    }

    /**
     * @brief Apply confidence boosting
     */
    std::pair<double, double> ScoringEngine::ApplyConfidenceBoosting(
        double score,
        double confidence,
        const std::vector<std::wstring>& factors) const
    {
        double boosted_score = score;
        double boosted_confidence = confidence;

        // Multiple indicators boost
        if (factors.size() >= 3) {
            boosted_score = std::min(boosted_score + MULTIPLE_INDICATORS_BOOST, 1.0);
            boosted_confidence = std::min(boosted_confidence + 0.05, 1.0);
        }

        // Critical indicator boost
        bool has_critical = false;
        for (const auto& factor : factors) {
            if (factor.find(L"Shadow copy deletion") != std::wstring::npos ||
                factor.find(L"Security bypass") != std::wstring::npos ||
                factor.find(L"Boot configuration") != std::wstring::npos) {
                has_critical = true;
                break;
            }
        }

        if (has_critical) {
            boosted_score = std::min(boosted_score + CRITICAL_INDICATOR_BOOST, 1.0);
        }

        return { boosted_score, boosted_confidence };
    }

    /**
     * @brief Apply false positive reduction
     */
    ComprehensiveAnalysis ScoringEngine::ApplyFalsePositiveReduction(
        const ComprehensiveAnalysis& analysis) const
    {
        // This is a simplified implementation
        // In production, would integrate with FalsePositiveMinimizer
        ComprehensiveAnalysis adjusted = analysis;

        // Check for common false positive scenarios
        bool likely_false_positive = false;
        std::wstring fp_reason;

        // Very low confidence with medium score might be FP
        if (analysis.overall_confidence < 0.5 &&
            analysis.overall_score >= 0.5 &&
            analysis.overall_score < 0.7) {
            likely_false_positive = true;
            fp_reason = L"Low confidence with medium score";
            adjusted.overall_score *= (1.0 - config_.false_positive_weight);
        }

        // Single indicator with no system activity
        if (analysis.contributing_factors.size() == 1 &&
            analysis.system_activity_score.raw_score == 0) {
            likely_false_positive = true;
            fp_reason = L"Single indicator without system activity";
            adjusted.overall_score *= 0.7;
        }

        adjusted.likely_false_positive = likely_false_positive;
        adjusted.false_positive_probability = likely_false_positive ? 0.6 : 0.1;
        adjusted.false_positive_reason = fp_reason;

        // Reclassify threat level if needed
        if (adjusted.overall_score != analysis.overall_score) {
            adjusted.threat_level = ClassifyThreatLevel(adjusted.overall_score);
        }

        return adjusted;
    }

    /**
     * @brief Generate detailed explanation
     */
    std::wstring ScoringEngine::GenerateDetailedExplanation(
        const ComprehensiveAnalysis& analysis) const
    {
        std::wstringstream explanation;

        explanation << L"=== DETAILED THREAT ANALYSIS ===" << std::endl;
        explanation << L"Analysis Time: " << analysis.analysis_duration.count() << L"ms" << std::endl;
        explanation << L"Overall Score: " << std::fixed << std::setprecision(2)
            << analysis.overall_score << L" (Confidence: "
            << analysis.overall_confidence << L")" << std::endl;
        explanation << L"Threat Level: " << THREAT_LEVEL_NAMES.at(analysis.threat_level) << std::endl;

        if (!analysis.primary_threat_name.empty()) {
            explanation << L"Suspected Threat: " << analysis.primary_threat_name << std::endl;
        }

        explanation << std::endl << L"=== COMPONENT ANALYSIS ===" << std::endl;

        // Entropy Analysis
        explanation << L"\nEntropy Analysis:" << std::endl;
        explanation << L"  Score: " << analysis.entropy_score.raw_score
            << L" (Weight: " << weights_.entropy_weight << L")" << std::endl;
        for (const auto& indicator : analysis.entropy_score.indicators) {
            explanation << L"  - " << std::wstring(indicator.begin(), indicator.end()) << std::endl;
        }

        // Behavioral Analysis
        explanation << L"\nBehavioral Analysis:" << std::endl;
        explanation << L"  Score: " << analysis.behavioral_score.raw_score
            << L" (Weight: " << weights_.behavioral_weight << L")" << std::endl;
        for (const auto& indicator : analysis.behavioral_score.indicators) {
            explanation << L"  - " << std::wstring(indicator.begin(), indicator.end()) << std::endl;
        }

        // System Activity
        explanation << L"\nSystem Activity:" << std::endl;
        explanation << L"  Score: " << analysis.system_activity_score.raw_score
            << L" (Weight: " << weights_.system_activity_weight << L")" << std::endl;
        for (const auto& indicator : analysis.system_activity_score.indicators) {
            explanation << L"  - " << std::wstring(indicator.begin(), indicator.end()) << std::endl;
        }

        // Temporal Analysis
        explanation << L"\nTemporal Analysis:" << std::endl;
        explanation << L"  Score: " << analysis.temporal_score.raw_score
            << L" (Weight: " << weights_.temporal_weight << L")" << std::endl;
        for (const auto& indicator : analysis.temporal_score.indicators) {
            explanation << L"  - " << std::wstring(indicator.begin(), indicator.end()) << std::endl;
        }

        // Contributing Factors
        explanation << std::endl << L"=== CONTRIBUTING FACTORS ===" << std::endl;
        for (const auto& factor : analysis.contributing_factors) {
            explanation << L"• " << factor << std::endl;
        }

        // False Positive Analysis
        if (analysis.likely_false_positive) {
            explanation << std::endl << L"=== FALSE POSITIVE ANALYSIS ===" << std::endl;
            explanation << L"Likely False Positive: YES" << std::endl;
            explanation << L"Probability: " << analysis.false_positive_probability << std::endl;
            explanation << L"Reason: " << analysis.false_positive_reason << std::endl;
        }

        // Recommendations
        explanation << std::endl << L"=== RECOMMENDED ACTION ===" << std::endl;
        explanation << analysis.recommended_action << std::endl;

        return explanation.str();
    }

    /**
     * @brief Generate summary
     */
    std::wstring ScoringEngine::GenerateSummary(const ComprehensiveAnalysis& analysis) const
    {
        std::wstringstream summary;

        summary << L"Threat Level: " << THREAT_LEVEL_NAMES.at(analysis.threat_level)
            << L" | Score: " << std::fixed << std::setprecision(2)
            << analysis.overall_score
            << L" | Confidence: " << analysis.overall_confidence;

        if (!analysis.primary_threat_name.empty() &&
            analysis.primary_threat_name != L"Unknown") {
            summary << L" | Suspected: " << analysis.primary_threat_name;
        }

        if (analysis.likely_false_positive) {
            summary << L" | *Possible False Positive*";
        }

        return summary.str();
    }

    /**
     * @brief Extract contributing factors
     */
    std::vector<std::wstring> ScoringEngine::ExtractContributingFactors(
        const ComponentScore& entropy,
        const ComponentScore& behavioral,
        const ComponentScore& system,
        const ComponentScore& temporal) const
    {
        std::vector<std::wstring> factors;

        // Add high-scoring component factors
        if (entropy.raw_score > 0.5) {
            for (const auto& indicator : entropy.indicators) {
                factors.push_back(L"[Entropy] " +
                    std::wstring(indicator.begin(), indicator.end()));
            }
        }

        if (behavioral.raw_score > 0.5) {
            for (const auto& indicator : behavioral.indicators) {
                factors.push_back(L"[Behavior] " +
                    std::wstring(indicator.begin(), indicator.end()));
            }
        }

        if (system.raw_score > 0.5) {
            for (const auto& indicator : system.indicators) {
                factors.push_back(L"[System] " +
                    std::wstring(indicator.begin(), indicator.end()));
            }
        }

        if (temporal.raw_score > 0.5) {
            for (const auto& indicator : temporal.indicators) {
                factors.push_back(L"[Temporal] " +
                    std::wstring(indicator.begin(), indicator.end()));
            }
        }

        return factors;
    }

    /**
     * @brief Match threat patterns
     */
    std::vector<std::wstring> ScoringEngine::MatchThreatPatterns(
        const ComprehensiveAnalysis& analysis) const
    {
        std::vector<std::wstring> matched_families;

        // Convert contributing factors to searchable strings
        std::string combined_factors;
        for (const auto& factor : analysis.contributing_factors) {
            combined_factors += std::string(factor.begin(), factor.end()) + " ";
        }

        // Convert to lowercase for matching
        std::transform(combined_factors.begin(), combined_factors.end(),
            combined_factors.begin(), ::tolower);

        // Check each threat pattern
        for (const auto& [family, patterns] : threat_patterns_) {
            for (const auto& pattern : patterns) {
                if (combined_factors.find(pattern) != std::string::npos) {
                    matched_families.push_back(family);
                    break;
                }
            }
        }

        // Remove duplicates
        std::sort(matched_families.begin(), matched_families.end());
        matched_families.erase(
            std::unique(matched_families.begin(), matched_families.end()),
            matched_families.end()
        );

        return matched_families;
    }

    /**
     * @brief Update statistics
     */
    void ScoringEngine::UpdateStatistics(const ComprehensiveAnalysis& analysis,
        std::chrono::milliseconds duration)
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);

        statistics_.total_analyses++;

        if (analysis.threat_level >= ThreatLevel::HIGH) {
            statistics_.threats_detected++;
        }

        statistics_.threat_level_distribution[analysis.threat_level]++;

        // Update average analysis time
        double current_avg = statistics_.average_analysis_time_ms;
        double new_time = static_cast<double>(duration.count());
        statistics_.average_analysis_time_ms =
            (current_avg * (statistics_.total_analyses - 1) + new_time) /
            statistics_.total_analyses;

        // Update average confidence
        double current_conf = statistics_.average_confidence_score;
        statistics_.average_confidence_score =
            (current_conf * (statistics_.total_analyses - 1) + analysis.overall_confidence) /
            statistics_.total_analyses;

        if (analysis.likely_false_positive &&
            analysis.overall_score != analysis.overall_score) {  // Score was adjusted
            statistics_.false_positives_prevented++;
        }
    }

    /**
     * @brief Calculate combined confidence
     */
    double ConfidenceCalculator::CalculateCombinedConfidence(
        const std::vector<double>& scores,
        const std::vector<double>& weights)
    {
        if (scores.empty() || weights.empty() || scores.size() != weights.size()) {
            return 0.0;
        }

        // Weighted average
        double weighted_sum = 0.0;
        double weight_sum = 0.0;

        for (size_t i = 0; i < scores.size(); ++i) {
            weighted_sum += scores[i] * weights[i];
            weight_sum += weights[i];
        }

        double base_confidence = weight_sum > 0 ? weighted_sum / weight_sum : 0.0;

        // Adjust based on variance (agreement between components)
        double variance = CalculateConfidenceVariance(scores);

        // Low variance (high agreement) boosts confidence
        if (variance < 0.1) {
            base_confidence = std::min(base_confidence * 1.1, 1.0);
        }
        else if (variance > 0.3) {
            // High variance (disagreement) reduces confidence
            base_confidence *= 0.9;
        }

        return base_confidence;
    }

    /**
     * @brief Calculate confidence variance
     */
    double ConfidenceCalculator::CalculateConfidenceVariance(const std::vector<double>& scores)
    {
        if (scores.size() < 2) {
            return 0.0;
        }

        double mean = std::accumulate(scores.begin(), scores.end(), 0.0) / scores.size();
        double variance = 0.0;

        for (double score : scores) {
            variance += (score - mean) * (score - mean);
        }

        return variance / scores.size();
    }

    /**
     * @brief Adjust confidence based on evidence
     */
    double ConfidenceCalculator::AdjustConfidenceByEvidence(
        double base_confidence,
        size_t evidence_count,
        double evidence_quality)
    {
        // More evidence increases confidence
        double evidence_factor = 1.0 + (evidence_count * 0.05);
        evidence_factor = std::min(evidence_factor, 1.5);

        // Quality of evidence also matters
        double quality_factor = 0.5 + (evidence_quality * 0.5);

        return std::min(base_confidence * evidence_factor * quality_factor, 1.0);
    }

} // namespace CryptoShield::Detection