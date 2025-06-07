#pragma once
/**
 * @file FalsePositiveMinimizer.h
 * @brief False positive reduction system for ransomware detection
 * @details Identifies legitimate software behaviors and adjusts threat scores
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include "TraditionalEngine.h"
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <optional>
#include <chrono>
#include <regex>

namespace CryptoShield::Detection {

    /**
     * @brief Legitimate software category
     */
    enum class SoftwareCategory {
        BACKUP_SOFTWARE,        // Backup and recovery tools
        COMPRESSION_TOOLS,      // ZIP, RAR, 7z tools
        MEDIA_ENCODERS,         // Video/audio encoders
        DEVELOPMENT_TOOLS,      // Compilers, IDEs
        SYSTEM_UTILITIES,       // System maintenance tools
        ANTIVIRUS_SOFTWARE,     // Security software
        CLOUD_SYNC,            // Cloud storage clients
        DATABASE_MANAGEMENT,    // Database tools
        ENCRYPTION_TOOLS,       // Legitimate encryption software
        UNKNOWN                // Unknown category
    };

    /**
     * @brief Legitimate process information
     */
    struct LegitimateProcess {
        std::wstring process_name;
        std::wstring publisher;
        SoftwareCategory category;
        std::vector<std::wstring> known_paths;
        std::vector<std::wstring> allowed_extensions;
        std::vector<std::wstring> typical_behaviors;
        double trust_score;  // 0.0 to 1.0
        bool requires_signature;
        std::chrono::system_clock::time_point last_updated;
    };

    /**
     * @brief Legitimate behavior pattern
     */
    struct LegitimatePattern {
        std::wstring pattern_id;
        std::wstring pattern_name;
        SoftwareCategory category;
        std::vector<std::wstring> required_indicators;
        std::vector<std::wstring> optional_indicators;
        std::vector<std::wstring> excluded_indicators;
        double confidence_threshold;
        size_t min_indicators_required;
        std::wstring description;
    };

    /**
     * @brief False positive analysis result
     */
    struct FalsePositiveAnalysis {
        bool likely_false_positive;
        double false_positive_probability;
        double adjustment_factor;  // Score reduction factor (0-1)
        SoftwareCategory identified_category;
        std::wstring identified_software;
        std::vector<std::wstring> legitimacy_indicators;
        std::vector<std::wstring> suspicious_indicators;
        std::wstring recommendation;
        std::wstring detailed_reason;
    };

    /**
     * @brief Process reputation information
     */
    struct ProcessReputation {
        std::wstring process_name;
        double reputation_score;  // 0.0 (bad) to 1.0 (good)
        size_t total_executions;
        size_t false_positive_count;
        size_t true_positive_count;
        std::chrono::system_clock::time_point first_seen;
        std::chrono::system_clock::time_point last_seen;
        bool is_signed;
        std::wstring signer_name;
    };

    /**
     * @brief Whitelist entry
     */
    struct WhitelistEntry {
        std::wstring entry_id;
        std::wstring process_path;
        std::wstring process_name;
        std::wstring hash_value;  // SHA256
        SoftwareCategory category;
        std::chrono::system_clock::time_point added_date;
        std::chrono::system_clock::time_point expiry_date;
        std::wstring added_by;
        std::wstring reason;
        bool is_active;
    };

    /**
     * @brief False positive minimizer configuration
     */
    struct FalsePositiveMinimizerConfig {
        bool enable_whitelist;
        bool enable_reputation_system;
        bool enable_signature_verification;
        bool enable_behavioral_analysis;
        double min_reputation_score;
        double max_fp_adjustment;
        size_t reputation_history_days;
        bool auto_whitelist_signed;
        bool strict_mode;
    };

    /**
     * @brief Main false positive minimizer class
     * @details Reduces false positives by identifying legitimate software
     */
    class FalsePositiveMinimizer {
    public:
        /**
         * @brief Constructor
         * @param config Configuration settings
         */
        explicit FalsePositiveMinimizer(
            const FalsePositiveMinimizerConfig& config = GetDefaultConfig());

        /**
         * @brief Destructor
         */
        ~FalsePositiveMinimizer();

        // Disable copy
        FalsePositiveMinimizer(const FalsePositiveMinimizer&) = delete;
        FalsePositiveMinimizer& operator=(const FalsePositiveMinimizer&) = delete;

        /**
         * @brief Initialize the minimizer
         * @return true on success
         */
        bool Initialize();

        /**
         * @brief Analyze for false positives
         * @param process_name Process name
         * @param process_path Full path to process
         * @param operations Recent file operations
         * @param original_score Original threat score
         * @return False positive analysis result
         */
        FalsePositiveAnalysis AnalyzeLegitimacy(
            const std::wstring& process_name,
            const std::wstring& process_path,
            const std::vector<FileOperation>& operations,
            double original_score);

        /**
         * @brief Check if process is whitelisted
         * @param process_path Process path
         * @param process_hash Process hash (optional)
         * @return true if whitelisted
         */
        bool IsWhitelisted(const std::wstring& process_path,
            const std::wstring& process_hash = L"") const;

        /**
         * @brief Add process to whitelist
         * @param entry Whitelist entry
         * @return true if added successfully
         */
        bool AddToWhitelist(const WhitelistEntry& entry);

        /**
         * @brief Remove from whitelist
         * @param entry_id Entry ID to remove
         * @return true if removed
         */
        bool RemoveFromWhitelist(const std::wstring& entry_id);

        /**
         * @brief Get process reputation
         * @param process_name Process name
         * @return Process reputation if available
         */
        std::optional<ProcessReputation> GetProcessReputation(
            const std::wstring& process_name) const;

        /**
         * @brief Update process reputation
         * @param process_name Process name
         * @param is_false_positive Whether this was a false positive
         */
        void UpdateReputation(const std::wstring& process_name,
            bool is_false_positive);

        /**
         * @brief Identify software category
         * @param process_name Process name
         * @param operations File operations
         * @return Identified category
         */
        SoftwareCategory IdentifyCategory(
            const std::wstring& process_name,
            const std::vector<FileOperation>& operations) const;

        /**
         * @brief Check if legitimate backup activity
         * @param operations File operations
         * @return true if matches backup patterns
         */
        bool IsLegitimateBackupActivity(
            const std::vector<FileOperation>& operations) const;

        /**
         * @brief Check if legitimate compression activity
         * @param process_name Process name
         * @param operations File operations
         * @return true if matches compression patterns
         */
        bool IsLegitimateCompressionActivity(
            const std::wstring& process_name,
            const std::vector<FileOperation>& operations) const;

        /**
         * @brief Check if legitimate media processing
         * @param operations File operations
         * @return true if matches media processing patterns
         */
        bool IsLegitimateMediaProcessing(
            const std::vector<FileOperation>& operations) const;

        /**
         * @brief Check if legitimate development activity
         * @param process_name Process name
         * @param operations File operations
         * @return true if matches development patterns
         */
        bool IsLegitimateDevActivity(
            const std::wstring& process_name,
            const std::vector<FileOperation>& operations) const;

        /**
         * @brief Verify process signature
         * @param process_path Path to process
         * @return Signer name if signed, empty if unsigned
         */
        std::wstring VerifyProcessSignature(const std::wstring& process_path) const;

        /**
         * @brief Load whitelist from file
         * @param whitelist_file Path to whitelist file
         * @return true on success
         */
        bool LoadWhitelist(const std::wstring& whitelist_file);

        /**
         * @brief Save whitelist to file
         * @param whitelist_file Path to save whitelist
         * @return true on success
         */
        bool SaveWhitelist(const std::wstring& whitelist_file) const;

        /**
         * @brief Clear reputation data older than specified days
         * @param days_to_keep Number of days to keep
         */
        void CleanupOldReputationData(size_t days_to_keep);

        /**
         * @brief Get statistics
         */
        struct Statistics {
            size_t total_analyses;
            size_t false_positives_prevented;
            size_t whitelist_entries;
            size_t reputation_entries;
            std::map<SoftwareCategory, size_t> detections_by_category;
            double average_adjustment_factor;
        };

        Statistics GetStatistics() const;

        /**
         * @brief Get default configuration
         * @return Default config
         */
        static FalsePositiveMinimizerConfig GetDefaultConfig();

        /**
         * @brief Update configuration
         * @param config New configuration
         */
        void UpdateConfiguration(const FalsePositiveMinimizerConfig& config);

    private:
        /**
         * @brief Initialize legitimate process database
         */
        void InitializeLegitimateProcesses();

        /**
         * @brief Initialize legitimate patterns
         */
        void InitializeLegitimatePatterns();

        /**
         * @brief Calculate process reputation score
         * @param process_name Process name
         * @param process_path Process path
         * @return Reputation score (0-1)
         */
        double CalculateReputationScore(const std::wstring& process_name,
            const std::wstring& process_path) const;

        /**
         * @brief Match legitimate pattern
         * @param pattern Pattern to match
         * @param operations File operations
         * @return Match confidence (0-1)
         */
        double MatchLegitimatePattern(const LegitimatePattern& pattern,
            const std::vector<FileOperation>& operations) const;

        /**
         * @brief Analyze file operation patterns
         * @param operations File operations
         * @return Pattern analysis indicators
         */
        std::vector<std::wstring> AnalyzeOperationPatterns(
            const std::vector<FileOperation>& operations) const;

        /**
         * @brief Check for suspicious anomalies
         * @param process_name Process name
         * @param operations File operations
         * @return Suspicious indicators
         */
        std::vector<std::wstring> CheckSuspiciousAnomalies(
            const std::wstring& process_name,
            const std::vector<FileOperation>& operations) const;

        /**
         * @brief Calculate false positive probability
         * @param legitimacy_indicators Positive indicators
         * @param suspicious_indicators Negative indicators
         * @param category Software category
         * @return Probability (0-1)
         */
        double CalculateFalseProbability(
            const std::vector<std::wstring>& legitimacy_indicators,
            const std::vector<std::wstring>& suspicious_indicators,
            SoftwareCategory category) const;

        /**
         * @brief Generate recommendation
         * @param analysis Analysis result
         * @return Recommendation text
         */
        std::wstring GenerateRecommendation(const FalsePositiveAnalysis& analysis) const;

        /**
         * @brief Update statistics
         * @param analysis Completed analysis
         */
        void UpdateStatistics(const FalsePositiveAnalysis& analysis);

    private:
        // Configuration
        FalsePositiveMinimizerConfig config_;

        // Legitimate process database
        mutable std::mutex processes_mutex_;
        std::map<std::wstring, LegitimateProcess> legitimate_processes_;

        // Legitimate patterns
        mutable std::mutex patterns_mutex_;
        std::vector<LegitimatePattern> legitimate_patterns_;

        // Whitelist
        mutable std::mutex whitelist_mutex_;
        std::map<std::wstring, WhitelistEntry> whitelist_;
        std::map<std::wstring, std::wstring> hash_to_path_;  // Hash lookup

        // Reputation system
        mutable std::mutex reputation_mutex_;
        std::map<std::wstring, ProcessReputation> reputation_data_;

        // Statistics
        mutable std::mutex stats_mutex_;
        Statistics statistics_;

        // Known legitimate software
        static const std::vector<std::wstring> BACKUP_SOFTWARE;
        static const std::vector<std::wstring> COMPRESSION_SOFTWARE;
        static const std::vector<std::wstring> MEDIA_SOFTWARE;
        static const std::vector<std::wstring> DEVELOPMENT_SOFTWARE;
        static const std::vector<std::wstring> SYSTEM_SOFTWARE;
        static const std::vector<std::wstring> SECURITY_SOFTWARE;

        // Legitimate file extensions by category
        static const std::map<SoftwareCategory, std::vector<std::wstring>> LEGITIMATE_EXTENSIONS;

        // Trusted publishers
        static const std::vector<std::wstring> TRUSTED_PUBLISHERS;
    };

    /**
     * @brief Utility class for signature verification
     */
    class SignatureVerifier {
    public:
        /**
         * @brief Verify file signature
         * @param file_path Path to file
         * @param signer_name Output signer name
         * @return true if signed and valid
         */
        static bool VerifyFileSignature(const std::wstring& file_path,
            std::wstring& signer_name);

        /**
         * @brief Check if signer is trusted
         * @param signer_name Signer name
         * @return true if trusted
         */
        static bool IsTrustedSigner(const std::wstring& signer_name);

        /**
         * @brief Get certificate chain
         * @param file_path Path to file
         * @return Certificate chain information
         */
        static std::vector<std::wstring> GetCertificateChain(
            const std::wstring& file_path);
    };

} // namespace CryptoShield::Detection