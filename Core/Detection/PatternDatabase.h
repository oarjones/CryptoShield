#pragma once
/**
 * @file PatternDatabase.h
 * @brief Pattern database for known ransomware families and behaviors
 * @details Stores and matches patterns for ransomware identification
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>      // Incluir ANTES de otras cabeceras
#include <fltuser.h>

#pragma once

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
     * @brief Pattern type enumeration
     */
    enum class PatternType {
        FILE_EXTENSION,      // Known ransomware file extensions
        FILE_NAME,          // Ransom note filenames
        PROCESS_NAME,       // Known ransomware process names
        MUTEX_NAME,         // Mutex names used by ransomware
        REGISTRY_KEY,       // Registry keys/values
        COMMAND_LINE,       // Command line patterns
        NETWORK_IOC,        // Network indicators
        BEHAVIOR_SEQUENCE   // Behavioral sequences
    };

    /**
     * @brief Pattern matching mode
     */
    enum class MatchMode {
        EXACT,              // Exact string match
        SUBSTRING,          // Substring match
        REGEX,              // Regular expression match
        WILDCARD,           // Wildcard pattern (* and ?)
        FUZZY               // Fuzzy matching with threshold
    };

    /**
     * @brief Pattern confidence level
     */
    enum class PatternConfidence {
        LOW = 1,            // Weak indicator
        MEDIUM = 2,         // Moderate indicator
        HIGH = 3,           // Strong indicator
        CRITICAL = 4        // Definitive indicator
    };

    /**
     * @brief Individual pattern entry
     */
    struct RansomwarePattern {
        std::wstring pattern_id;
        PatternType type;
        std::wstring pattern_value;
        MatchMode match_mode;
        PatternConfidence confidence;
        std::wstring family_name;
        std::wstring variant_name;
        std::wstring description;
        std::chrono::system_clock::time_point first_seen;
        std::chrono::system_clock::time_point last_updated;
        size_t hit_count;
        bool is_active;
        double false_positive_rate;
        std::vector<std::wstring> related_patterns;
    };

    /**
     * @brief Pattern match result
     */
    struct PatternMatch {
        std::wstring pattern_id;
        std::wstring matched_value;
        PatternType pattern_type;
        double match_score;
        PatternConfidence confidence;
        std::wstring family_name;
        std::wstring variant_name;
        std::chrono::steady_clock::time_point match_time;
        std::wstring context;  // Additional context about the match
    };

    /**
     * @brief Behavioral sequence pattern
     */
    struct BehaviorSequence {
        std::wstring sequence_id;
        std::wstring family_name;
        std::vector<std::wstring> required_behaviors;
        std::vector<std::wstring> optional_behaviors;
        std::chrono::milliseconds max_time_window;
        size_t min_behaviors_required;
        PatternConfidence confidence;
        std::wstring description;
    };

    /**
     * @brief Pattern database statistics
     */
    struct DatabaseStatistics {
        size_t total_patterns;
        size_t active_patterns;
        std::map<PatternType, size_t> patterns_by_type;
        std::map<std::wstring, size_t> patterns_by_family;
        size_t total_matches;
        std::chrono::system_clock::time_point last_update;
        double average_match_time_ms;
    };

    /**
     * @brief Pattern update information
     */
    struct PatternUpdate {
        std::vector<RansomwarePattern> new_patterns;
        std::vector<std::wstring> removed_pattern_ids;
        std::vector<RansomwarePattern> updated_patterns;
        std::chrono::system_clock::time_point update_timestamp;
        std::wstring update_source;
        std::wstring update_version;
    };

    /**
     * @brief Main pattern database class
     * @details Manages ransomware pattern storage and matching
     */
    class PatternDatabase {
    public:
        /**
         * @brief Constructor
         */
        PatternDatabase();

        /**
         * @brief Destructor
         */
        ~PatternDatabase();

        // Disable copy
        PatternDatabase(const PatternDatabase&) = delete;
        PatternDatabase& operator=(const PatternDatabase&) = delete;

        /**
         * @brief Initialize database with default patterns
         * @return true on success
         */
        bool Initialize();

        /**
         * @brief Load patterns from file
         * @param database_file Path to pattern database file
         * @return true on success
         */
        bool LoadPatterns(const std::wstring& database_file);

        /**
         * @brief Save patterns to file
         * @param database_file Path to save database
         * @return true on success
         */
        bool SavePatterns(const std::wstring& database_file) const;

        /**
         * @brief Add new pattern to database
         * @param pattern Pattern to add
         * @return Pattern ID if successful
         */
        std::optional<std::wstring> AddPattern(const RansomwarePattern& pattern);

        /**
         * @brief Remove pattern from database
         * @param pattern_id Pattern ID to remove
         * @return true if pattern was removed
         */
        bool RemovePattern(const std::wstring& pattern_id);

        /**
         * @brief Update existing pattern
         * @param pattern Updated pattern data
         * @return true if pattern was updated
         */
        bool UpdatePattern(const RansomwarePattern& pattern);

        /**
         * @brief Match value against patterns
         * @param value Value to match
         * @param type Pattern type to match against
         * @return Vector of matches
         */
        std::vector<PatternMatch> MatchPattern(const std::wstring& value,
            PatternType type) const;

        /**
         * @brief Match multiple values against patterns
         * @param values Values to match
         * @param type Pattern type to match against
         * @return Vector of all matches
         */
        std::vector<PatternMatch> MatchPatterns(const std::vector<std::wstring>& values,
            PatternType type) const;

        /**
         * @brief Match against all pattern types
         * @param value Value to match
         * @return Vector of matches from all pattern types
         */
        std::vector<PatternMatch> MatchAllTypes(const std::wstring& value) const;

        /**
         * @brief Match behavioral sequence
         * @param behaviors Observed behaviors
         * @param time_window Time window of observations
         * @return Matched sequences
         */
        std::vector<std::wstring> MatchBehaviorSequence(
            const std::vector<std::wstring>& behaviors,
            std::chrono::milliseconds time_window) const;

        /**
         * @brief Get patterns by family
         * @param family_name Ransomware family name
         * @return Vector of patterns for the family
         */
        std::vector<RansomwarePattern> GetPatternsByFamily(
            const std::wstring& family_name) const;

        /**
         * @brief Get patterns by type
         * @param type Pattern type
         * @return Vector of patterns of the specified type
         */
        std::vector<RansomwarePattern> GetPatternsByType(PatternType type) const;

        /**
         * @brief Get pattern by ID
         * @param pattern_id Pattern ID
         * @return Pattern if found
         */
        std::optional<RansomwarePattern> GetPattern(const std::wstring& pattern_id) const;

        /**
         * @brief Get all known ransomware families
         * @return Set of family names
         */
        std::set<std::wstring> GetKnownFamilies() const;

        /**
         * @brief Update pattern hit count
         * @param pattern_id Pattern that was matched
         */
        void UpdateHitCount(const std::wstring& pattern_id);

        /**
         * @brief Get database statistics
         * @return Current statistics
         */
        DatabaseStatistics GetStatistics() const;

        /**
         * @brief Apply pattern updates
         * @param update Update information
         * @return true if update was successful
         */
        bool ApplyUpdate(const PatternUpdate& update);

        /**
         * @brief Clear all patterns
         */
        void Clear();

        /**
         * @brief Get patterns that need review (high FP rate)
         * @param fp_threshold False positive rate threshold
         * @return Patterns exceeding threshold
         */
        std::vector<RansomwarePattern> GetPatternsNeedingReview(
            double fp_threshold = 0.1) const;

        /**
         * @brief Search patterns by description
         * @param search_term Search term
         * @return Matching patterns
         */
        std::vector<RansomwarePattern> SearchPatterns(
            const std::wstring& search_term) const;

    private:
        /**
         * @brief Initialize default patterns
         */
        void InitializeDefaultPatterns();

        /**
         * @brief Initialize known file extensions
         */
        void InitializeFileExtensions();

        /**
         * @brief Initialize ransom note patterns
         */
        void InitializeRansomNotePatterns();

        /**
         * @brief Initialize process name patterns
         */
        void InitializeProcessPatterns();

        /**
         * @brief Initialize command line patterns
         */
        void InitializeCommandLinePatterns();

        /**
         * @brief Initialize behavior sequences
         */
        void InitializeBehaviorSequences();

        /**
         * @brief Perform exact match
         * @param value Value to match
         * @param pattern Pattern to match against
         * @return Match score (0 or 1)
         */
        double PerformExactMatch(const std::wstring& value,
            const std::wstring& pattern) const;

        /**
         * @brief Perform substring match
         * @param value Value to match
         * @param pattern Pattern to match against
         * @return Match score (0 or 1)
         */
        double PerformSubstringMatch(const std::wstring& value,
            const std::wstring& pattern) const;

        /**
         * @brief Perform regex match
         * @param value Value to match
         * @param pattern Regex pattern
         * @return Match score (0 or 1)
         */
        double PerformRegexMatch(const std::wstring& value,
            const std::wstring& pattern) const;

        /**
         * @brief Perform wildcard match
         * @param value Value to match
         * @param pattern Wildcard pattern
         * @return Match score (0 or 1)
         */
        double PerformWildcardMatch(const std::wstring& value,
            const std::wstring& pattern) const;

        /**
         * @brief Perform fuzzy match
         * @param value Value to match
         * @param pattern Pattern to match against
         * @return Match score (0-1)
         */
        double PerformFuzzyMatch(const std::wstring& value,
            const std::wstring& pattern) const;

        /**
         * @brief Calculate Levenshtein distance
         * @param s1 First string
         * @param s2 Second string
         * @return Edit distance
         */
        size_t LevenshteinDistance(const std::wstring& s1,
            const std::wstring& s2) const;

        /**
         * @brief Generate unique pattern ID
         * @return Unique ID string
         */
        std::wstring GeneratePatternId() const;

        /**
         * @brief Validate pattern
         * @param pattern Pattern to validate
         * @return true if valid
         */
        bool ValidatePattern(const RansomwarePattern& pattern) const;

        /**
         * @brief Update statistics after match
         * @param match_time Time taken for match
         */
        void UpdateMatchStatistics(std::chrono::microseconds match_time);

    private:
        // Pattern storage
        mutable std::mutex patterns_mutex_;
        std::map<std::wstring, RansomwarePattern> patterns_;
        std::multimap<PatternType, std::wstring> patterns_by_type_;
        std::multimap<std::wstring, std::wstring> patterns_by_family_;

        // Behavior sequences
        mutable std::mutex sequences_mutex_;
        std::map<std::wstring, BehaviorSequence> behavior_sequences_;

        // Compiled regex cache
        mutable std::mutex regex_cache_mutex_;
        mutable std::map<std::wstring, std::wregex> regex_cache_;

        // Statistics
        mutable std::mutex stats_mutex_;
        DatabaseStatistics statistics_;

        // Configuration
        static constexpr double FUZZY_MATCH_THRESHOLD = 0.8;
        static constexpr size_t MAX_REGEX_CACHE_SIZE = 100;
        static constexpr size_t MAX_PATTERN_LENGTH = 1024;

        // Pattern ID counter
        mutable std::atomic<uint64_t> pattern_id_counter_;
    };

    /**
     * @brief Pattern matching engine
     * @details Optimized pattern matching with caching
     */
    class PatternMatcher {
    public:
        /**
         * @brief Match multiple patterns efficiently
         * @param values Values to match
         * @param patterns Patterns to match against
         * @return All matches found
         */
        static std::vector<PatternMatch> BatchMatch(
            const std::vector<std::wstring>& values,
            const std::vector<RansomwarePattern>& patterns);

        /**
         * @brief Optimize pattern order for matching
         * @param patterns Patterns to optimize
         * @return Reordered patterns for efficiency
         */
        static std::vector<RansomwarePattern> OptimizePatternOrder(
            const std::vector<RansomwarePattern>& patterns);

        /**
         * @brief Preprocess patterns for faster matching
         * @param patterns Patterns to preprocess
         * @return Preprocessed pattern data
         */
        static std::map<std::wstring, std::wstring> PreprocessPatterns(
            const std::vector<RansomwarePattern>& patterns);
    };

} // namespace CryptoShield::Detection