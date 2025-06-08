/**
 * @file BehavioralDetector.cpp
 * @brief Behavioral pattern detection implementation
 * @details Implements mass modification, extension change, and traversal detection
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */
#define NOMINMAX
#include "BehavioralDetector.h"
#include <regex> // Added
#include <iostream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <cmath>
#include <numeric>
#include <cwctype> 

namespace CryptoShield::Detection {

    // Static member definitions
    // const std::vector<std::wstring> FileExtensionMonitor::RANSOMWARE_EXTENSIONS = { ... }; // DELETE THIS
    // const std::vector<std::wstring> FileExtensionMonitor::SUSPICIOUS_PATTERNS = { ... }; // DELETE THIS

    /**
     * @brief Constructor
     */
    MassFileModificationDetector::MassFileModificationDetector(const Configuration& config)
        : config_(config)
    {
        current_window_.start_time = std::chrono::steady_clock::now();
        last_cleanup_ = current_window_.start_time;
    }

    /**
     * @brief Analyze file operation
     */
    BehavioralAnalysisResult MassFileModificationDetector::AnalyzeOperation(
        const FileOperationInfo& operation)
    {
        std::lock_guard<std::mutex> lock(window_mutex_);

        // Clean up old operations if window expired
        auto now = std::chrono::steady_clock::now();
        if (now - current_window_.start_time > config_.window_duration) {
            ResetWindow();
            current_window_.start_time = now;
        }

        // Add operation to current window
        current_window_.operations.push_back(operation);

        // Update statistics
        std::wstring directory = ExtractDirectory(operation.file_path);
        std::wstring extension = ExtractExtension(operation.file_path);

        current_window_.affected_directories.insert(directory);
        if (!extension.empty()) {
            current_window_.file_extensions.insert(extension);
        }
        current_window_.process_operation_count[operation.process_id]++;

        // Calculate suspicion score
        double suspicion_score = CalculateSuspicionScore();

        // Build result
        BehavioralAnalysisResult result;
        result.is_suspicious = suspicion_score >= config_.suspicion_score_threshold;
        result.confidence_score = suspicion_score;
        result.operations_count = current_window_.operations.size();
        result.directories_affected = current_window_.affected_directories.size();
        result.extensions_affected = current_window_.file_extensions.size();

        // Calculate operations per second
        auto duration = now - current_window_.start_time;
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        result.operations_per_second = seconds > 0 ?
            static_cast<double>(result.operations_count) / seconds : 0.0;

        // Build description
        std::wstringstream desc;
        desc << L"Operations: " << result.operations_count
            << L", Directories: " << result.directories_affected
            << L", Extensions: " << result.extensions_affected
            << L", Rate: " << std::fixed << std::setprecision(2)
            << result.operations_per_second << L" ops/sec";
        result.description = desc.str();

        // Add suspicious patterns
        if (IsRapidEncryptionPattern()) {
            result.suspicious_patterns.push_back(L"Rapid encryption-like pattern");
        }
        if (IsWideSpreadModification()) {
            result.suspicious_patterns.push_back(L"Widespread file modification");
        }

        return result;
    }

    /**
     * @brief Reset detection window
     */
    void MassFileModificationDetector::ResetWindow()
    {
        current_window_.operations.clear();
        current_window_.affected_directories.clear();
        current_window_.file_extensions.clear();
        current_window_.process_operation_count.clear();
        current_window_.start_time = std::chrono::steady_clock::now();
    }

    /**
     * @brief Update configuration
     */
    void MassFileModificationDetector::UpdateConfiguration(const Configuration& config)
    {
        std::lock_guard<std::mutex> lock(window_mutex_);
        config_ = config;
    }

    /**
     * @brief Get current window statistics
     */
    MassFileModificationDetector::WindowStatistics
        MassFileModificationDetector::GetWindowStatistics() const
    {
        std::lock_guard<std::mutex> lock(window_mutex_);

        WindowStatistics stats;
        stats.operation_count = current_window_.operations.size();
        stats.directory_count = current_window_.affected_directories.size();
        stats.extension_count = current_window_.file_extensions.size();
        stats.window_start = current_window_.start_time;
        stats.window_end = std::chrono::steady_clock::now();

        auto duration = stats.window_end - stats.window_start;
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        stats.operations_per_second = seconds > 0 ?
            static_cast<double>(stats.operation_count) / seconds : 0.0;

        return stats;
    }

    /**
     * @brief Calculate suspicion score
     */
    double MassFileModificationDetector::CalculateSuspicionScore() const
    {
        double score = 0.0;

        // Factor 1: Operation count (0-0.3)
        if (current_window_.operations.size() >= config_.min_operations_threshold) {
            score += 0.3 * std::min(
                static_cast<double>(current_window_.operations.size()) /
                (config_.min_operations_threshold * 2), 1.0
            );
        }

        // Factor 2: Directory spread (0-0.3)
        if (current_window_.affected_directories.size() >= config_.min_directories_threshold) {
            score += 0.3 * std::min(
                static_cast<double>(current_window_.affected_directories.size()) /
                (config_.min_directories_threshold * 3), 1.0
            );
        }

        // Factor 3: Extension variety (0-0.2)
        if (current_window_.file_extensions.size() >= config_.min_extensions_threshold) {
            score += 0.2 * std::min(
                static_cast<double>(current_window_.file_extensions.size()) /
                (config_.min_extensions_threshold * 5), 1.0
            );
        }

        // Factor 4: Operation rate (0-0.2)
        auto duration = std::chrono::steady_clock::now() - current_window_.start_time;
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        if (seconds > 0) {
            double rate = static_cast<double>(current_window_.operations.size()) / seconds;
            if (rate > config_.max_operations_per_second) {
                score += 0.2 * std::min(rate / (config_.max_operations_per_second * 2), 1.0);
            }
        }

        return score;
    }

    /**
     * @brief Check if pattern matches rapid encryption
     */
    bool MassFileModificationDetector::IsRapidEncryptionPattern() const
    {
        if (current_window_.operations.size() < config_.min_operations_threshold) {
            return false;
        }

        // Check for high write/rename ratio
        size_t writes = 0, renames = 0;
        for (const auto& op : current_window_.operations) {
            if (op.type == FileOperationType::Write) writes++;
            else if (op.type == FileOperationType::Rename) renames++;
        }

        double write_ratio = static_cast<double>(writes) / current_window_.operations.size();
        double rename_ratio = static_cast<double>(renames) / current_window_.operations.size();

        return (write_ratio > 0.4 && rename_ratio > 0.2) ||
            (write_ratio > 0.6) ||
            (rename_ratio > 0.4);
    }

    /**
     * @brief Check if modifications are widespread
     */
    bool MassFileModificationDetector::IsWideSpreadModification() const
    {
        return current_window_.affected_directories.size() >= config_.min_directories_threshold &&
            current_window_.file_extensions.size() >= config_.min_extensions_threshold;
    }

    /**
     * @brief Extract directory from file path
     */
    std::wstring MassFileModificationDetector::ExtractDirectory(const std::wstring& file_path) const
    {
        size_t last_slash = file_path.find_last_of(L"\\");
        if (last_slash != std::wstring::npos) {
            return file_path.substr(0, last_slash);
        }
        return L"";
    }

    /**
     * @brief Extract file extension
     */
    std::wstring MassFileModificationDetector::ExtractExtension(const std::wstring& file_path) const
    {
        size_t last_dot = file_path.find_last_of(L".");
        if (last_dot != std::wstring::npos && last_dot < file_path.length() - 1) {
            return file_path.substr(last_dot);
        }
        return L"";
    }

    /**
     * @brief Constructor
     */
    FileExtensionMonitor::FileExtensionMonitor(const CryptoShield::Detection::DetectionEngineConfig::BehavioralConfig& config)
        : config_(config) {
        // Constructor body, if any
    }

    /**
     * @brief Analyze file rename operation
     */
    ExtensionChangeEvent FileExtensionMonitor::AnalyzeFileRename(
        const std::wstring& old_path,
        const std::wstring& new_path,
        ULONG process_id)
    {
        ExtensionChangeEvent event;
        event.file_path = old_path;
        event.timestamp = std::chrono::steady_clock::now();
        event.process_id = process_id;

        // Extract extensions
        size_t old_dot = old_path.find_last_of(L".");
        size_t new_dot = new_path.find_last_of(L".");

        if (old_dot != std::wstring::npos) {
            event.original_extension = old_path.substr(old_dot);
        }
        if (new_dot != std::wstring::npos) {
            event.new_extension = new_path.substr(new_dot);
        }

        // Calculate suspicion score
        event.suspicion_score = CalculateExtensionSuspicion(event.new_extension);
        event.is_suspicious = event.suspicion_score > 0.5;

        // Track original extension
        {
            std::lock_guard<std::mutex> lock(extensions_mutex_);
            original_extensions_[new_path] = event.original_extension;
        }

        // Store event
        {
            std::lock_guard<std::mutex> lock(changes_mutex_);
            extension_changes_.push_back(event);

            // Keep only recent events (last 10000)
            if (extension_changes_.size() > 10000) {
                extension_changes_.erase(extension_changes_.begin());
            }
        }

        return event;
    }

    /**
     * @brief Calculate extension suspicion score
     */
    double FileExtensionMonitor::CalculateExtensionSuspicion(const std::wstring& extension) const
    {
        if (extension.empty()) {
            return 0.0;
        }

        // Convert to lowercase for comparison
        std::wstring lower_ext = extension;
        std::transform(lower_ext.begin(), lower_ext.end(), lower_ext.begin(), ::towlower);

        // Check if it's a known ransomware extension
        if (IsKnownRansomwareExtension(lower_ext)) {
            return 1.0;
        }

        // Check if it matches suspicious patterns
        if (MatchesSuspiciousPattern(lower_ext)) {
            return 0.8;
        }

        // Check for unusual characteristics
        double score = 0.0;

        // Long extensions are suspicious
        if (extension.length() > 10) {
            score += 0.3;
        }

        // Multiple dots are suspicious
        size_t dot_count = std::count(extension.begin(), extension.end(), L'.');
        if (dot_count > 1) {
            score += 0.2;
        }

        // Extensions with numbers are somewhat suspicious
        if (std::any_of(extension.begin(), extension.end(), ::iswdigit)) {
            score += 0.1;
        }

        // Random-looking extensions (high entropy) are suspicious
        std::set<wchar_t> unique_chars(extension.begin(), extension.end());
        double char_ratio = static_cast<double>(unique_chars.size()) / extension.length();
        if (char_ratio > 0.8) {
            score += 0.2;
        }

        return std::min(score, 1.0);
    }

    /**
     * @brief Check if extension is known ransomware indicator
     */
    bool FileExtensionMonitor::IsKnownRansomwareExtension(const std::wstring& extension) const
    {
        return std::find(config_.suspicious_extensions.begin(), config_.suspicious_extensions.end(), extension) != config_.suspicious_extensions.end();
    }

    /**
     * @brief Get recent extension changes
     */
    std::vector<ExtensionChangeEvent> FileExtensionMonitor::GetRecentChanges(
        std::chrono::seconds max_age) const
    {
        std::lock_guard<std::mutex> lock(changes_mutex_);

        auto now = std::chrono::steady_clock::now();
        std::vector<ExtensionChangeEvent> recent;

        for (const auto& event : extension_changes_) {
            if (now - event.timestamp <= max_age) {
                recent.push_back(event);
            }
        }

        return recent;
    }

    /**
     * @brief Clear old extension change records
     */
    void FileExtensionMonitor::CleanupOldRecords(std::chrono::seconds max_age)
    {
        std::lock_guard<std::mutex> lock(changes_mutex_);

        auto now = std::chrono::steady_clock::now();
        extension_changes_.erase(
            std::remove_if(extension_changes_.begin(), extension_changes_.end(),
                [&](const ExtensionChangeEvent& event) {
                    return now - event.timestamp > max_age;
                }),
            extension_changes_.end()
        );
    }

    /**
     * @brief Check if extension matches suspicious pattern
     */
    bool FileExtensionMonitor::MatchesSuspiciousPattern(const std::wstring& extension) const {
        if (config_.suspicious_patterns_regex.empty()) {
            // Fallback to old logic or return false if no regex patterns are configured
            // For now, let's keep the old logic as a fallback if regex list is empty.
            // This part can be adjusted based on desired behavior.
            // Check for email-like patterns
            if (extension.find(L'@') != std::wstring::npos) {
                return true;
            }
            // Check for brackets
            if (extension.find(L'[') != std::wstring::npos ||
                extension.find(L']') != std::wstring::npos) {
                return true;
            }
            // Check for hex-only extensions (simple check)
            if (extension.length() > 4 && extension.length() < 10) { // Typical short hex-like strings
                 bool all_hex_like = true;
                 int hex_chars = 0;
                 for (wchar_t c : extension) {
                    if (c == L'.') continue;
                    if (!std::iswxdigit(c)) {
                        all_hex_like = false;
                        break;
                    }
                    hex_chars++;
                 }
                 if (all_hex_like && hex_chars > 3) return true; // e.g. .abcd, .1234
            }
            return false;
        }
        for (const auto& pattern_str : config_.suspicious_patterns_regex) {
            try {
                std::wregex pattern_regex(pattern_str);
                if (std::regex_match(extension, pattern_regex)) {
                    return true;
                }
            } catch (const std::regex_error& e) {
                 std::wcerr << L"Regex error in FileExtensionMonitor for pattern '" << pattern_str
                           << L"': " << e.what() << std::endl;
                // Potentially skip this pattern or handle error as appropriate
            }
        }
        return false;
    }

    /**
     * @brief Constructor
     */
    DirectoryTraversalDetector::DirectoryTraversalDetector()
    {
    }

    /**
     * @brief Analyze file operation for traversal patterns
     */
    void DirectoryTraversalDetector::AnalyzeOperation(
        const FileOperationInfo& operation, ULONG process_id)
    {
        std::lock_guard<std::mutex> lock(traversal_mutex_);

        // Extract directory
        //size_t last_slash = operation.file_path.find_last_of(L"\\");
        size_t last_slash = std::wstring(operation.file_path).find_last_of(L"\\");
        if (last_slash == std::wstring::npos) {
            return;
        }

        //std::wstring directory = operation.file_path.substr(0, last_slash);
        std::wstring directory = std::wstring(operation.file_path).substr(0, last_slash);

        // Update process traversal info
        auto& info = process_traversals_[process_id];

        if (info.visited_directories.empty()) {
            info.first_access = std::chrono::steady_clock::now();
            info.root_directory = directory;
        }

        info.visited_directories.insert(directory);
        info.last_access = std::chrono::steady_clock::now();
        info.files_affected++;

        // Update max depth
        size_t depth = CalculateDirectoryDepth(directory);
        info.max_depth = std::max(info.max_depth, depth);
    }

    /**
     * @brief Get traversal pattern for process
     */
    std::optional<DirectoryTraversalPattern> DirectoryTraversalDetector::GetTraversalPattern(
        ULONG process_id) const
    {
        std::lock_guard<std::mutex> lock(traversal_mutex_);

        auto it = process_traversals_.find(process_id);
        if (it == process_traversals_.end()) {
            return std::nullopt;
        }

        const auto& info = it->second;

        DirectoryTraversalPattern pattern;
        pattern.root_directory = FindCommonRoot(info.visited_directories);
        pattern.traversed_directories = std::vector<std::wstring>(
            info.visited_directories.begin(),
            info.visited_directories.end()
        );
        pattern.depth = info.max_depth;
        pattern.is_recursive = info.max_depth > 2 && info.visited_directories.size() > 5;
        pattern.start_time = info.first_access;
        pattern.end_time = info.last_access;
        pattern.files_affected = info.files_affected;

        return pattern;
    }

    /**
     * @brief Check if process shows recursive traversal
     */
    bool DirectoryTraversalDetector::IsRecursiveTraversal(ULONG process_id) const
    {
        auto pattern = GetTraversalPattern(process_id);
        return pattern.has_value() && pattern->is_recursive;
    }

    /**
     * @brief Calculate traversal suspicion score
     */
    double DirectoryTraversalDetector::CalculateTraversalSuspicion(
        const DirectoryTraversalPattern& pattern) const
    {
        double score = 0.0;

        // Factor 1: Depth (0-0.3)
        if (pattern.depth > 3) {
            score += 0.3 * std::min(pattern.depth / 10.0, 1.0);
        }

        // Factor 2: Directory count (0-0.3)
        if (pattern.traversed_directories.size() > 10) {
            score += 0.3 * std::min(pattern.traversed_directories.size() / 50.0, 1.0);
        }

        // Factor 3: Files affected (0-0.2)
        if (pattern.files_affected > 100) {
            score += 0.2 * std::min(pattern.files_affected / 1000.0, 1.0);
        }

        // Factor 4: Speed (0-0.2)
        auto duration = pattern.end_time - pattern.start_time;
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        if (seconds > 0 && pattern.files_affected > 0) {
            double files_per_second = static_cast<double>(pattern.files_affected) / seconds;
            if (files_per_second > 10) {
                score += 0.2 * std::min(files_per_second / 50.0, 1.0);
            }
        }

        return score;
    }

    /**
     * @brief Clear traversal data for process
     */
    void DirectoryTraversalDetector::ClearProcessData(ULONG process_id)
    {
        std::lock_guard<std::mutex> lock(traversal_mutex_);
        process_traversals_.erase(process_id);
    }

    /**
     * @brief Calculate directory depth
     */
    size_t DirectoryTraversalDetector::CalculateDirectoryDepth(const std::wstring& directory) const
    {
        return std::count(directory.begin(), directory.end(), L'\\');
    }

    /**
     * @brief Find common root directory
     */
    std::wstring DirectoryTraversalDetector::FindCommonRoot(
        const std::set<std::wstring>& directories) const
    {
        if (directories.empty()) {
            return L"";
        }

        // Start with the first directory
        std::wstring common = *directories.begin();

        // Find common prefix with all other directories
        for (const auto& dir : directories) {
            size_t i = 0;
            while (i < common.length() && i < dir.length() && common[i] == dir[i]) {
                i++;
            }
            common = common.substr(0, i);
        }

        // Trim to last complete directory
        size_t last_slash = common.find_last_of(L"\\");
        if (last_slash != std::wstring::npos) {
            common = common.substr(0, last_slash);
        }

        return common;
    }

    /**
     * @brief Constructor
     */
    BehavioralDetector::BehavioralDetector(const CryptoShield::Detection::DetectionEngineConfig::BehavioralConfig& config)
        : config_(config), // Initialize the member
          total_operations_analyzed_(0),
          suspicious_patterns_detected_(0) {
        // Initialize detection components
        // Pass the behavioral config to MassFileModificationDetector if its constructor/config method changes
        // For now, assuming MassFileModificationDetector uses its own struct which might be set via ConfigureThresholds
        // or if it directly uses parts of BehavioralConfig, it will access it via config_ passed to its methods or if BehavioralDetector calls a specific config method on it.
        // The existing ConfigureThresholds in BehavioralDetector seems to handle this for MassFileModificationDetector.
        mass_modification_detector_ = std::make_unique<MassFileModificationDetector>(); // This might also need config

        // Pass the behavioral config to FileExtensionMonitor
        extension_monitor_ = std::make_unique<FileExtensionMonitor>(config_);

        traversal_detector_ = std::make_unique<DirectoryTraversalDetector>();

        // ConfigureThresholds might be called later by TraditionalEngine or similar, using the main config.
        // For now, ensure sub-components are constructed correctly.
        // If MassFileModificationDetector's `Configuration` struct is derived from `BehavioralConfig` or can be set by it,
        // then it should be done here or via a method call.
        // The current `BehavioralDetector::ConfigureThresholds` method updates `config_` of type `MassFileModificationDetector::Configuration`
        // This means the main `config_` of `BehavioralDetector` (which is now `BehavioralConfig`) should be used to set that.
        // This part might need adjustment if `MassFileModificationDetector` is to be configured from `BehavioralConfig` directly at construction or via a new method.
        // However, the prompt focuses on passing `BehavioralConfig` to `BehavioralDetector` and `FileExtensionMonitor`.
        // The existing `BehavioralDetector::ConfigureThresholds` method will need to be updated to use `config_.min_operations_threshold` etc. from the new `config_` member.
        // For now, only constructor changes are made as per immediate instructions.
    }

    /**
     * @brief Destructor
     */
    BehavioralDetector::~BehavioralDetector() = default;

    /**
     * @brief Analyze single file operation
     */
    BehavioralAnalysisResult BehavioralDetector::AnalyzeOperation(
        const FileOperationInfo& operation)
    {
        total_operations_analyzed_++;

        // Update process profile
        UpdateProcessProfile(operation);

        // Mass modification detection
        auto mass_result = mass_modification_detector_->AnalyzeOperation(operation);

        // Directory traversal detection
        traversal_detector_->AnalyzeOperation(operation, operation.process_id);

        // Extension monitoring for rename operations
        if (operation.type == FileOperationType::Rename) {
            // Note: Need old path from somewhere - this is simplified
            extension_monitor_->AnalyzeFileRename(
                operation.file_path,
                operation.file_path + std::wstring(L".encrypted"),
                operation.process_id
            );
        }

        // Get process profile
        ProcessBehaviorProfile profile;
        {
            std::lock_guard<std::mutex> lock(profiles_mutex_);
            profile = process_profiles_[operation.process_id];
        }

        // Calculate combined score
        double combined_score = CalculateCombinedScore(profile);

        // Build result
        BehavioralAnalysisResult result = mass_result;
        result.confidence_score = combined_score;
        result.is_suspicious = combined_score > 0.6;

        if (result.is_suspicious) {
            suspicious_patterns_detected_++;
        }

        return result;
    }

    /**
     * @brief Analyze batch of operations
     */
    BehavioralAnalysisResult BehavioralDetector::AnalyzeBatch(
        const std::vector<FileOperationInfo>& operations)
    {
        BehavioralAnalysisResult result;

        if (operations.empty()) {
            return result;
        }

        // Analyze each operation
        double max_score = 0.0;
        for (const auto& op : operations) {
            auto op_result = AnalyzeOperation(op);
            max_score = std::max(max_score, op_result.confidence_score);

            // Merge suspicious patterns
            result.suspicious_patterns.insert(
                result.suspicious_patterns.end(),
                op_result.suspicious_patterns.begin(),
                op_result.suspicious_patterns.end()
            );
        }

        // Remove duplicates
        std::sort(result.suspicious_patterns.begin(), result.suspicious_patterns.end());
        result.suspicious_patterns.erase(
            std::unique(result.suspicious_patterns.begin(), result.suspicious_patterns.end()),
            result.suspicious_patterns.end()
        );

        // Detect temporal anomalies
        double temporal_score = DetectTemporalAnomalies(operations);

        // Final score
        result.confidence_score = std::max(max_score, temporal_score);
        result.is_suspicious = result.confidence_score > 0.6;

        // Get window statistics for description
        auto stats = mass_modification_detector_->GetWindowStatistics();
        result.operations_count = stats.operation_count;
        result.directories_affected = stats.directory_count;
        result.extensions_affected = stats.extension_count;
        result.operations_per_second = stats.operations_per_second;

        return result;
    }

    /**
     * @brief Configure detection thresholds
     */
    void BehavioralDetector::ConfigureThresholds(size_t min_operations,
        size_t min_directories,
        size_t min_extensions,
        double max_rate)
    {
        MassFileModificationDetector::Configuration config;
        config.min_operations_threshold = min_operations;
        config.min_directories_threshold = min_directories;
        config.min_extensions_threshold = min_extensions;
        config.max_operations_per_second = max_rate;

        mass_modification_detector_->UpdateConfiguration(config);
        config_ = config;
    }

    /**
     * @brief Get process behavior profile
     */
    std::optional<ProcessBehaviorProfile> BehavioralDetector::GetProcessProfile(
        ULONG process_id) const
    {
        std::lock_guard<std::mutex> lock(profiles_mutex_);

        auto it = process_profiles_.find(process_id);
        if (it != process_profiles_.end()) {
            return it->second;
        }

        return std::nullopt;
    }

    /**
     * @brief Clear process history
     */
    void BehavioralDetector::ClearProcessHistory(ULONG process_id)
    {
        std::lock_guard<std::mutex> lock(profiles_mutex_);

        if (process_id == 0) {
            process_profiles_.clear();
        }
        else {
            process_profiles_.erase(process_id);
            traversal_detector_->ClearProcessData(process_id);
        }
    }

    /**
     * @brief Get detector statistics
     */
    BehavioralDetector::Statistics BehavioralDetector::GetStatistics() const
    {
        Statistics stats;
        stats.total_operations_analyzed = total_operations_analyzed_.load();
        stats.suspicious_patterns_detected = suspicious_patterns_detected_.load();

        {
            std::lock_guard<std::mutex> lock(profiles_mutex_);
            stats.processes_tracked = process_profiles_.size();

            double total_score = 0.0;
            for (const auto& [pid, profile] : process_profiles_) {
                total_score += profile.overall_suspicion_score;
            }

            stats.average_confidence_score = stats.processes_tracked > 0 ?
                total_score / stats.processes_tracked : 0.0;
        }

        return stats;
    }

    /**
     * @brief Update process profile
     */
    void BehavioralDetector::UpdateProcessProfile(const FileOperationInfo& operation)
    {
        std::lock_guard<std::mutex> lock(profiles_mutex_);

        auto& profile = process_profiles_[operation.process_id];

        if (profile.process_id == 0) {
            profile.process_id = operation.process_id;
            profile.first_seen = std::chrono::steady_clock::now();

            // Get process name (simplified)
            profile.process_name = L"Unknown";
        }

        profile.last_seen = std::chrono::steady_clock::now();
        profile.total_operations++;

        // Update operation counts
        switch (operation.type) {
        case FileOperationType::Write:
            profile.write_operations++;
            break;
        case FileOperationType::Delete:
            profile.delete_operations++;
            break;
        case FileOperationType::Rename:
            profile.rename_operations++;
            break;
        }

        // Extract directory and extension
        //size_t last_slash = operation.file_path.find_last_of(L"\\");
        size_t last_slash = std::wstring(operation.file_path).find_last_of(L"\\");


        if (last_slash != std::wstring::npos) {
            profile.affected_directories.insert(std::wstring(operation.file_path).substr(0, last_slash));
        }

        //size_t last_dot = operation.file_path.find_last_of(L".");
        size_t last_dot = std::wstring(operation.file_path).find_last_of(L".");
        if (last_dot != std::wstring::npos) {
            //std::wstring extension = operation.file_path.substr(last_dot);
            std::wstring extension = std::wstring(operation.file_path).substr(last_dot);

            profile.affected_extensions.insert(extension);

            if (operation.type == FileOperationType::Create) {
                profile.created_extensions.insert(extension);
            }
        }

        // Update behavioral scores
        profile.overall_suspicion_score = CalculateCombinedScore(profile);
    }

    /**
     * @brief Calculate combined suspicion score
     */
    double BehavioralDetector::CalculateCombinedScore(const ProcessBehaviorProfile& profile) const
    {
        double score = 0.0;

        // Mass modification score (0-0.3)
        if (profile.total_operations > 50) {
            score += 0.3 * std::min(profile.total_operations / 500.0, 1.0);
        }

        // Extension variety score (0-0.2)
        if (profile.affected_extensions.size() > 5) {
            score += 0.2 * std::min(profile.affected_extensions.size() / 20.0, 1.0);
        }

        // Directory spread score (0-0.2)
        if (profile.affected_directories.size() > 3) {
            score += 0.2 * std::min(profile.affected_directories.size() / 15.0, 1.0);
        }

        // Operation type distribution (0-0.3)
        double write_ratio = profile.total_operations > 0 ?
            static_cast<double>(profile.write_operations) / profile.total_operations : 0.0;
        double rename_ratio = profile.total_operations > 0 ?
            static_cast<double>(profile.rename_operations) / profile.total_operations : 0.0;

        if (write_ratio > 0.5 || rename_ratio > 0.3) {
            score += 0.3 * std::max(write_ratio, rename_ratio);
        }

        return score;
    }

    /**
     * @brief Detect temporal anomalies
     */
    double BehavioralDetector::DetectTemporalAnomalies(
        const std::vector<FileOperationInfo>& operations) const
    {
        if (operations.size() < 10) {
            return 0.0;
        }

        // Calculate inter-operation times
        std::vector<double> intervals;
        for (size_t i = 1; i < operations.size(); ++i) {
            /*
            auto duration = operations[i].timestamp - operations[i - 1].timestamp;
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
            intervals.push_back(static_cast<double>(ms));
            */

            // Corregido
            ULARGE_INTEGER time1, time2;
            time1.LowPart = operations[i].timestamp.dwLowDateTime;
            time1.HighPart = operations[i].timestamp.dwHighDateTime;
            time2.LowPart = operations[i - 1].timestamp.dwLowDateTime;
            time2.HighPart = operations[i - 1].timestamp.dwHighDateTime;

            // La resta da un valor en unidades de 100-nanosegundos. Lo convertimos a milisegundos.
            auto ms = static_cast<double>((time1.QuadPart - time2.QuadPart) / 10000.0);
            intervals.push_back(ms);



            
        }

        // Calculate statistics
        double sum = std::accumulate(intervals.begin(), intervals.end(), 0.0);
        double mean = sum / intervals.size();

        double sq_sum = 0.0;
        for (double interval : intervals) {
            sq_sum += (interval - mean) * (interval - mean);
        }
        double std_dev = std::sqrt(sq_sum / intervals.size());

        // Low standard deviation with high frequency indicates automated behavior
        if (std_dev < 100 && mean < 100) {  // Very regular, fast operations
            return 0.8;
        }
        else if (std_dev < 500 && mean < 500) {  // Regular, moderately fast
            return 0.5;
        }

        return 0.0;
    }

} // namespace CryptoShield::Detection