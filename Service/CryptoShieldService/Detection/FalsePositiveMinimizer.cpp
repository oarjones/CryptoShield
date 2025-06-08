/**
 * @file FalsePositiveMinimizer.cpp
 * @brief False positive reduction system implementation
 * @details Implements legitimate software detection and score adjustment
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */
#define NOMINMAX
#include "FalsePositiveMinimizer.h"
#include "../CommunicationManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace CryptoShield::Detection {

    // Static member definitions
    // const std::vector<std::wstring> FalsePositiveMinimizer::BACKUP_SOFTWARE = { ... }; // DELETE
    // const std::vector<std::wstring> FalsePositiveMinimizer::COMPRESSION_SOFTWARE = { ... }; // DELETE
    // const std::vector<std::wstring> FalsePositiveMinimizer::MEDIA_SOFTWARE = { ... }; // DELETE
    // const std::vector<std::wstring> FalsePositiveMinimizer::DEVELOPMENT_SOFTWARE = { ... }; // DELETE
    // const std::vector<std::wstring> FalsePositiveMinimizer::SYSTEM_SOFTWARE = { ... }; // DELETE
    // const std::vector<std::wstring> FalsePositiveMinimizer::SECURITY_SOFTWARE = { ... }; // DELETE

    const std::map<SoftwareCategory, std::vector<std::wstring>>
        FalsePositiveMinimizer::LEGITIMATE_EXTENSIONS = {
            {SoftwareCategory::BACKUP_SOFTWARE, {
                L".bak", L".backup", L".bkp", L".bkf", L".abk",
                L".arc", L".adi", L".tib", L".tibx", L".vbk",
                L".vib", L".vrb", L".pbd"
            }},
            {SoftwareCategory::COMPRESSION_TOOLS, {
                L".zip", L".rar", L".7z", L".tar", L".gz",
                L".bz2", L".xz", L".cab", L".iso", L".dmg",
                L".pkg", L".deb", L".rpm", L".tgz", L".lzh"
            }},
            {SoftwareCategory::MEDIA_ENCODERS, {
                L".mp4", L".avi", L".mkv", L".mov", L".wmv",
                L".flv", L".webm", L".m4v", L".mpg", L".mpeg",
                L".mp3", L".wav", L".flac", L".aac", L".ogg"
            }},
            {SoftwareCategory::DEVELOPMENT_TOOLS, {
                L".exe", L".dll", L".obj", L".lib", L".pdb",
                L".ilk", L".exp", L".res", L".manifest", L".a",
                L".o", L".so", L".dylib", L".class", L".jar"
            }}
    };

    // const std::vector<std::wstring> FalsePositiveMinimizer::TRUSTED_PUBLISHERS = { ... }; // DELETE

    /**
     * @brief Constructor
     */
    FalsePositiveMinimizer::FalsePositiveMinimizer(const CryptoShield::Detection::DetectionEngineConfig::FalsePositiveConfig& config)
        : config_(config), // Initialize the member
          statistics_{} {
        // Existing constructor body, like Initialize()
        // Initialize(); // Will be called after construction by TraditionalEngine typically
    }

    /**
     * @brief Destructor
     */
    FalsePositiveMinimizer::~FalsePositiveMinimizer() = default;

    /**
     * @brief Initialize the minimizer
     */
    bool FalsePositiveMinimizer::Initialize()
    {
        try {
            InitializeLegitimateProcesses();
            InitializeLegitimatePatterns();

            std::wcout << L"[FalsePositiveMinimizer] Initialized with "
                << legitimate_processes_.size() << L" legitimate processes and "
                << legitimate_patterns_.size() << L" patterns" << std::endl;

            return true;
        }
        catch (const std::exception& e) {
            std::wcerr << L"[FalsePositiveMinimizer] Initialization failed: "
                << e.what() << std::endl;
            return false;
        }
    }

    /**
     * @brief Initialize legitimate process database
     */
    void FalsePositiveMinimizer::InitializeLegitimateProcesses()
    {
        std::lock_guard<std::mutex> lock(processes_mutex_);

        // Backup software
        for (const auto& name : config_.trusted_backup_software) { // Use config list
            LegitimateProcess proc;
            proc.process_name = name;
            proc.category = SoftwareCategory::BACKUP_SOFTWARE;
            proc.trust_score = 0.9;
            proc.requires_signature = false;
            proc.allowed_extensions = LEGITIMATE_EXTENSIONS.at(SoftwareCategory::BACKUP_SOFTWARE);
            proc.typical_behaviors = {
                L"MASS_FILE_READ",
                L"ARCHIVE_CREATION",
                L"SHADOW_COPY_ACCESS",
                L"VOLUME_SNAPSHOT"
            };
            proc.last_updated = std::chrono::system_clock::now();

            legitimate_processes_[name] = proc;
        }

        // Compression tools
        for (const auto& name : config_.trusted_compression_software) { // Use config list
            LegitimateProcess proc;
            proc.process_name = name;
            proc.category = SoftwareCategory::COMPRESSION_TOOLS;
            proc.trust_score = 0.85;
            proc.requires_signature = false;
            proc.allowed_extensions = LEGITIMATE_EXTENSIONS.at(SoftwareCategory::COMPRESSION_TOOLS);
            proc.typical_behaviors = {
                L"MASS_FILE_READ",
                L"ARCHIVE_CREATION",
                L"TEMP_FILE_USAGE",
                L"HIGH_CPU_USAGE"
            };
            proc.last_updated = std::chrono::system_clock::now();

            legitimate_processes_[name] = proc;
        }

        // Media software (Removed as MEDIA_SOFTWARE list is removed)
        // for (const auto& name : MEDIA_SOFTWARE) {
        // ...
        // }

        // Development tools
        for (const auto& name : config_.trusted_dev_software) { // Use config list
            LegitimateProcess proc;
            proc.process_name = name;
            proc.category = SoftwareCategory::DEVELOPMENT_TOOLS;
            proc.trust_score = 0.85;
            proc.requires_signature = false;
            proc.allowed_extensions = LEGITIMATE_EXTENSIONS.at(SoftwareCategory::DEVELOPMENT_TOOLS);
            proc.typical_behaviors = {
                L"SOURCE_FILE_ACCESS",
                L"COMPILATION_PATTERN",
                L"DEBUG_FILE_CREATION",
                L"EXECUTABLE_CREATION"
            };
            proc.last_updated = std::chrono::system_clock::now();

            legitimate_processes_[name] = proc;
        }

        // System software - highest trust
        for (const auto& name : config_.trusted_system_software) { // Use config list
            LegitimateProcess proc;
            proc.process_name = name;
            proc.category = SoftwareCategory::SYSTEM_UTILITIES;
            proc.trust_score = 0.95;
            proc.requires_signature = true;
            proc.typical_behaviors = {
                L"SYSTEM_FILE_ACCESS",
                L"REGISTRY_MODIFICATION",
                L"SERVICE_MANAGEMENT",
                L"PRIVILEGED_OPERATION"
            };
            proc.known_paths = {
                L"C:\\Windows\\System32\\",
                L"C:\\Windows\\SysWOW64\\"
            };
            proc.last_updated = std::chrono::system_clock::now();

            legitimate_processes_[name] = proc;
        }
    }

    /**
     * @brief Initialize legitimate patterns
     */
    void FalsePositiveMinimizer::InitializeLegitimatePatterns()
    {
        std::lock_guard<std::mutex> lock(patterns_mutex_);

        // Backup pattern
        {
            LegitimatePattern pattern;
            pattern.pattern_id = L"LEGIT_BACKUP_001";
            pattern.pattern_name = L"Standard Backup Operation";
            pattern.category = SoftwareCategory::BACKUP_SOFTWARE;
            pattern.required_indicators = {
                L"SEQUENTIAL_READ_PATTERN",
                L"ARCHIVE_FILE_CREATION",
                L"PRESERVE_ORIGINAL_FILES"
            };
            pattern.optional_indicators = {
                L"SHADOW_COPY_READ",
                L"COMPRESSION_ACTIVITY",
                L"CATALOG_FILE_CREATION"
            };
            pattern.excluded_indicators = {
                L"ORIGINAL_FILE_DELETION",
                L"EXTENSION_CHANGE",
                L"RANSOM_NOTE_CREATION"
            };
            pattern.confidence_threshold = 0.7;
            pattern.min_indicators_required = 2;
            pattern.description = L"Typical backup software behavior";

            legitimate_patterns_.push_back(pattern);
        }

        // Compression pattern
        {
            LegitimatePattern pattern;
            pattern.pattern_id = L"LEGIT_COMPRESS_001";
            pattern.pattern_name = L"File Compression Operation";
            pattern.category = SoftwareCategory::COMPRESSION_TOOLS;
            pattern.required_indicators = {
                L"MULTIPLE_FILE_READ",
                L"ARCHIVE_EXTENSION_CREATE",
                L"TEMP_FILE_USAGE"
            };
            pattern.optional_indicators = {
                L"HIGH_COMPRESSION_RATIO",
                L"DIRECTORY_STRUCTURE_PRESERVE",
                L"METADATA_PRESERVATION"
            };
            pattern.excluded_indicators = {
                L"ORIGINAL_FILE_ENCRYPTION",
                L"SUSPICIOUS_EXTENSION_ADD"
            };
            pattern.confidence_threshold = 0.75;
            pattern.min_indicators_required = 2;
            pattern.description = L"Standard compression tool behavior";

            legitimate_patterns_.push_back(pattern);
        }

        // Media encoding pattern
        {
            LegitimatePattern pattern;
            pattern.pattern_id = L"LEGIT_MEDIA_001";
            pattern.pattern_name = L"Media Encoding Operation";
            pattern.category = SoftwareCategory::MEDIA_ENCODERS;
            pattern.required_indicators = {
                L"MEDIA_FILE_READ",
                L"MEDIA_FILE_WRITE",
                L"HIGH_CPU_SUSTAINED"
            };
            pattern.optional_indicators = {
                L"CODEC_LIBRARY_LOAD",
                L"FRAME_BUFFER_ALLOCATION",
                L"GPU_ACCELERATION"
            };
            pattern.excluded_indicators = {
                L"NON_MEDIA_FILE_MODIFICATION",
                L"SYSTEM_FILE_ACCESS"
            };
            pattern.confidence_threshold = 0.7;
            pattern.min_indicators_required = 2;
            pattern.description = L"Media encoding/transcoding behavior";

            legitimate_patterns_.push_back(pattern);
        }

        // Development build pattern
        {
            LegitimatePattern pattern;
            pattern.pattern_id = L"LEGIT_DEV_001";
            pattern.pattern_name = L"Software Build Operation";
            pattern.category = SoftwareCategory::DEVELOPMENT_TOOLS;
            pattern.required_indicators = {
                L"SOURCE_FILE_READ",
                L"OBJECT_FILE_CREATE",
                L"EXECUTABLE_GENERATION"
            };
            pattern.optional_indicators = {
                L"DEBUG_SYMBOL_CREATE",
                L"LINKER_ACTIVITY",
                L"MANIFEST_GENERATION"
            };
            pattern.excluded_indicators = {
                L"SYSTEM_FILE_MODIFICATION",
                L"REGISTRY_PERSISTENCE"
            };
            pattern.confidence_threshold = 0.8;
            pattern.min_indicators_required = 2;
            pattern.description = L"Software compilation and build process";

            legitimate_patterns_.push_back(pattern);
        }
    }

    /**
     * @brief Analyze for false positives
     */
    FalsePositiveAnalysis FalsePositiveMinimizer::AnalyzeLegitimacy(
        const std::wstring& process_name,
        const std::wstring& process_path,
        const std::vector<FileOperation>& operations,
        double original_score)
    {
        FalsePositiveAnalysis analysis;
        analysis.likely_false_positive = false;
        analysis.false_positive_probability = 0.0;
        analysis.adjustment_factor = 1.0;
        analysis.identified_category = SoftwareCategory::UNKNOWN;

        // Check whitelist first
        if (config_.enable_whitelist && IsWhitelisted(process_path)) {
            analysis.likely_false_positive = true;
            analysis.false_positive_probability = 0.95;
            analysis.adjustment_factor = 0.1;
            analysis.identified_software = process_name;
            analysis.legitimacy_indicators.push_back(L"Process is whitelisted");
            analysis.recommendation = L"Whitelisted process - significantly reduce threat score";
            analysis.detailed_reason = L"Process found in trusted whitelist";

            UpdateStatistics(analysis);
            return analysis;
        }

        // Verify signature if enabled
        std::wstring signer_name;
        if (config_.enable_signature_verification) {
            signer_name = VerifyProcessSignature(process_path);
            if (!signer_name.empty()) {
                analysis.legitimacy_indicators.push_back(
                    L"Digitally signed by: " + signer_name
                );

                // Check if trusted publisher
                if (std::find(config_.trusted_publishers.begin(), config_.trusted_publishers.end(), // Use config list
                    signer_name) != config_.trusted_publishers.end()) {
                    analysis.legitimacy_indicators.push_back(L"Trusted publisher");
                    analysis.false_positive_probability += 0.4;
                }
            }
        }

        // Identify software category
        analysis.identified_category = IdentifyCategory(process_name, operations);

        // Check specific legitimate activities
        if (analysis.identified_category == SoftwareCategory::BACKUP_SOFTWARE ||
            IsLegitimateBackupActivity(operations)) {
            analysis.legitimacy_indicators.push_back(L"Backup software behavior detected");
            analysis.false_positive_probability += 0.3;
        }

        if (analysis.identified_category == SoftwareCategory::COMPRESSION_TOOLS ||
            IsLegitimateCompressionActivity(process_name, operations)) {
            analysis.legitimacy_indicators.push_back(L"Compression tool behavior detected");
            analysis.false_positive_probability += 0.25;
        }

        if (analysis.identified_category == SoftwareCategory::MEDIA_ENCODERS ||
            IsLegitimateMediaProcessing(operations)) {
            analysis.legitimacy_indicators.push_back(L"Media processing behavior detected");
            analysis.false_positive_probability += 0.2;
        }

        if (analysis.identified_category == SoftwareCategory::DEVELOPMENT_TOOLS ||
            IsLegitimateDevActivity(process_name, operations)) {
            analysis.legitimacy_indicators.push_back(L"Development tool behavior detected");
            analysis.false_positive_probability += 0.25;
        }

        // Check reputation if enabled
        if (config_.enable_reputation_system) {
            double reputation = CalculateReputationScore(process_name, process_path);
            if (reputation > config_.min_reputation_score) {
                analysis.legitimacy_indicators.push_back(
                    L"Good reputation score: " + std::to_wstring(reputation)
                );
                analysis.false_positive_probability += reputation * 0.3;
            }
        }

        // Analyze operation patterns
        auto pattern_indicators = AnalyzeOperationPatterns(operations);
        analysis.legitimacy_indicators.insert(
            analysis.legitimacy_indicators.end(),
            pattern_indicators.begin(),
            pattern_indicators.end()
        );

        // Check for suspicious anomalies
        analysis.suspicious_indicators = CheckSuspiciousAnomalies(process_name, operations);

        // Calculate final probability
        analysis.false_positive_probability = CalculateFalseProbability(
            analysis.legitimacy_indicators,
            analysis.suspicious_indicators,
            analysis.identified_category
        );

        // Determine if likely false positive
        analysis.likely_false_positive = analysis.false_positive_probability > 0.6;

        // Calculate adjustment factor
        if (analysis.likely_false_positive) {
            // Reduce score based on confidence
            analysis.adjustment_factor = 1.0 -
                (analysis.false_positive_probability * config_.max_fp_adjustment);
            analysis.adjustment_factor = std::max(analysis.adjustment_factor, 0.1);
        }

        // Set identified software name
        if (analysis.identified_category != SoftwareCategory::UNKNOWN) {
            analysis.identified_software = process_name;
        }

        // Generate recommendation
        analysis.recommendation = GenerateRecommendation(analysis);

        // Build detailed reason
        std::wstringstream reason;
        reason << L"Process '" << process_name << L"' analyzed: ";
        reason << L"Category=" << static_cast<int>(analysis.identified_category) << L", ";
        reason << L"FP Probability=" << std::fixed << std::setprecision(2)
            << analysis.false_positive_probability << L", ";
        reason << L"Legitimacy indicators=" << analysis.legitimacy_indicators.size() << L", ";
        reason << L"Suspicious indicators=" << analysis.suspicious_indicators.size();
        analysis.detailed_reason = reason.str();

        // Update statistics
        UpdateStatistics(analysis);

        return analysis;
    }

    /**
     * @brief Check if process is whitelisted
     */
    bool FalsePositiveMinimizer::IsWhitelisted(const std::wstring& process_path,
        const std::wstring& process_hash) const
    {
        std::lock_guard<std::mutex> lock(whitelist_mutex_);

        // Check by path
        auto it = whitelist_.find(process_path);
        if (it != whitelist_.end() && it->second.is_active) {
            // Check if not expired
            auto now = std::chrono::system_clock::now();
            if (now < it->second.expiry_date) {
                return true;
            }
        }

        // Check by hash if provided
        if (!process_hash.empty()) {
            auto hash_it = hash_to_path_.find(process_hash);
            if (hash_it != hash_to_path_.end()) {
                return IsWhitelisted(hash_it->second);
            }
        }

        return false;
    }

    /**
     * @brief Check if legitimate backup activity
     */
    bool FalsePositiveMinimizer::IsLegitimateBackupActivity(
        const std::vector<FileOperation>& operations) const
    {
        if (operations.empty()) {
            return false;
        }

        size_t read_count = 0;
        size_t write_count = 0;
        size_t delete_count = 0;
        std::set<std::wstring> read_extensions;
        std::set<std::wstring> write_extensions;

        for (const auto& op : operations) {
            std::wstring ext = std::filesystem::path(op.file_path).extension().wstring();

            switch (op.operation_type) {
            //case FileOperationType::Create:
            case static_cast<ULONG>(FileOperationType::Create):
            //case FileOperationType::Write:
            case static_cast<ULONG>(FileOperationType::Write):
                write_count++;
                write_extensions.insert(ext);
                break;
            //case FileOperationType::Delete:
            case static_cast<ULONG>(FileOperationType::Delete):
                delete_count++;
                break;
            default:
                read_count++;
                read_extensions.insert(ext);
            }
        }

        // Backup characteristics:
        // - High read to write ratio
        // - Writes to backup extensions
        // - Minimal deletions
        // - Preserves original files

        bool high_read_ratio = read_count > write_count * 2;
        bool backup_extensions = false;

        for (const auto& ext : write_extensions) {
            if (std::find(LEGITIMATE_EXTENSIONS.at(SoftwareCategory::BACKUP_SOFTWARE).begin(),
                LEGITIMATE_EXTENSIONS.at(SoftwareCategory::BACKUP_SOFTWARE).end(),
                ext) != LEGITIMATE_EXTENSIONS.at(SoftwareCategory::BACKUP_SOFTWARE).end()) {
                backup_extensions = true;
                break;
            }
        }

        bool minimal_deletions = delete_count < operations.size() * 0.05;

        return high_read_ratio && backup_extensions && minimal_deletions;
    }

    /**
     * @brief Check if legitimate compression activity
     */
    bool FalsePositiveMinimizer::IsLegitimateCompressionActivity(
        const std::wstring& process_name,
        const std::vector<FileOperation>& operations) const
    {
        // Check if known compression tool
        bool is_known_tool = false;
        std::wstring lower_name = process_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);

        for (const auto& tool_pattern : config_.trusted_compression_software) { // Use config list
            std::wstring lower_tool_pattern = tool_pattern;
            std::transform(lower_tool_pattern.begin(), lower_tool_pattern.end(), lower_tool_pattern.begin(), ::towlower);
            if (lower_name.find(lower_tool_pattern) != std::wstring::npos) {
                is_known_tool = true;
                break;
            }
        }

        // Analyze operation patterns
        size_t archive_creates = 0;
        bool temp_file_usage = false;

        for (const auto& op : operations) {
            std::wstring ext = std::filesystem::path(op.file_path).extension().wstring();

            // Check for archive creation
            if ((op.operation_type == static_cast<ULONG>(FileOperationType::Create) || op.operation_type == static_cast<ULONG>(FileOperationType::Write)) &&
                std::find(LEGITIMATE_EXTENSIONS.at(SoftwareCategory::COMPRESSION_TOOLS).begin(),
                    LEGITIMATE_EXTENSIONS.at(SoftwareCategory::COMPRESSION_TOOLS).end(),
                    ext) != LEGITIMATE_EXTENSIONS.at(SoftwareCategory::COMPRESSION_TOOLS).end()) {
                archive_creates++;
            }

            // Check for temp file usage
            if (op.file_path.find(L"\\Temp\\") != std::wstring::npos ||
                op.file_path.find(L"\\tmp\\") != std::wstring::npos) {
                temp_file_usage = true;
            }
        }

        return (is_known_tool || archive_creates > 0) && temp_file_usage;
    }

    /**
     * @brief Identify software category
     */
    SoftwareCategory FalsePositiveMinimizer::IdentifyCategory(
        const std::wstring& process_name,
        const std::vector<FileOperation>& operations) const
    {
        std::lock_guard<std::mutex> lock(processes_mutex_);

        // Check if in known legitimate processes
        auto it = legitimate_processes_.find(process_name);
        if (it != legitimate_processes_.end()) {
            return it->second.category;
        }

        // Try to identify by process name patterns
        std::wstring lower_name = process_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);

        // Check each category
        for (const auto& backup_name_pattern : config_.trusted_backup_software) { // Use config list
            std::wstring lower_backup_pattern = backup_name_pattern;
            std::transform(lower_backup_pattern.begin(), lower_backup_pattern.end(), lower_backup_pattern.begin(), ::towlower);
            if (lower_name.find(lower_backup_pattern) != std::wstring::npos) {
                return SoftwareCategory::BACKUP_SOFTWARE;
            }
        }

        for (const auto& compress_name_pattern : config_.trusted_compression_software) { // Use config list
            std::wstring lower_compress_pattern = compress_name_pattern;
            std::transform(lower_compress_pattern.begin(), lower_compress_pattern.end(), lower_compress_pattern.begin(), ::towlower);
            if (lower_name.find(lower_compress_pattern) != std::wstring::npos) {
                return SoftwareCategory::COMPRESSION_TOOLS;
            }
        }
        // MEDIA_SOFTWARE and SECURITY_SOFTWARE checks would be removed or adapted if they were here
        // For DEVELOPMENT_SOFTWARE
        for (const auto& dev_name_pattern : config_.trusted_dev_software) { // Use config list
            std::wstring lower_dev_pattern = dev_name_pattern;
            std::transform(lower_dev_pattern.begin(), lower_dev_pattern.end(), lower_dev_pattern.begin(), ::towlower);
            if (lower_name.find(lower_dev_pattern) != std::wstring::npos) {
                return SoftwareCategory::DEVELOPMENT_TOOLS;
            }
        }
        // For SYSTEM_SOFTWARE
        for (const auto& system_name_pattern : config_.trusted_system_software) { // Use config list
            std::wstring lower_system_pattern = system_name_pattern;
            std::transform(lower_system_pattern.begin(), lower_system_pattern.end(), lower_system_pattern.begin(), ::towlower);
            if (lower_name.find(lower_system_pattern) != std::wstring::npos) {
                return SoftwareCategory::SYSTEM_UTILITIES;
            }
        }

        // Analyze by behavior if name doesn't match
        if (operations.size() > 10) {
            if (IsLegitimateBackupActivity(operations)) {
                return SoftwareCategory::BACKUP_SOFTWARE;
            }
            if (IsLegitimateMediaProcessing(operations)) {
                return SoftwareCategory::MEDIA_ENCODERS;
            }
        }

        return SoftwareCategory::UNKNOWN;
    }

    /**
     * @brief Calculate reputation score
     */
    double FalsePositiveMinimizer::CalculateReputationScore(
        const std::wstring& process_name,
        const std::wstring& process_path) const
    {
        std::lock_guard<std::mutex> lock(reputation_mutex_);

        auto it = reputation_data_.find(process_name);
        if (it == reputation_data_.end()) {
            return 0.5; // Neutral reputation for unknown
        }

        const auto& rep = it->second;

        // Calculate score based on history
        double base_score = rep.reputation_score;

        // Adjust based on false positive rate
        if (rep.total_executions > 0) {
            double fp_rate = static_cast<double>(rep.false_positive_count) / rep.total_executions;
            base_score = base_score * (1.0 - fp_rate) + 0.5 * fp_rate;
        }

        // Boost for signed processes
        if (rep.is_signed) {
            base_score = std::min(base_score * 1.2, 1.0);
        }

        // Reduce for new/rare processes
        auto age = std::chrono::system_clock::now() - rep.first_seen;
        //auto days = std::chrono::duration_cast<std::chrono::days>(age).count();
        auto days = std::chrono::duration_cast<std::chrono::hours>(age).count() / 24;
        if (days < 7) {
            base_score *= 0.8;
        }

        return base_score;
    }

    /**
     * @brief Generate recommendation
     */
    std::wstring FalsePositiveMinimizer::GenerateRecommendation(
        const FalsePositiveAnalysis& analysis) const
    {
        if (analysis.likely_false_positive) {
            if (analysis.false_positive_probability > 0.9) {
                return L"HIGHLY LIKELY FALSE POSITIVE: Consider whitelisting this process";
            }
            else if (analysis.false_positive_probability > 0.7) {
                return L"Probable false positive: Reduce threat score significantly";
            }
            else {
                return L"Possible false positive: Monitor but reduce threat level";
            }
        }
        else {
            if (analysis.suspicious_indicators.size() > 3) {
                return L"Multiple suspicious indicators: Maintain high threat level";
            }
            else if (analysis.legitimacy_indicators.empty()) {
                return L"No legitimacy indicators found: Proceed with caution";
            }
            else {
                return L"Mixed indicators: Continue monitoring with standard response";
            }
        }
    }

    /**
     * @brief Update statistics
     */
    void FalsePositiveMinimizer::UpdateStatistics(const FalsePositiveAnalysis& analysis)
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);

        statistics_.total_analyses++;

        if (analysis.likely_false_positive) {
            statistics_.false_positives_prevented++;
        }

        if (analysis.identified_category != SoftwareCategory::UNKNOWN) {
            statistics_.detections_by_category[analysis.identified_category]++;
        }

        // Update average adjustment factor
        double current_avg = statistics_.average_adjustment_factor;
        statistics_.average_adjustment_factor =
            (current_avg * (statistics_.total_analyses - 1) + analysis.adjustment_factor) /
            statistics_.total_analyses;
    }

    /**
     * @brief Verify process signature
     */
    std::wstring FalsePositiveMinimizer::VerifyProcessSignature(
        const std::wstring& process_path) const
    {
        std::wstring signer_name;
        SignatureVerifier::VerifyFileSignature(process_path, signer_name);
        return signer_name;
    }

    /**
     * @brief Get statistics
     */
    FalsePositiveMinimizer::Statistics FalsePositiveMinimizer::GetStatistics() const
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);

        Statistics stats = statistics_;
        stats.whitelist_entries = whitelist_.size();
        stats.reputation_entries = reputation_data_.size();

        return stats;
    }

    /**
     * @brief Get default configuration
     */
    FalsePositiveMinimizerConfig FalsePositiveMinimizer::GetDefaultConfig()
    {
        FalsePositiveMinimizerConfig config;

        config.enable_whitelist = true;
        config.enable_reputation_system = true;
        config.enable_signature_verification = true;
        config.enable_behavioral_analysis = true;
        config.min_reputation_score = 0.6;
        config.max_fp_adjustment = 0.8;
        config.reputation_history_days = 30;
        config.auto_whitelist_signed = false;
        config.strict_mode = false;

        return config;
    }

    /**
     * @brief Check suspicious anomalies (simplified implementation)
     */
    std::vector<std::wstring> FalsePositiveMinimizer::CheckSuspiciousAnomalies(
        const std::wstring& process_name,
        const std::vector<FileOperation>& operations) const
    {
        std::vector<std::wstring> anomalies;

        // Check for ransomware-like patterns
        size_t extension_changes = 0;
        size_t deletes = 0;

        for (const auto& op : operations) {
            if (op.operation_type == static_cast<ULONG>(FileOperationType::Rename)) {
                extension_changes++;
            }
            else if (op.operation_type == static_cast<ULONG>(FileOperationType::Delete)) {
                deletes++;
            }
        }

        if (extension_changes > operations.size() * 0.3) {
            anomalies.push_back(L"High rate of file extension changes");
        }

        if (deletes > operations.size() * 0.5) {
            anomalies.push_back(L"High rate of file deletions");
        }

        return anomalies;
    }

    /**
     * @brief Calculate false positive probability
     */
    double FalsePositiveMinimizer::CalculateFalseProbability(
        const std::vector<std::wstring>& legitimacy_indicators,
        const std::vector<std::wstring>& suspicious_indicators,
        SoftwareCategory category) const
    {
        double probability = 0.0;

        // Base probability from indicators
        double positive_weight = legitimacy_indicators.size() * 0.15;
        double negative_weight = suspicious_indicators.size() * 0.2;

        probability = positive_weight / (positive_weight + negative_weight + 1.0);

        // Adjust based on category
        switch (category) {
        case SoftwareCategory::BACKUP_SOFTWARE:
        case SoftwareCategory::SYSTEM_UTILITIES:
            probability *= 1.3;
            break;
        case SoftwareCategory::COMPRESSION_TOOLS:
        case SoftwareCategory::DEVELOPMENT_TOOLS:
            probability *= 1.2;
            break;
        case SoftwareCategory::MEDIA_ENCODERS:
            probability *= 1.1;
            break;
        default:
            break;
        }

        return std::min(probability, 0.99);
    }

    /**
     * @brief Analyze operation patterns (simplified)
     */
    std::vector<std::wstring> FalsePositiveMinimizer::AnalyzeOperationPatterns(
        const std::vector<FileOperation>& operations) const
    {
        std::vector<std::wstring> patterns;

        // Analyze file access patterns
        std::map<std::wstring, size_t> extension_counts;
        for (const auto& op : operations) {
            std::wstring ext = std::filesystem::path(op.file_path).extension().wstring();
            extension_counts[ext]++;
        }

        // Check for legitimate patterns
        bool mostly_media = false;
        bool mostly_documents = false;

        for (const auto& [ext, count] : extension_counts) {
            if (count > operations.size() * 0.3) {
                if (ext == L".mp4" || ext == L".avi" || ext == L".mkv") {
                    mostly_media = true;
                }
                else if (ext == L".doc" || ext == L".pdf" || ext == L".txt") {
                    mostly_documents = true;
                }
            }
        }

        if (mostly_media) {
            patterns.push_back(L"Primarily accessing media files");
        }
        if (mostly_documents) {
            patterns.push_back(L"Primarily accessing document files");
        }

        return patterns;
    }

    // SignatureVerifier implementation
    bool SignatureVerifier::VerifyFileSignature(const std::wstring& file_path,
        std::wstring& signer_name)
    {
        // Prepare WINTRUST_FILE_INFO structure
        WINTRUST_FILE_INFO file_info = {};
        file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
        file_info.pcwszFilePath = file_path.c_str();

        // Prepare WINTRUST_DATA structure
        WINTRUST_DATA trust_data = {};
        trust_data.cbStruct = sizeof(WINTRUST_DATA);
        trust_data.dwUIChoice = WTD_UI_NONE;
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust_data.dwUnionChoice = WTD_CHOICE_FILE;
        trust_data.pFile = &file_info;
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
        trust_data.dwProvFlags = WTD_SAFER_FLAG;

        // Verify signature
        GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG status = WinVerifyTrust(NULL, &policy_guid, &trust_data);

        // Close verification
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policy_guid, &trust_data);

        if (status == ERROR_SUCCESS) {
            // Get signer info (simplified - would need more code for full implementation)
            signer_name = L"Verified Signer"; // Placeholder
            return true;
        }

        return false;
    }


	/**
	 * @brief Check if legitimate media processing
	 */
    bool FalsePositiveMinimizer::IsLegitimateMediaProcessing(
        const std::vector<FileOperation>& operations) const
    {
        if (operations.empty()) {
            return false;
        }

        size_t media_file_ops = 0;
        const auto& media_extensions = LEGITIMATE_EXTENSIONS.at(SoftwareCategory::MEDIA_ENCODERS);

        for (const auto& op : operations) {
            std::wstring ext = std::filesystem::path(op.file_path).extension().wstring();

            // Comprueba si la extensión está en la lista de extensiones de medios legítimos
            if (std::find(media_extensions.begin(), media_extensions.end(), ext) != media_extensions.end()) {
                media_file_ops++;
            }
        }

        // Considera la actividad como legítima si más del 70% de las operaciones son sobre archivos de medios.
        double media_ratio = static_cast<double>(media_file_ops) / operations.size();

        return media_ratio > 0.7;
    }

    /**
	 * @brief Check if legitimate development activity
     */
    bool FalsePositiveMinimizer::IsLegitimateDevActivity(
        const std::wstring& process_name,
        const std::vector<FileOperation>& operations) const
    {
        // Comprueba si el nombre del proceso corresponde a una herramienta de desarrollo conocida.
        bool is_dev_tool = false;
        std::wstring lower_name = process_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);

        for (const auto& tool_pattern : config_.trusted_dev_software) { // Use config list
            std::wstring lower_tool_pattern = tool_pattern;
            std::transform(lower_tool_pattern.begin(), lower_tool_pattern.end(), lower_tool_pattern.begin(), ::towlower);
            if (lower_name.find(lower_tool_pattern) != std::wstring::npos) {
                is_dev_tool = true;
                break;
            }
        }

        if (!is_dev_tool) {
            return false; // Si no es una herramienta de desarrollo, no es actividad de desarrollo.
        }

        // Si es una herramienta de desarrollo, comprueba si las operaciones son sobre archivos de código/compilación.
        size_t dev_file_ops = 0;
        const auto& dev_extensions = LEGITIMATE_EXTENSIONS.at(SoftwareCategory::DEVELOPMENT_TOOLS);

        for (const auto& op : operations) {
            std::wstring ext = std::filesystem::path(op.file_path).extension().wstring();
            if (std::find(dev_extensions.begin(), dev_extensions.end(), ext) != dev_extensions.end()) {
                dev_file_ops++;
            }
        }

        // Es actividad de desarrollo legítima si la mayoría de las operaciones son sobre archivos de desarrollo.
        double dev_ratio = static_cast<double>(dev_file_ops) / operations.size();

        return dev_ratio > 0.5;
    }

} // namespace CryptoShield::Detection