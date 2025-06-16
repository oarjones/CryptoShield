/**
 * @file DetectionConfig.cpp
 * @brief Unified configuration system implementation
 * @details Manages loading, saving, and validation of detection engine configuration
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */
#define NOMINMAX
#include "DetectionConfig.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <iomanip>
#include <algorithm>
#include <nlohmann/json.hpp>
#include "../Utils/StringUtils.h"

namespace CryptoShield::Detection {

    /**
     * @brief Constructor
     */
    DetectionConfigManager::DetectionConfigManager()
        : current_config_(GetDefaultConfiguration())
        , statistics_{}
    {
        statistics_.last_load_time = std::chrono::system_clock::now();
    }

    /**
     * @brief Destructor
     */
    DetectionConfigManager::~DetectionConfigManager() = default;

    /**
     * @brief Load configuration from file
     */
    bool DetectionConfigManager::LoadConfiguration(const std::wstring& config_file)
    {
        try {
            std::ifstream file(config_file);
            if (!file.is_open()) {
                std::wcerr << L"[ConfigManager] Failed to open config file: "
                    << config_file << std::endl;
                return false;
            }

            nlohmann::json j;
            file >> j;

            std::lock_guard<std::mutex> lock(config_mutex_);

            // Parse global settings
            if (j.contains("global")) {
                auto& g = j["global"];
                current_config_.global.enable_detection = g.value("enable_detection", true);
                current_config_.global.enable_logging = g.value("enable_logging", true);
                current_config_.global.enable_telemetry = g.value("enable_telemetry", false);
                current_config_.global.debug_mode = g.value("debug_mode", false);
                current_config_.global.log_directory = std::wstring(
                    g.value("log_directory", "C:\\ProgramData\\CryptoShield\\Logs").begin(),
                    g.value("log_directory", "C:\\ProgramData\\CryptoShield\\Logs").end()
                );
                current_config_.global.max_log_size_mb = g.value("max_log_size_mb", 100);
                current_config_.global.log_retention_days = g.value("log_retention_days", 30);
                current_config_.global.thread_pool_size = g.value("thread_pool_size", 4);
                current_config_.global.max_memory_usage_mb = g.value("max_memory_usage_mb", 200);
            }

            // Parse entropy configuration
            if (j.contains("entropy_analysis")) {
                auto& e = j["entropy_analysis"];
                current_config_.entropy.enabled = e.value("enabled", true);
                current_config_.entropy.weight = e.value("weight", 0.30);
                current_config_.entropy.threshold_text_files = e.value("threshold_text_files", 4.5);
                current_config_.entropy.threshold_images = e.value("threshold_images", 7.0);
                current_config_.entropy.threshold_executables = e.value("threshold_executables", 6.0);
                current_config_.entropy.threshold_compressed = e.value("threshold_compressed", 7.8);
                current_config_.entropy.threshold_databases = e.value("threshold_databases", 5.5);
                current_config_.entropy.threshold_unknown = e.value("threshold_unknown", 6.5);
                current_config_.entropy.block_size = e.value("block_size", 4096);
                current_config_.entropy.enable_chi_square = e.value("enable_chi_square", true);
                current_config_.entropy.enable_hamming_distance = e.value("enable_hamming_distance", true);
                current_config_.entropy.enable_advanced_analysis = e.value("enable_advanced_analysis", true);
                current_config_.entropy.max_file_size_for_analysis = e.value("max_file_size_for_analysis", 104857600);
            }

            // Parse behavioral configuration
            if (j.contains("behavioral_detection")) {
                auto& b = j["behavioral_detection"];
                current_config_.behavioral.enabled = b.value("enabled", true);
                current_config_.behavioral.weight = b.value("weight", 0.25);
                current_config_.behavioral.min_operations_threshold = b.value("min_operations", 50);
                current_config_.behavioral.min_directories_threshold = b.value("min_directories", 3);
                current_config_.behavioral.min_extensions_threshold = b.value("min_extensions", 2);
                current_config_.behavioral.max_operations_per_second = b.value("max_ops_per_second", 10.0);
                current_config_.behavioral.time_window_seconds = b.value("time_window_seconds", 60);
                current_config_.behavioral.track_extension_changes = b.value("track_extension_changes", true);
                current_config_.behavioral.track_directory_traversal = b.value("track_directory_traversal", true);
                current_config_.behavioral.track_temporal_patterns = b.value("track_temporal_patterns", true);
                current_config_.behavioral.suspicion_score_threshold = b.value("suspicion_score_threshold", 0.7);

                // Load suspicious extensions
                if (b.contains("suspicious_extensions")) {
                    current_config_.behavioral.suspicious_extensions.clear();
                    for (const auto& ext : b["suspicious_extensions"]) {
                        std::string ext_str = ext.get<std::string>();
                        current_config_.behavioral.suspicious_extensions.push_back(
                            std::wstring(ext_str.begin(), ext_str.end())
                        );
                    }
                }
                if (b.contains("suspicious_patterns_regex") && b["suspicious_patterns_regex"].is_array()) {
                    current_config_.behavioral.suspicious_patterns_regex.clear();
                    for (const auto& pat : b["suspicious_patterns_regex"]) {
                        current_config_.behavioral.suspicious_patterns_regex.push_back(
                            std::wstring(pat.get<std::string>().begin(), pat.get<std::string>().end())
                        );
                    }
                }
            }

            // Parse system activity configuration
            if (j.contains("system_monitoring")) {
                auto& s = j["system_monitoring"];
                current_config_.system_activity.enabled = s.value("enabled", true);
                current_config_.system_activity.weight = s.value("weight", 0.25);
                current_config_.system_activity.monitor_shadow_copy_deletion = s.value("monitor_shadow_copy", true);
                current_config_.system_activity.monitor_registry_changes = s.value("monitor_registry", true);
                current_config_.system_activity.monitor_boot_configuration = s.value("monitor_boot_config", true);
                current_config_.system_activity.monitor_security_software = s.value("monitor_security_software", true);
                current_config_.system_activity.monitor_network_activity = s.value("monitor_network", false);
                current_config_.system_activity.command_line_history_size = s.value("command_history_size", 1000);
                current_config_.system_activity.registry_history_size = s.value("registry_history_size", 5000);
            }

            // Parse scoring configuration
            if (j.contains("scoring")) {
                auto& sc = j["scoring"];
                current_config_.scoring.entropy_weight = sc.value("entropy_weight", 0.30);
                current_config_.scoring.behavioral_weight = sc.value("behavioral_weight", 0.25);
                current_config_.scoring.system_activity_weight = sc.value("system_activity_weight", 0.25);
                current_config_.scoring.temporal_weight = sc.value("temporal_weight", 0.20);
                current_config_.scoring.threshold_low = sc.value("threshold_low", 0.3);
                current_config_.scoring.threshold_medium = sc.value("threshold_medium", 0.6);
                current_config_.scoring.threshold_high = sc.value("threshold_high", 0.8);
                current_config_.scoring.threshold_critical = sc.value("threshold_critical", 0.95);
                current_config_.scoring.enable_false_positive_reduction = sc.value("enable_fp_reduction", true);
                current_config_.scoring.false_positive_weight = sc.value("false_positive_weight", 0.15);
                current_config_.scoring.enable_detailed_explanation = sc.value("enable_detailed_explanation", true);
                current_config_.scoring.enable_confidence_boosting = sc.value("enable_confidence_boosting", true);
                current_config_.scoring.confidence_boost_threshold = sc.value("confidence_boost_threshold", 0.8);
            }

            // Parse pattern database configuration
            if (j.contains("pattern_database")) {
                auto& p = j["pattern_database"];
                current_config_.pattern_database.enabled = p.value("enabled", true);
                std::string db_file = p.value("database_file", "patterns.db");
                current_config_.pattern_database.database_file = std::wstring(db_file.begin(), db_file.end());
                current_config_.pattern_database.auto_update = p.value("auto_update", false);
                current_config_.pattern_database.update_interval_hours = p.value("update_interval_hours", 24);
                current_config_.pattern_database.enable_custom_patterns = p.value("enable_custom_patterns", true);
                current_config_.pattern_database.max_patterns = p.value("max_patterns", 10000);
                current_config_.pattern_database.min_pattern_confidence = p.value("min_pattern_confidence", 0.5);
                current_config_.pattern_database.enable_fuzzy_matching = p.value("enable_fuzzy_matching", true);
                current_config_.pattern_database.fuzzy_match_threshold = p.value("fuzzy_match_threshold", 0.8);
            }

            // Parse false positive configuration
            if (j.contains("false_positive_minimizer")) {
                auto& fp = j["false_positive_minimizer"];
                current_config_.false_positive.enabled = fp.value("enabled", true);
                current_config_.false_positive.enable_whitelist = fp.value("enable_whitelist", true);
                current_config_.false_positive.enable_reputation_system = fp.value("enable_reputation", true);
                current_config_.false_positive.enable_signature_verification = fp.value("enable_signature_verification", true);
                current_config_.false_positive.enable_behavioral_analysis = fp.value("enable_behavioral_analysis", true);
                current_config_.false_positive.min_reputation_score = fp.value("min_reputation_score", 0.6);
                current_config_.false_positive.max_fp_adjustment = fp.value("max_fp_adjustment", 0.8);
                current_config_.false_positive.reputation_history_days = fp.value("reputation_history_days", 30);
                current_config_.false_positive.auto_whitelist_signed = fp.value("auto_whitelist_signed", false);
                current_config_.false_positive.strict_mode = fp.value("strict_mode", false);

                if (fp.contains("trusted_publishers") && fp["trusted_publishers"].is_array()) {
                    current_config_.false_positive.trusted_publishers.clear();
                    for (const auto& pub : fp["trusted_publishers"]) {
                        current_config_.false_positive.trusted_publishers.push_back(
                            std::wstring(pub.get<std::string>().begin(), pub.get<std::string>().end())
                        );
                    }
                }
                if (fp.contains("trusted_backup_software") && fp["trusted_backup_software"].is_array()) {
                    current_config_.false_positive.trusted_backup_software.clear();
                    for (const auto& proc : fp["trusted_backup_software"]) {
                        current_config_.false_positive.trusted_backup_software.push_back(
                            std::wstring(proc.get<std::string>().begin(), proc.get<std::string>().end())
                        );
                    }
                }
                if (fp.contains("trusted_compression_software") && fp["trusted_compression_software"].is_array()) {
                    current_config_.false_positive.trusted_compression_software.clear();
                    for (const auto& proc : fp["trusted_compression_software"]) {
                        current_config_.false_positive.trusted_compression_software.push_back(
                            std::wstring(proc.get<std::string>().begin(), proc.get<std::string>().end())
                        );
                    }
                }
                if (fp.contains("trusted_dev_software") && fp["trusted_dev_software"].is_array()) {
                    current_config_.false_positive.trusted_dev_software.clear();
                    for (const auto& proc : fp["trusted_dev_software"]) {
                        current_config_.false_positive.trusted_dev_software.push_back(
                            std::wstring(proc.get<std::string>().begin(), proc.get<std::string>().end())
                        );
                    }
                }
                if (fp.contains("trusted_system_software") && fp["trusted_system_software"].is_array()) {
                    current_config_.false_positive.trusted_system_software.clear();
                    for (const auto& proc : fp["trusted_system_software"]) {
                        current_config_.false_positive.trusted_system_software.push_back(
                            std::wstring(proc.get<std::string>().begin(), proc.get<std::string>().end())
                        );
                    }
                }
            }

            // Parse response configuration
            if (j.contains("response")) {
                auto& r = j["response"];
                current_config_.response.enable_auto_response = r.value("enable_auto_response", true);
                current_config_.response.enable_process_termination = r.value("enable_process_termination", true);
                current_config_.response.enable_file_quarantine = r.value("enable_file_quarantine", true);
                current_config_.response.enable_network_isolation = r.value("enable_network_isolation", false);
                current_config_.response.enable_alerts = r.value("enable_alerts", true);
                current_config_.response.enable_logging_only_mode = r.value("logging_only_mode", false);
                current_config_.response.response_delay_ms = r.value("response_delay_ms", 1000);
            }

            // Parse performance configuration
            if (j.contains("performance")) {
                auto& perf = j["performance"];
                current_config_.performance.max_concurrent_analyses = perf.value("max_concurrent_analyses", 10);
                current_config_.performance.analysis_timeout_ms = perf.value("analysis_timeout_ms", 5000);
                current_config_.performance.cache_size_mb = perf.value("cache_size_mb", 50);
                current_config_.performance.enable_gpu_acceleration = perf.value("enable_gpu_acceleration", false);
                current_config_.performance.enable_simd_optimization = perf.value("enable_simd_optimization", true);
                current_config_.performance.batch_processing_size = perf.value("batch_processing_size", 100);
                current_config_.performance.cpu_usage_limit_percent = perf.value("cpu_usage_limit_percent", 50.0);
                current_config_.performance.enable_adaptive_performance = perf.value("enable_adaptive_performance", true);
            }

            // Set metadata
            current_config_.config_version = L"1.0";
            current_config_.last_modified = std::chrono::system_clock::now();
            current_config_.modified_by = L"ConfigManager";

            // Validate loaded configuration
            auto validation = ValidateConfiguration(current_config_);
            if (!validation.is_valid) {
                std::wcerr << L"[ConfigManager] Configuration validation failed:" << std::endl;
                for (const auto& error : validation.errors) {
                    std::wcerr << L"  ERROR: " << error << std::endl;
                }
                return false;
            }

            current_config_file_ = config_file;

            // Update statistics
            statistics_.last_load_time = std::chrono::system_clock::now();
            statistics_.total_parameters = 50; // Approximate count

            std::wcout << L"[ConfigManager] Configuration loaded successfully from "
                << config_file << std::endl;

            return true;
        }
        catch (const std::exception& e) {
            std::wcerr << L"[ConfigManager] Error loading configuration: "
                << e.what() << std::endl;
            return false;
        }
    }


    /**
     * @brief Save configuration to file
     */
    bool DetectionConfigManager::SaveConfiguration(const std::wstring& config_file) const
    {
        try {
            nlohmann::json j;

            std::lock_guard<std::mutex> lock(config_mutex_);

            // Save metadata
            j["version"] = "1.0";
            j["timestamp"] = std::chrono::system_clock::now().time_since_epoch().count();

            // Save global settings
            j["global"]["enable_detection"] = current_config_.global.enable_detection;
            j["global"]["enable_logging"] = current_config_.global.enable_logging;
            j["global"]["enable_telemetry"] = current_config_.global.enable_telemetry;
            j["global"]["debug_mode"] = current_config_.global.debug_mode;
            /*j["global"]["log_directory"] = std::string(
                current_config_.global.log_directory.begin(),
                current_config_.global.log_directory.end()
            );*/
            j["global"]["log_directory"] = CryptoShield::Utils::to_string_utf8(current_config_.global.log_directory); // current_config_.global.log_directory;
            j["global"]["max_log_size_mb"] = current_config_.global.max_log_size_mb;
            j["global"]["log_retention_days"] = current_config_.global.log_retention_days;
            j["global"]["thread_pool_size"] = current_config_.global.thread_pool_size;
            j["global"]["max_memory_usage_mb"] = current_config_.global.max_memory_usage_mb;

            // Save entropy configuration
            j["entropy_analysis"]["enabled"] = current_config_.entropy.enabled;
            j["entropy_analysis"]["weight"] = current_config_.entropy.weight;
            j["entropy_analysis"]["threshold_text_files"] = current_config_.entropy.threshold_text_files;
            j["entropy_analysis"]["threshold_images"] = current_config_.entropy.threshold_images;
            j["entropy_analysis"]["threshold_executables"] = current_config_.entropy.threshold_executables;
            j["entropy_analysis"]["threshold_compressed"] = current_config_.entropy.threshold_compressed;
            j["entropy_analysis"]["threshold_databases"] = current_config_.entropy.threshold_databases;
            j["entropy_analysis"]["threshold_unknown"] = current_config_.entropy.threshold_unknown;
            j["entropy_analysis"]["block_size"] = current_config_.entropy.block_size;
            j["entropy_analysis"]["enable_chi_square"] = current_config_.entropy.enable_chi_square;
            j["entropy_analysis"]["enable_hamming_distance"] = current_config_.entropy.enable_hamming_distance;
            j["entropy_analysis"]["enable_advanced_analysis"] = current_config_.entropy.enable_advanced_analysis;
            j["entropy_analysis"]["max_file_size_for_analysis"] = current_config_.entropy.max_file_size_for_analysis;

            // Save behavioral configuration
            j["behavioral_detection"]["enabled"] = current_config_.behavioral.enabled;
            j["behavioral_detection"]["weight"] = current_config_.behavioral.weight;
            j["behavioral_detection"]["min_operations"] = current_config_.behavioral.min_operations_threshold;
            j["behavioral_detection"]["min_directories"] = current_config_.behavioral.min_directories_threshold;
            j["behavioral_detection"]["min_extensions"] = current_config_.behavioral.min_extensions_threshold;
            j["behavioral_detection"]["max_ops_per_second"] = current_config_.behavioral.max_operations_per_second;
            j["behavioral_detection"]["time_window_seconds"] = current_config_.behavioral.time_window_seconds;
            j["behavioral_detection"]["track_extension_changes"] = current_config_.behavioral.track_extension_changes;
            j["behavioral_detection"]["track_directory_traversal"] = current_config_.behavioral.track_directory_traversal;
            j["behavioral_detection"]["track_temporal_patterns"] = current_config_.behavioral.track_temporal_patterns;
            j["behavioral_detection"]["suspicion_score_threshold"] = current_config_.behavioral.suspicion_score_threshold;

            // Save suspicious extensions
            auto& exts = j["behavioral_detection"]["suspicious_extensions"];
            exts = nlohmann::json::array(); // Initialize as array
            for (const auto& ext : current_config_.behavioral.suspicious_extensions) {
                //exts.push_back(std::string(ext.begin(), ext.end()));
                exts.push_back(CryptoShield::Utils::to_string_utf8(ext));
            }
            auto& patterns_regex = j["behavioral_detection"]["suspicious_patterns_regex"];
            patterns_regex = nlohmann::json::array(); // Initialize as array
            for (const auto& pat : current_config_.behavioral.suspicious_patterns_regex) {
                patterns_regex.push_back(CryptoShield::Utils::to_string_utf8(pat));
            }

            // Save system monitoring configuration
            j["system_monitoring"]["enabled"] = current_config_.system_activity.enabled;
            j["system_monitoring"]["weight"] = current_config_.system_activity.weight;
            j["system_monitoring"]["monitor_shadow_copy"] = current_config_.system_activity.monitor_shadow_copy_deletion;
            j["system_monitoring"]["monitor_registry"] = current_config_.system_activity.monitor_registry_changes;
            j["system_monitoring"]["monitor_boot_config"] = current_config_.system_activity.monitor_boot_configuration;
            j["system_monitoring"]["monitor_security_software"] = current_config_.system_activity.monitor_security_software;
            j["system_monitoring"]["monitor_network"] = current_config_.system_activity.monitor_network_activity;
            j["system_monitoring"]["command_history_size"] = current_config_.system_activity.command_line_history_size;
            j["system_monitoring"]["registry_history_size"] = current_config_.system_activity.registry_history_size;

            // Save scoring configuration
            j["scoring"]["entropy_weight"] = current_config_.scoring.entropy_weight;
            j["scoring"]["behavioral_weight"] = current_config_.scoring.behavioral_weight;
            j["scoring"]["system_activity_weight"] = current_config_.scoring.system_activity_weight;
            j["scoring"]["temporal_weight"] = current_config_.scoring.temporal_weight;
            j["scoring"]["threshold_low"] = current_config_.scoring.threshold_low;
            j["scoring"]["threshold_medium"] = current_config_.scoring.threshold_medium;
            j["scoring"]["threshold_high"] = current_config_.scoring.threshold_high;
            j["scoring"]["threshold_critical"] = current_config_.scoring.threshold_critical;
            j["scoring"]["enable_fp_reduction"] = current_config_.scoring.enable_false_positive_reduction;
            j["scoring"]["false_positive_weight"] = current_config_.scoring.false_positive_weight;
            j["scoring"]["enable_detailed_explanation"] = current_config_.scoring.enable_detailed_explanation;
            j["scoring"]["enable_confidence_boosting"] = current_config_.scoring.enable_confidence_boosting;
            j["scoring"]["confidence_boost_threshold"] = current_config_.scoring.confidence_boost_threshold;

            // Save pattern database configuration
            j["pattern_database"]["enabled"] = current_config_.pattern_database.enabled;
            /*j["pattern_database"]["database_file"] = std::string(
                current_config_.pattern_database.database_file.begin(),
                current_config_.pattern_database.database_file.end()
            );*/

            j["pattern_database"]["database_file"] = CryptoShield::Utils::to_string_utf8(current_config_.pattern_database.database_file); //current_config_.pattern_database.database_file;

            j["pattern_database"]["auto_update"] = current_config_.pattern_database.auto_update;
            j["pattern_database"]["update_interval_hours"] = current_config_.pattern_database.update_interval_hours;
            j["pattern_database"]["enable_custom_patterns"] = current_config_.pattern_database.enable_custom_patterns;
            j["pattern_database"]["max_patterns"] = current_config_.pattern_database.max_patterns;
            j["pattern_database"]["min_pattern_confidence"] = current_config_.pattern_database.min_pattern_confidence;
            j["pattern_database"]["enable_fuzzy_matching"] = current_config_.pattern_database.enable_fuzzy_matching;
            j["pattern_database"]["fuzzy_match_threshold"] = current_config_.pattern_database.fuzzy_match_threshold;

            // Save false positive configuration
            j["false_positive_minimizer"]["enabled"] = current_config_.false_positive.enabled;
            j["false_positive_minimizer"]["enable_whitelist"] = current_config_.false_positive.enable_whitelist;
            j["false_positive_minimizer"]["enable_reputation"] = current_config_.false_positive.enable_reputation_system;
            j["false_positive_minimizer"]["enable_signature_verification"] = current_config_.false_positive.enable_signature_verification;
            j["false_positive_minimizer"]["enable_behavioral_analysis"] = current_config_.false_positive.enable_behavioral_analysis;
            j["false_positive_minimizer"]["min_reputation_score"] = current_config_.false_positive.min_reputation_score;
            j["false_positive_minimizer"]["max_fp_adjustment"] = current_config_.false_positive.max_fp_adjustment;
            j["false_positive_minimizer"]["reputation_history_days"] = current_config_.false_positive.reputation_history_days;
            j["false_positive_minimizer"]["auto_whitelist_signed"] = current_config_.false_positive.auto_whitelist_signed;
            j["false_positive_minimizer"]["strict_mode"] = current_config_.false_positive.strict_mode;

            auto& trusted_pubs = j["false_positive_minimizer"]["trusted_publishers"];
            trusted_pubs = nlohmann::json::array(); // Initialize as array
            for (const auto& pub : current_config_.false_positive.trusted_publishers) {
                trusted_pubs.push_back(CryptoShield::Utils::to_string_utf8(pub));
            }
            auto& backup_sw = j["false_positive_minimizer"]["trusted_backup_software"];
            backup_sw = nlohmann::json::array(); // Initialize as array
            for (const auto& proc : current_config_.false_positive.trusted_backup_software) {
                backup_sw.push_back(CryptoShield::Utils::to_string_utf8(proc));
            }
            auto& comp_sw = j["false_positive_minimizer"]["trusted_compression_software"];
            comp_sw = nlohmann::json::array(); // Initialize as array
            for (const auto& proc : current_config_.false_positive.trusted_compression_software) {
                comp_sw.push_back(CryptoShield::Utils::to_string_utf8(proc));
            }
            auto& dev_sw = j["false_positive_minimizer"]["trusted_dev_software"];
            dev_sw = nlohmann::json::array(); // Initialize as array
            for (const auto& proc : current_config_.false_positive.trusted_dev_software) {
                dev_sw.push_back(CryptoShield::Utils::to_string_utf8(proc));
            }
            auto& sys_sw = j["false_positive_minimizer"]["trusted_system_software"];
            sys_sw = nlohmann::json::array(); // Initialize as array
            for (const auto& proc : current_config_.false_positive.trusted_system_software) {
                sys_sw.push_back(CryptoShield::Utils::to_string_utf8(proc));
            }

            // Save response configuration
            j["response"]["enable_auto_response"] = current_config_.response.enable_auto_response;
            j["response"]["enable_process_termination"] = current_config_.response.enable_process_termination;
            j["response"]["enable_file_quarantine"] = current_config_.response.enable_file_quarantine;
            j["response"]["enable_network_isolation"] = current_config_.response.enable_network_isolation;
            j["response"]["enable_alerts"] = current_config_.response.enable_alerts;
            j["response"]["logging_only_mode"] = current_config_.response.enable_logging_only_mode;
            j["response"]["response_delay_ms"] = current_config_.response.response_delay_ms;

            // Save performance configuration
            j["performance"]["max_concurrent_analyses"] = current_config_.performance.max_concurrent_analyses;
            j["performance"]["analysis_timeout_ms"] = current_config_.performance.analysis_timeout_ms;
            j["performance"]["cache_size_mb"] = current_config_.performance.cache_size_mb;
            j["performance"]["enable_gpu_acceleration"] = current_config_.performance.enable_gpu_acceleration;
            j["performance"]["enable_simd_optimization"] = current_config_.performance.enable_simd_optimization;
            j["performance"]["batch_processing_size"] = current_config_.performance.batch_processing_size;
            j["performance"]["cpu_usage_limit_percent"] = current_config_.performance.cpu_usage_limit_percent;
            j["performance"]["enable_adaptive_performance"] = current_config_.performance.enable_adaptive_performance;

            // Write to file
            std::ofstream file(config_file);
            if (!file.is_open()) {
                std::wcerr << L"[ConfigManager] Failed to create config file: "
                    << config_file << std::endl;
                return false;
            }

            file << j.dump(4); // Pretty print with 4 spaces

            // Update statistics
            const_cast<DetectionConfigManager*>(this)->statistics_.last_save_time =
                std::chrono::system_clock::now();

            std::wcout << L"[ConfigManager] Configuration saved successfully to "
                << config_file << std::endl;

            return true;
        }
        catch (const std::exception& e) {
            std::wcerr << L"[ConfigManager] Error saving configuration: "
                << e.what() << std::endl;
            return false;
        }
    }

    /**
     * @brief Get current configuration
     */
    DetectionEngineConfig DetectionConfigManager::GetConfiguration() const
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        return current_config_;
    }

    /**
     * @brief Update configuration
     */
    ConfigValidationResult DetectionConfigManager::UpdateConfiguration(
        const DetectionEngineConfig& config)
    {
        // Validate new configuration
        auto validation = ValidateConfiguration(config);
        if (!validation.is_valid) {
            return validation;
        }

        std::lock_guard<std::mutex> lock(config_mutex_);

        // Store old config for change tracking
        auto old_config = current_config_;

        // Update configuration
        current_config_ = config;
        current_config_.last_modified = std::chrono::system_clock::now();

        // Track changes
        // This is a simplified implementation - in production would compare all fields
        RecordChange(L"global", L"configuration", L"previous", L"updated");

        // Update statistics
        statistics_.change_count++;

        std::wcout << L"[ConfigManager] Configuration updated successfully" << std::endl;

        return validation;
    }

    /**
     * @brief Validate configuration
     */
    ConfigValidationResult DetectionConfigManager::ValidateConfiguration(
        const DetectionEngineConfig& config) const
    {
        ConfigValidationResult result;
        result.is_valid = true;

        // Validate global settings
        ValidateGlobalSettings(config.global, result);

        // Validate entropy configuration
        ValidateEntropyConfig(config.entropy, result);

        // Validate behavioral configuration
        ValidateBehavioralConfig(config.behavioral, result);

        // Validate scoring configuration
        ValidateScoringConfig(config.scoring, result);

        // Additional validations...

        return result;
    }

    /**
     * @brief Get default configuration
     */
    DetectionEngineConfig DetectionConfigManager::GetDefaultConfiguration()
    {
        DetectionEngineConfig config;

        // Set version info
        config.config_version = L"1.0";
        config.last_modified = std::chrono::system_clock::now();
        config.modified_by = L"System";

        // Global settings
        config.global.enable_detection = true;
        config.global.enable_logging = true;
        config.global.enable_telemetry = false;
        config.global.debug_mode = false;
        config.global.log_directory = L"C:\\ProgramData\\CryptoShield\\Logs";
        config.global.max_log_size_mb = 100;
        config.global.log_retention_days = 30;
        config.global.thread_pool_size = 4;
        config.global.max_memory_usage_mb = 200;

        // Entropy configuration
        config.entropy.enabled = true;
        config.entropy.weight = 0.30;
        config.entropy.threshold_text_files = 4.5;
        config.entropy.threshold_images = 7.0;
        config.entropy.threshold_executables = 6.0;
        config.entropy.threshold_compressed = 7.8;
        config.entropy.threshold_databases = 5.5;
        config.entropy.threshold_unknown = 6.5;
        config.entropy.block_size = 4096;
        config.entropy.enable_chi_square = true;
        config.entropy.enable_hamming_distance = true;
        config.entropy.enable_advanced_analysis = true;
        config.entropy.max_file_size_for_analysis = 104857600; // 100MB

        // Behavioral configuration
        config.behavioral.enabled = true;
        config.behavioral.weight = 0.25;
        config.behavioral.min_operations_threshold = 50;
        config.behavioral.min_directories_threshold = 3;
        config.behavioral.min_extensions_threshold = 2;
        config.behavioral.max_operations_per_second = 10.0;
        config.behavioral.time_window_seconds = 60;
        config.behavioral.track_extension_changes = true;
        config.behavioral.track_directory_traversal = true;
        config.behavioral.track_temporal_patterns = true;
        config.behavioral.suspicion_score_threshold = 0.7;
        config.behavioral.suspicious_extensions = {
            L".locked", L".encrypted", L".crypto", L".enc",
            L".crypted", L".kraken", L".darkness", L".nochance"
        };
        config.behavioral.suspicious_patterns_regex = {
            L".*\\.id-[0-9A-F]{8}\\.[a-z]+@[a-z]+\\.[a-z]+$",
            L".*\\.[0-9A-F]{32}$"
        };

        // System activity configuration
        config.system_activity.enabled = true;
        config.system_activity.weight = 0.25;
        config.system_activity.monitor_shadow_copy_deletion = true;
        config.system_activity.monitor_registry_changes = true;
        config.system_activity.monitor_boot_configuration = true;
        config.system_activity.monitor_security_software = true;
        config.system_activity.monitor_network_activity = false;
        config.system_activity.command_line_history_size = 1000;
        config.system_activity.registry_history_size = 5000;

        // Scoring configuration
        config.scoring.entropy_weight = 0.30;
        config.scoring.behavioral_weight = 0.25;
        config.scoring.system_activity_weight = 0.25;
        config.scoring.temporal_weight = 0.20;
        config.scoring.threshold_low = 0.3;
        config.scoring.threshold_medium = 0.6;
        config.scoring.threshold_high = 0.8;
        config.scoring.threshold_critical = 0.95;
        config.scoring.enable_false_positive_reduction = true;
        config.scoring.false_positive_weight = 0.15;
        config.scoring.enable_detailed_explanation = true;
        config.scoring.enable_confidence_boosting = true;
        config.scoring.confidence_boost_threshold = 0.8;

        // Pattern database configuration
        config.pattern_database.enabled = true;
        config.pattern_database.database_file = L"patterns.db";
        config.pattern_database.auto_update = false;
        config.pattern_database.update_interval_hours = 24;
        config.pattern_database.enable_custom_patterns = true;
        config.pattern_database.max_patterns = 10000;
        config.pattern_database.min_pattern_confidence = 0.5;
        config.pattern_database.enable_fuzzy_matching = true;
        config.pattern_database.fuzzy_match_threshold = 0.8;

        // False positive configuration
        config.false_positive.enabled = true;
        config.false_positive.enable_whitelist = true;
        config.false_positive.enable_reputation_system = true;
        config.false_positive.enable_signature_verification = true;
        config.false_positive.enable_behavioral_analysis = true;
        config.false_positive.min_reputation_score = 0.6;
        config.false_positive.max_fp_adjustment = 0.8;
        config.false_positive.reputation_history_days = 30;
        config.false_positive.auto_whitelist_signed = false;
        config.false_positive.strict_mode = false;
        config.false_positive.trusted_publishers = { L"Microsoft Corporation", L"Google LLC" };
        config.false_positive.trusted_backup_software = { L"Acronis", L"Veeam", L"Macrium" };
        config.false_positive.trusted_compression_software = { L"WinRAR", L"7-Zip", L"WinZip" };
        config.false_positive.trusted_dev_software = { L"devenv", L"cl.exe", L"gcc" };
        config.false_positive.trusted_system_software = { L"TrustedInstaller", L"svchost" };

        // Response configuration
        config.response.enable_auto_response = true;
        config.response.enable_process_termination = true;
        config.response.enable_file_quarantine = true;
        config.response.enable_network_isolation = false;
        config.response.enable_alerts = true;
        config.response.enable_logging_only_mode = false;
        config.response.response_delay_ms = 1000;

        // Performance configuration
        config.performance.max_concurrent_analyses = 10;
        config.performance.analysis_timeout_ms = 5000;
        config.performance.cache_size_mb = 50;
        config.performance.enable_gpu_acceleration = false;
        config.performance.enable_simd_optimization = true;
        config.performance.batch_processing_size = 100;
        config.performance.cpu_usage_limit_percent = 50.0;
        config.performance.enable_adaptive_performance = true;

        return config;
    }

    /**
     * @brief Reset to default configuration
     */
    void DetectionConfigManager::ResetToDefaults()
    {
        std::lock_guard<std::mutex> lock(config_mutex_);

        auto old_config = current_config_;
        current_config_ = GetDefaultConfiguration();

        RecordChange(L"global", L"configuration", L"custom", L"default");

        std::wcout << L"[ConfigManager] Configuration reset to defaults" << std::endl;
    }

    /**
     * @brief Validate global settings
     */
    void DetectionConfigManager::ValidateGlobalSettings(
        const DetectionEngineConfig::GlobalSettings& settings,
        ConfigValidationResult& result) const
    {
        // Validate log directory
        if (settings.log_directory.empty()) {
            result.errors.push_back(L"Log directory cannot be empty");
            result.is_valid = false;
        }

        // Validate numeric ranges
        if (settings.max_log_size_mb == 0) {
            result.errors.push_back(L"Max log size must be greater than 0");
            result.is_valid = false;
        }

        if (settings.thread_pool_size == 0) {
            result.errors.push_back(L"Thread pool size must be at least 1");
            result.is_valid = false;
        }

        if (settings.thread_pool_size > 32) {
            result.warnings.push_back(L"Thread pool size > 32 may impact performance");
        }

        if (settings.max_memory_usage_mb < 50) {
            result.errors.push_back(L"Memory usage limit too low (minimum 50MB)");
            result.is_valid = false;
        }
    }

    /**
     * @brief Validate entropy configuration
     */
    void DetectionConfigManager::ValidateEntropyConfig(
        const DetectionEngineConfig::EntropyConfig& config,
        ConfigValidationResult& result) const
    {
        // Validate thresholds
        if (config.threshold_text_files < 0 || config.threshold_text_files > 8) {
            result.errors.push_back(L"Text file entropy threshold must be between 0 and 8");
            result.is_valid = false;
        }

        if (config.threshold_images < 0 || config.threshold_images > 8) {
            result.errors.push_back(L"Image entropy threshold must be between 0 and 8");
            result.is_valid = false;
        }

        // Validate block size
        if (config.block_size < 256 || config.block_size > 1048576) {
            result.errors.push_back(L"Block size must be between 256 and 1MB");
            result.is_valid = false;
        }

        // Validate weight
        if (config.weight < 0 || config.weight > 1) {
            result.errors.push_back(L"Entropy weight must be between 0 and 1");
            result.is_valid = false;
        }
    }

    /**
     * @brief Validate behavioral configuration
     */
    void DetectionConfigManager::ValidateBehavioralConfig(
        const DetectionEngineConfig::BehavioralConfig& config,
        ConfigValidationResult& result) const
    {
        // Validate thresholds
        if (config.min_operations_threshold == 0) {
            result.warnings.push_back(L"Min operations threshold of 0 may cause false positives");
        }

        if (config.max_operations_per_second <= 0) {
            result.errors.push_back(L"Max operations per second must be positive");
            result.is_valid = false;
        }

        if (config.time_window_seconds < 10) {
            result.warnings.push_back(L"Time window < 10 seconds may be too short");
        }

        // Validate weight
        if (config.weight < 0 || config.weight > 1) {
            result.errors.push_back(L"Behavioral weight must be between 0 and 1");
            result.is_valid = false;
        }
    }

    /**
     * @brief Validate scoring configuration
     */
    void DetectionConfigManager::ValidateScoringConfig(
        const DetectionEngineConfig::ScoringConfig& config,
        ConfigValidationResult& result) const
    {
        // Validate weights sum to 1.0
        double weight_sum = config.entropy_weight + config.behavioral_weight +
            config.system_activity_weight + config.temporal_weight;

        if (std::abs(weight_sum - 1.0) > 0.01) {
            result.errors.push_back(L"Scoring weights must sum to 1.0");
            result.is_valid = false;
        }

        // Validate thresholds are in order
        if (config.threshold_low >= config.threshold_medium ||
            config.threshold_medium >= config.threshold_high ||
            config.threshold_high >= config.threshold_critical) {
            result.errors.push_back(L"Threat thresholds must be in ascending order");
            result.is_valid = false;
        }

        // Validate threshold ranges
        if (config.threshold_critical > 1.0 || config.threshold_low < 0.0) {
            result.errors.push_back(L"Threat thresholds must be between 0 and 1");
            result.is_valid = false;
        }
    }

    /**
     * @brief Record configuration change
     */
    void DetectionConfigManager::RecordChange(const std::wstring& component,
        const std::wstring& parameter,
        const std::wstring& old_value,
        const std::wstring& new_value)
    {
        ConfigChangeEvent event;
        event.component_name = component;
        event.parameter_name = parameter;
        event.old_value = old_value;
        event.new_value = new_value;
        event.timestamp = std::chrono::system_clock::now();
        event.changed_by = L"System";

        {
            std::lock_guard<std::mutex> lock(history_mutex_);
            change_history_.push_back(event);

            // Keep only last 1000 changes
            if (change_history_.size() > 1000) {
                change_history_.erase(change_history_.begin());
            }
        }

        // Notify callbacks
        NotifyChangeCallbacks(event);
    }

    /**
     * @brief Notify change callbacks
     */
    void DetectionConfigManager::NotifyChangeCallbacks(const ConfigChangeEvent& event)
    {
        std::lock_guard<std::mutex> lock(callbacks_mutex_);

        for (const auto& callback : change_callbacks_) {
            try {
                callback(event);
            }
            catch (const std::exception& e) {
                std::wcerr << L"[ConfigManager] Callback exception: " << e.what() << std::endl;
            }
        }
    }

    /**
     * @brief Export configuration as JSON
     */
    std::string DetectionConfigManager::ExportAsJson() const
    {
        // Create a temporary file and save to it
        wchar_t temp_path[MAX_PATH];
        wchar_t temp_file[MAX_PATH];

        GetTempPathW(MAX_PATH, temp_path);
        GetTempFileNameW(temp_path, L"cfg", 0, temp_file);

        if (SaveConfiguration(temp_file)) {
            std::ifstream file(temp_file);
            std::stringstream buffer;
            buffer << file.rdbuf();

            // Delete temp file
            DeleteFileW(temp_file);

            return buffer.str();
        }

        return "{}";
    }

    /**
     * @brief Get statistics
     */
    DetectionConfigManager::ConfigStatistics DetectionConfigManager::GetStatistics() const
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);

        ConfigStatistics stats = statistics_;

        // Count enabled components
        stats.enabled_components = 0;
        if (current_config_.entropy.enabled) stats.enabled_components++;
        if (current_config_.behavioral.enabled) stats.enabled_components++;
        if (current_config_.system_activity.enabled) stats.enabled_components++;
        if (current_config_.pattern_database.enabled) stats.enabled_components++;
        if (current_config_.false_positive.enabled) stats.enabled_components++;

        stats.disabled_components = 5 - stats.enabled_components;

        return stats;
    }

    /**
     * @brief Create configuration template
     */
    bool DetectionConfigManager::CreateConfigurationTemplate(
        const std::wstring& template_file,
        bool include_comments)
    {
        try {
            // Get default configuration
            auto default_config = GetDefaultConfiguration();

            // Create manager and save
            DetectionConfigManager manager;
            manager.current_config_ = default_config;

            return manager.SaveConfiguration(template_file);
        }
        catch (const std::exception& e) {
            std::wcerr << L"[ConfigManager] Error creating template: " << e.what() << std::endl;
            return false;
        }
    }

} // namespace CryptoShield::Detection