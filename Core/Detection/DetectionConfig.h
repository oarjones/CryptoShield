#pragma once
/**
 * @file DetectionConfig.h
 * @brief Unified configuration system for traditional detection engine
 * @details Manages all configuration parameters for detection components
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
#include <memory>
#include <optional>
#include <chrono>
#include <mutex>
#include <functional>

namespace CryptoShield::Detection {

	/**
	 * @brief Configuration validation result
	 */
	struct ConfigValidationResult {
		bool is_valid;
		std::vector<std::wstring> errors;
		std::vector<std::wstring> warnings;
		std::map<std::wstring, std::wstring> suggestions;
	};

	/**
	 * @brief Configuration change event
	 */
	struct ConfigChangeEvent {
		std::wstring component_name;
		std::wstring parameter_name;
		std::wstring old_value;
		std::wstring new_value;
		std::chrono::system_clock::time_point timestamp;
		std::wstring changed_by;
	};

	/**
	 * @brief Master configuration structure
	 * @details Contains all configuration parameters for the detection engine
	 */
	struct DetectionEngineConfig {
		// Engine metadata
		std::wstring config_version;
		std::chrono::system_clock::time_point last_modified;
		std::wstring modified_by;

		// Global settings
		struct GlobalSettings {
			bool enable_detection;
			bool enable_logging;
			bool enable_telemetry;
			bool debug_mode;
			std::wstring log_directory;
			size_t max_log_size_mb;
			size_t log_retention_days;
			size_t thread_pool_size;
			size_t max_memory_usage_mb;
		} global;

		// Entropy analysis configuration
		struct EntropyConfig {
			bool enabled;
			double weight;
			double threshold_text_files;
			double threshold_images;
			double threshold_executables;
			double threshold_compressed;
			double threshold_databases;
			double threshold_unknown;
			size_t block_size;
			bool enable_chi_square;
			bool enable_hamming_distance;
			bool enable_advanced_analysis;
			size_t max_file_size_for_analysis;
		} entropy;

		// Behavioral detection configuration
		struct BehavioralConfig {
			bool enabled;
			double weight;
			size_t min_operations_threshold;
			size_t min_directories_threshold;
			size_t min_extensions_threshold;
			double max_operations_per_second;
			size_t time_window_seconds;
			bool track_extension_changes;
			bool track_directory_traversal;
			bool track_temporal_patterns;
			std::vector<std::wstring> suspicious_extensions;
			double suspicion_score_threshold;
			std::vector<std::wstring> suspicious_patterns_regex;
			std::chrono::seconds window_duration;
		} behavioral;

		// System activity monitoring configuration
		struct SystemActivityConfig {
			bool enabled;
			double weight;
			bool monitor_shadow_copy_deletion;
			bool monitor_registry_changes;
			bool monitor_boot_configuration;
			bool monitor_security_software;
			bool monitor_network_activity;
			size_t command_line_history_size;
			size_t registry_history_size;
			std::vector<std::wstring> critical_registry_keys;
			std::vector<std::wstring> suspicious_commands;
		} system_activity;

		// Scoring engine configuration
		struct ScoringConfig {
			double entropy_weight;
			double behavioral_weight;
			double system_activity_weight;
			double temporal_weight;
			double threshold_low;
			double threshold_medium;
			double threshold_high;
			double threshold_critical;
			bool enable_false_positive_reduction;
			double false_positive_weight;
			bool enable_detailed_explanation;
			bool enable_confidence_boosting;
			double confidence_boost_threshold;
		} scoring;

		// Pattern database configuration
		struct PatternDatabaseConfig {
			bool enabled;
			std::wstring database_file;
			bool auto_update;
			size_t update_interval_hours;
			std::wstring update_server;
			bool enable_custom_patterns;
			std::wstring custom_patterns_file;
			size_t max_patterns;
			double min_pattern_confidence;
			bool enable_fuzzy_matching;
			double fuzzy_match_threshold;
		} pattern_database;

		// False positive minimizer configuration
		struct FalsePositiveConfig {
			bool enabled;
			bool enable_whitelist;
			bool enable_reputation_system;
			bool enable_signature_verification;
			bool enable_behavioral_analysis;
			double min_reputation_score;
			double max_fp_adjustment;
			size_t reputation_history_days;
			bool auto_whitelist_signed;
			bool strict_mode;
			std::wstring whitelist_file;
			std::wstring reputation_database;
			std::vector<std::wstring> trusted_publishers;
			std::vector<std::wstring> trusted_backup_software;
			std::vector<std::wstring> trusted_compression_software;
			std::vector<std::wstring> trusted_dev_software;
			std::vector<std::wstring> trusted_system_software;
		} false_positive;

		// Response configuration
		struct ResponseConfig {
			bool enable_auto_response;
			bool enable_process_termination;
			bool enable_file_quarantine;
			bool enable_network_isolation;
			bool enable_alerts;
			bool enable_logging_only_mode;
			size_t response_delay_ms;
			std::vector<std::wstring> alert_recipients;
			std::wstring quarantine_directory;
		} response;

		// Performance tuning
		struct PerformanceConfig {
			size_t max_concurrent_analyses;
			size_t analysis_timeout_ms;
			size_t cache_size_mb;
			bool enable_gpu_acceleration;
			bool enable_simd_optimization;
			size_t batch_processing_size;
			double cpu_usage_limit_percent;
			bool enable_adaptive_performance;
		} performance;
	};

	/**
	 * @brief Configuration manager class
	 * @details Handles loading, saving, validation, and management of configurations
	 */
	class DetectionConfigManager {
	public:
		/**
		 * @brief Constructor
		 */
		DetectionConfigManager();

		/**
		 * @brief Destructor
		 */
		~DetectionConfigManager();

		// Disable copy
		DetectionConfigManager(const DetectionConfigManager&) = delete;
		DetectionConfigManager& operator=(const DetectionConfigManager&) = delete;

		/**
		 * @brief Load configuration from file
		 * @param config_file Path to configuration file
		 * @return true on success
		 */
		bool LoadConfiguration(const std::wstring& config_file);

		/**
		 * @brief Save configuration to file
		 * @param config_file Path to save configuration
		 * @return true on success
		 */
		bool SaveConfiguration(const std::wstring& config_file) const;

		/**
		 * @brief Get current configuration
		 * @return Current configuration
		 */
		DetectionEngineConfig GetConfiguration() const;

		/**
		 * @brief Update configuration
		 * @param config New configuration
		 * @return Validation result
		 */
		ConfigValidationResult UpdateConfiguration(const DetectionEngineConfig& config);

		/**
		 * @brief Validate configuration
		 * @param config Configuration to validate
		 * @return Validation result
		 */
		ConfigValidationResult ValidateConfiguration(const DetectionEngineConfig& config) const;

		/**
		 * @brief Get default configuration
		 * @return Default configuration
		 */
		static DetectionEngineConfig GetDefaultConfiguration();

		/**
		 * @brief Reset to default configuration
		 */
		void ResetToDefaults();

		/**
		 * @brief Merge configurations
		 * @param base Base configuration
		 * @param overlay Configuration to merge
		 * @return Merged configuration
		 */
		static DetectionEngineConfig MergeConfigurations(
			const DetectionEngineConfig& base,
			const DetectionEngineConfig& overlay);

		/**
		 * @brief Export configuration as JSON string
		 * @return JSON representation
		 */
		std::string ExportAsJson() const;

		/**
		 * @brief Import configuration from JSON string
		 * @param json_str JSON string
		 * @return true on success
		 */
		bool ImportFromJson(const std::string& json_str);

		/**
		 * @brief Get configuration parameter
		 * @param path Parameter path (e.g., "entropy.threshold_text_files")
		 * @return Parameter value if found
		 */
		std::optional<std::wstring> GetParameter(const std::wstring& path) const;

		/**
		 * @brief Set configuration parameter
		 * @param path Parameter path
		 * @param value New value
		 * @return true if parameter was set
		 */
		bool SetParameter(const std::wstring& path, const std::wstring& value);

		/**
		 * @brief Get configuration change history
		 * @param max_entries Maximum entries to return
		 * @return Change history
		 */
		std::vector<ConfigChangeEvent> GetChangeHistory(size_t max_entries = 100) const;

		/**
		 * @brief Register configuration change callback
		 * @param callback Function to call on configuration change
		 */
		void RegisterChangeCallback(
			std::function<void(const ConfigChangeEvent&)> callback);

		/**
		 * @brief Validate configuration file
		 * @param config_file Path to configuration file
		 * @return Validation result
		 */
		static ConfigValidationResult ValidateConfigurationFile(
			const std::wstring& config_file);

		/**
		 * @brief Create configuration template
		 * @param template_file Path to save template
		 * @param include_comments Include descriptive comments
		 * @return true on success
		 */
		static bool CreateConfigurationTemplate(const std::wstring& template_file,
			bool include_comments = true);

		/**
		 * @brief Get configuration schema
		 * @return JSON schema for configuration validation
		 */
		static std::string GetConfigurationSchema();

		/**
		 * @brief Backup current configuration
		 * @param backup_file Path to backup file
		 * @return true on success
		 */
		bool BackupConfiguration(const std::wstring& backup_file) const;

		/**
		 * @brief Restore configuration from backup
		 * @param backup_file Path to backup file
		 * @return true on success
		 */
		bool RestoreConfiguration(const std::wstring& backup_file);

		/**
		 * @brief Get configuration statistics
		 */
		struct ConfigStatistics {
			size_t total_parameters;
			size_t enabled_components;
			size_t disabled_components;
			std::chrono::system_clock::time_point last_load_time;
			std::chrono::system_clock::time_point last_save_time;
			size_t change_count;
		};

		ConfigStatistics GetStatistics() const;

	private:
		/**
		 * @brief Validate global settings
		 * @param settings Global settings to validate
		 * @param result Validation result to update
		 */
		void ValidateGlobalSettings(const DetectionEngineConfig::GlobalSettings& settings,
			ConfigValidationResult& result) const;

		/**
		 * @brief Validate entropy configuration
		 * @param config Entropy config to validate
		 * @param result Validation result to update
		 */
		void ValidateEntropyConfig(const DetectionEngineConfig::EntropyConfig& config,
			ConfigValidationResult& result) const;

		/**
		 * @brief Validate behavioral configuration
		 * @param config Behavioral config to validate
		 * @param result Validation result to update
		 */
		void ValidateBehavioralConfig(const DetectionEngineConfig::BehavioralConfig& config,
			ConfigValidationResult& result) const;

		/**
		 * @brief Validate scoring configuration
		 * @param config Scoring config to validate
		 * @param result Validation result to update
		 */
		void ValidateScoringConfig(const DetectionEngineConfig::ScoringConfig& config,
			ConfigValidationResult& result) const;

		/**
		 * @brief Record configuration change
		 * @param component Component name
		 * @param parameter Parameter name
		 * @param old_value Old value
		 * @param new_value New value
		 */
		void RecordChange(const std::wstring& component,
			const std::wstring& parameter,
			const std::wstring& old_value,
			const std::wstring& new_value);

		/**
		 * @brief Notify change callbacks
		 * @param event Change event
		 */
		void NotifyChangeCallbacks(const ConfigChangeEvent& event);

		/**
		 * @brief Parse parameter path
		 * @param path Parameter path
		 * @param component Output component name
		 * @param parameter Output parameter name
		 * @return true if path is valid
		 */
		bool ParseParameterPath(const std::wstring& path,
			std::wstring& component,
			std::wstring& parameter) const;

	private:
		// Current configuration
		mutable std::mutex config_mutex_;
		DetectionEngineConfig current_config_;

		// Change history
		mutable std::mutex history_mutex_;
		std::vector<ConfigChangeEvent> change_history_;

		// Change callbacks
		mutable std::mutex callbacks_mutex_;
		std::vector<std::function<void(const ConfigChangeEvent&)>> change_callbacks_;

		// Statistics
		mutable std::mutex stats_mutex_;
		ConfigStatistics statistics_;

		// Configuration file paths
		std::wstring current_config_file_;
		std::wstring last_backup_file_;

		// Validation state
		mutable ConfigValidationResult last_validation_result_;
	};

	/**
	 * @brief Configuration utilities
	 */
	class ConfigurationUtils {
	public:
		/**
		 * @brief Convert configuration to command line arguments
		 * @param config Configuration
		 * @return Command line arguments
		 */
		static std::vector<std::wstring> ConfigToCommandLine(
			const DetectionEngineConfig& config);

		/**
		 * @brief Parse command line to configuration overrides
		 * @param argc Argument count
		 * @param argv Argument values
		 * @return Configuration with overrides
		 */
		static DetectionEngineConfig ParseCommandLine(int argc, wchar_t* argv[]);

		/**
		 * @brief Generate configuration documentation
		 * @param output_file Path to output file
		 * @param format Documentation format (md, html, txt)
		 * @return true on success
		 */
		static bool GenerateDocumentation(const std::wstring& output_file,
			const std::wstring& format = L"md");

		/**
		 * @brief Compare configurations
		 * @param config1 First configuration
		 * @param config2 Second configuration
		 * @return List of differences
		 */
		static std::vector<std::wstring> CompareConfigurations(
			const DetectionEngineConfig& config1,
			const DetectionEngineConfig& config2);
	};

} // namespace CryptoShield::Detection