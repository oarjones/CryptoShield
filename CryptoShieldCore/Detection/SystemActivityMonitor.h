#pragma once
/**
 * @file SystemActivityMonitor.h
 * @brief System activity monitoring for ransomware detection
 * @details Monitors shadow copy deletion, registry changes, and boot configuration
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <mutex>
#include <atomic>
#include <memory>
#include <optional>

namespace CryptoShield::Detection {

    /**
     * @brief Shadow copy deletion event
     */
    struct ShadowDeletionEvent {
        std::wstring command_line;
        std::wstring process_name;
        ULONG process_id;
        ULONG parent_process_id;
        std::chrono::steady_clock::time_point timestamp;
        double suspicion_score;
        std::wstring detection_reason;
        bool is_legitimate;
    };

    /**
     * @brief Registry modification event
     */
    struct RegistryModificationEvent {
        std::wstring key_path;
        std::wstring value_name;
        std::wstring old_value;
        std::wstring new_value;
        ULONG process_id;
        std::chrono::steady_clock::time_point timestamp;
        bool is_critical_key;
        bool is_startup_key;
        bool is_security_key;
    };

    /**
     * @brief Boot configuration change event
     */
    struct BootConfigChangeEvent {
        std::wstring command_line;
        std::wstring parameter_changed;
        std::wstring old_value;
        std::wstring new_value;
        ULONG process_id;
        std::chrono::steady_clock::time_point timestamp;
        bool disables_recovery;
        bool modifies_safeboot;
    };

    /**
     * @brief Process command line analysis result
     */
    struct CommandLineAnalysis {
        bool is_suspicious;
        double suspicion_score;
        std::vector<std::wstring> matched_patterns;
        std::wstring primary_threat_type;
        std::wstring recommended_action;
    };

    /**
     * @brief Registry threat analysis result
     */
    struct RegistryThreatAnalysis {
        bool is_suspicious;
        double confidence_score;
        std::wstring threat_type;
        std::vector<std::wstring> affected_keys;
        std::wstring description;
        bool requires_immediate_action;
    };

    /**
     * @brief System activity summary
     */
    struct SystemActivitySummary {
        size_t shadow_deletion_attempts;
        size_t registry_modifications;
        size_t boot_config_changes;
        size_t security_bypass_attempts;
        double overall_system_threat_score;
        std::chrono::steady_clock::time_point analysis_timestamp;
        std::vector<std::wstring> high_risk_processes;
    };

    /**
     * @brief Shadow copy deletion detector
     * @details Detects attempts to delete Volume Shadow Copies
     */
    class ShadowCopyDeletionDetector {
    public:
        /**
         * @brief Constructor
         */
        ShadowCopyDeletionDetector();

        /**
         * @brief Destructor
         */
        ~ShadowCopyDeletionDetector() = default;

        /**
         * @brief Analyze command line for shadow deletion
         * @param command_line Full command line to analyze
         * @param process_name Name of process executing command
         * @param process_id Process ID
         * @param parent_pid Parent process ID
         * @return Shadow deletion event
         */
        ShadowDeletionEvent AnalyzeCommandLine(const std::wstring& command_line,
            const std::wstring& process_name,
            ULONG process_id,
            ULONG parent_pid);

        /**
         * @brief Check if process is legitimate for shadow operations
         * @param process_name Process name
         * @param command_line Command being executed
         * @return true if legitimate
         */
        bool IsLegitimateProcess(const std::wstring& process_name,
            const std::wstring& command_line) const;

        /**
         * @brief Get recent shadow deletion events
         * @param max_age Maximum age of events to return
         * @return Vector of recent events
         */
        std::vector<ShadowDeletionEvent> GetRecentEvents(
            std::chrono::seconds max_age = std::chrono::seconds(3600)) const;

        /**
         * @brief Clear event history
         */
        void ClearHistory();

    private:
        /**
         * @brief Score command suspicion level
         * @param command Command line to score
         * @return Suspicion score (0-1)
         */
        double ScoreCommandSuspicion(const std::wstring& command) const;

        /**
         * @brief Score process context
         * @param process_name Process name
         * @param parent_pid Parent process ID
         * @return Context score (0-1)
         */
        double ScoreProcessContext(const std::wstring& process_name, ULONG parent_pid) const;

        /**
         * @brief Check for shadow deletion patterns
         * @param command Command line
         * @return true if matches deletion pattern
         */
        bool MatchesShadowDeletionPattern(const std::wstring& command) const;

        /**
         * @brief Check for recovery disable patterns
         * @param command Command line
         * @return true if disables recovery
         */
        bool MatchesRecoveryDisablePattern(const std::wstring& command) const;

    private:
        // Known suspicious commands
        static const std::vector<std::wstring> SHADOW_DELETION_COMMANDS;
        static const std::vector<std::wstring> BOOT_CONFIG_COMMANDS;
        static const std::vector<std::wstring> RECOVERY_DISABLE_COMMANDS;

        // Legitimate processes that may delete shadows
        static const std::vector<std::wstring> LEGITIMATE_PROCESSES;
        static const std::vector<std::wstring> BACKUP_SOFTWARE;

        // Event history
        std::vector<ShadowDeletionEvent> event_history_;
        mutable std::mutex history_mutex_;
    };

    /**
     * @brief Registry modification tracker
     * @details Monitors critical registry key modifications
     */
    class RegistryModificationTracker {
    public:
        /**
         * @brief Constructor
         */
        RegistryModificationTracker();

        /**
         * @brief Destructor
         */
        ~RegistryModificationTracker() = default;

        /**
         * @brief Analyze registry modification
         * @param key_path Registry key path
         * @param value_name Value name
         * @param old_value Previous value
         * @param new_value New value
         * @param process_id Process making change
         * @return Threat analysis result
         */
        RegistryThreatAnalysis AnalyzeRegistryChange(const std::wstring& key_path,
            const std::wstring& value_name,
            const std::wstring& old_value,
            const std::wstring& new_value,
            ULONG process_id);

        /**
         * @brief Check if key is critical
         * @param key_path Registry key path
         * @return true if critical system key
         */
        bool IsCriticalKey(const std::wstring& key_path) const;

        /**
         * @brief Check if startup modification
         * @param key_path Registry key path
         * @return true if modifies startup
         */
        bool IsStartupModification(const std::wstring& key_path) const;

        /**
         * @brief Check if security bypass attempt
         * @param key_path Registry key path
         * @param value New value being set
         * @return true if attempts security bypass
         */
        bool IsSecurityBypass(const std::wstring& key_path, const std::wstring& value) const;

        /**
         * @brief Get modification history for process
         * @param process_id Process ID
         * @return Vector of modifications
         */
        std::vector<RegistryModificationEvent> GetProcessHistory(ULONG process_id) const;

        /**
         * @brief Clear modification history
         * @param older_than Clear entries older than this
         */
        void ClearHistory(std::chrono::seconds older_than = std::chrono::seconds(3600));

    private:
        /**
         * @brief Calculate modification risk score
         * @param event Modification event
         * @return Risk score (0-1)
         */
        double CalculateRiskScore(const RegistryModificationEvent& event) const;

        /**
         * @brief Check for ransomware-like registry patterns
         * @param key_path Key being modified
         * @param value Value being set
         * @return true if matches ransomware pattern
         */
        bool MatchesRansomwarePattern(const std::wstring& key_path,
            const std::wstring& value) const;

        /**
         * @brief Check if disabling Windows Defender
         * @param key_path Key path
         * @param value New value
         * @return true if disabling defender
         */
        bool IsDisablingDefender(const std::wstring& key_path,
            const std::wstring& value) const;

    private:
        // Critical registry keys to monitor
        static const std::vector<std::wstring> CRITICAL_REGISTRY_KEYS;
        static const std::vector<std::wstring> STARTUP_KEYS;
        static const std::vector<std::wstring> SECURITY_KEYS;
        static const std::vector<std::wstring> DEFENDER_KEYS;

        // Modification history
        std::vector<RegistryModificationEvent> modification_history_;
        mutable std::mutex history_mutex_;

        // Per-process tracking
        std::map<ULONG, std::vector<size_t>> process_modifications_;
    };

    /**
     * @brief Boot configuration monitor
     * @details Monitors changes to boot configuration
     */
    class BootConfigurationMonitor {
    public:
        /**
         * @brief Constructor
         */
        BootConfigurationMonitor();

        /**
         * @brief Destructor
         */
        ~BootConfigurationMonitor() = default;

        /**
         * @brief Analyze boot configuration command
         * @param command_line Command line to analyze
         * @param process_id Process executing command
         * @return Boot config change event
         */
        BootConfigChangeEvent AnalyzeBootCommand(const std::wstring& command_line,
            ULONG process_id);

        /**
         * @brief Check if command disables recovery
         * @param command_line Command to check
         * @return true if disables recovery options
         */
        bool DisablesRecoveryOptions(const std::wstring& command_line) const;

        /**
         * @brief Check if command modifies safe boot
         * @param command_line Command to check
         * @return true if modifies safe boot
         */
        bool ModifiesSafeBoot(const std::wstring& command_line) const;

        /**
         * @brief Get recent boot config changes
         * @param max_count Maximum number to return
         * @return Vector of recent changes
         */
        std::vector<BootConfigChangeEvent> GetRecentChanges(size_t max_count = 10) const;

    private:
        // Boot configuration commands
        static const std::vector<std::wstring> BCDEDIT_COMMANDS;
        static const std::vector<std::wstring> RECOVERY_DISABLE_PARAMS;

        // Change history
        std::vector<BootConfigChangeEvent> change_history_;
        mutable std::mutex history_mutex_;
    };

    /**
     * @brief Process behavior analyzer
     * @details Analyzes process behavior for suspicious activity
     */
    class ProcessBehaviorAnalyzer {
    public:
        /**
         * @brief Process behavior flags
         */
        enum class BehaviorFlags : uint32_t {
            NONE = 0,
            DELETES_SHADOWS = 1 << 0,
            MODIFIES_REGISTRY = 1 << 1,
            CHANGES_BOOT_CONFIG = 1 << 2,
            DISABLES_SECURITY = 1 << 3,
            SPAWNS_CHILDREN = 1 << 4,
            NETWORK_ACTIVITY = 1 << 5,
            FILE_ENCRYPTION = 1 << 6,
            DROPS_RANSOM_NOTE = 1 << 7
        };

        /**
         * @brief Process risk profile
         */
        struct ProcessRiskProfile {
            ULONG process_id;
            std::wstring process_name;
            uint32_t behavior_flags;
            double risk_score;
            size_t suspicious_actions;
            std::chrono::steady_clock::time_point first_seen;
            std::chrono::steady_clock::time_point last_activity;
            std::vector<std::wstring> detected_behaviors;
        };

        /**
         * @brief Constructor
         */
        ProcessBehaviorAnalyzer();

        /**
         * @brief Destructor
         */
        ~ProcessBehaviorAnalyzer() = default;

        /**
         * @brief Update process behavior
         * @param process_id Process ID
         * @param behavior Behavior flag to add
         */
        void UpdateProcessBehavior(ULONG process_id, BehaviorFlags behavior);

        /**
         * @brief Get process risk profile
         * @param process_id Process ID
         * @return Risk profile if available
         */
        std::optional<ProcessRiskProfile> GetProcessRiskProfile(ULONG process_id) const;

        /**
         * @brief Calculate process risk score
         * @param process_id Process ID
         * @return Risk score (0-1)
         */
        double CalculateProcessRiskScore(ULONG process_id) const;

        /**
         * @brief Get high risk processes
         * @param min_score Minimum risk score
         * @return Vector of high risk process IDs
         */
        std::vector<ULONG> GetHighRiskProcesses(double min_score = 0.7) const;

    private:
        // Process profiles
        std::map<ULONG, ProcessRiskProfile> process_profiles_;
        mutable std::mutex profiles_mutex_;
    };

    /**
     * @brief Main system activity monitor
     * @details Coordinates all system monitoring components
     */
    class SystemActivityMonitor {
    public:
        /**
         * @brief Constructor
         */
        SystemActivityMonitor();

        /**
         * @brief Destructor
         */
        ~SystemActivityMonitor();

        /**
         * @brief Analyze command line execution
         * @param command_line Command being executed
         * @param process_name Process name
         * @param process_id Process ID
         * @param parent_pid Parent process ID
         * @return Command line analysis result
         */
        CommandLineAnalysis AnalyzeCommandLine(const std::wstring& command_line,
            const std::wstring& process_name,
            ULONG process_id,
            ULONG parent_pid);

        /**
         * @brief Analyze registry modification
         * @param key_path Registry key
         * @param value_name Value name
         * @param old_value Old value
         * @param new_value New value
         * @param process_id Process ID
         * @return Registry threat analysis
         */
        RegistryThreatAnalysis AnalyzeRegistryChange(const std::wstring& key_path,
            const std::wstring& value_name,
            const std::wstring& old_value,
            const std::wstring& new_value,
            ULONG process_id);

        /**
         * @brief Get process suspicion score
         * @param process_id Process ID
         * @return Suspicion score (0-1)
         */
        double GetProcessSuspicionScore(ULONG process_id) const;

        /**
         * @brief Get system activity summary
         * @param time_window Time window for summary
         * @return Activity summary
         */
        SystemActivitySummary GetActivitySummary(
            std::chrono::seconds time_window = std::chrono::seconds(3600)) const;

        /**
         * @brief Clear all monitoring data
         */
        void ClearAllData();

        /**
         * @brief Enable/disable specific monitoring
         * @param enable_shadow Enable shadow copy monitoring
         * @param enable_registry Enable registry monitoring
         * @param enable_boot Enable boot config monitoring
         */
        void ConfigureMonitoring(bool enable_shadow,
            bool enable_registry,
            bool enable_boot);

    private:
        // Monitoring components
        std::unique_ptr<ShadowCopyDeletionDetector> shadow_detector_;
        std::unique_ptr<RegistryModificationTracker> registry_tracker_;
        std::unique_ptr<BootConfigurationMonitor> boot_monitor_;
        std::unique_ptr<ProcessBehaviorAnalyzer> behavior_analyzer_;

        // Configuration
        bool monitor_shadow_copy_;
        bool monitor_registry_;
        bool monitor_boot_config_;

        // Statistics
        mutable std::atomic<size_t> total_commands_analyzed_;
        mutable std::atomic<size_t> suspicious_activities_detected_;
    };

} // namespace CryptoShield::Detection