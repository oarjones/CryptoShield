/**
 * @file SystemActivityMonitor.cpp
 * @brief System activity monitoring implementation
 * @details Implements shadow copy, registry, and boot config monitoring
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */
#define NOMINMAX
#include "SystemActivityMonitor.h"
#include <iostream>
#include <algorithm>
#include <sstream>
#include <regex>
#include <psapi.h>

namespace CryptoShield::Detection {

    // Static member definitions for ShadowCopyDeletionDetector
    const std::vector<std::wstring> ShadowCopyDeletionDetector::SHADOW_DELETION_COMMANDS = {
        L"vssadmin.exe delete shadows",
        L"vssadmin delete shadows",
        L"wmic shadowcopy delete",
        L"wbadmin delete catalog",
        L"wbadmin delete backup",
        L"wbadmin delete systemstatebackup",
        L"bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        L"bcdedit /set {default} recoveryenabled no",
        L"wevtutil cl system",
        L"wevtutil cl security",
        L"wevtutil cl application"
    };

    const std::vector<std::wstring> ShadowCopyDeletionDetector::BOOT_CONFIG_COMMANDS = {
        L"bcdedit",
        L"bootcfg",
        L"bcdboot"
    };

    const std::vector<std::wstring> ShadowCopyDeletionDetector::RECOVERY_DISABLE_COMMANDS = {
        L"recoveryenabled no",
        L"bootstatuspolicy ignoreallfailures",
        L"no protectbootloader"
    };

    const std::vector<std::wstring> ShadowCopyDeletionDetector::LEGITIMATE_PROCESSES = {
        L"TrustedInstaller.exe",
        L"services.exe",
        L"svchost.exe",
        L"wuauclt.exe",
        L"MsMpEng.exe"  // Windows Defender
    };

    const std::vector<std::wstring> ShadowCopyDeletionDetector::BACKUP_SOFTWARE = {
        L"Acronis",
        L"Veeam",
        L"BackupExec",
        L"ShadowProtect",
        L"Macrium"
    };

    /**
     * @brief Constructor
     */
    ShadowCopyDeletionDetector::ShadowCopyDeletionDetector()
    {
        event_history_.reserve(1000);
    }

    /**
     * @brief Analyze command line for shadow deletion
     */
    ShadowDeletionEvent ShadowCopyDeletionDetector::AnalyzeCommandLine(
        const std::wstring& command_line,
        const std::wstring& process_name,
        ULONG process_id,
        ULONG parent_pid)
    {
        ShadowDeletionEvent event;
        event.command_line = command_line;
        event.process_name = process_name;
        event.process_id = process_id;
        event.parent_process_id = parent_pid;
        event.timestamp = std::chrono::steady_clock::now();

        // Convert to lowercase for comparison
        std::wstring lower_command = command_line;
        std::transform(lower_command.begin(), lower_command.end(), lower_command.begin(), ::towlower);

        // Check if legitimate process
        event.is_legitimate = IsLegitimateProcess(process_name, command_line);

        // Score the command
        event.suspicion_score = ScoreCommandSuspicion(lower_command);

        // Add process context score
        double context_score = ScoreProcessContext(process_name, parent_pid);
        event.suspicion_score = (event.suspicion_score + context_score) / 2.0;

        // Determine detection reason
        if (MatchesShadowDeletionPattern(lower_command)) {
            event.detection_reason = L"Shadow copy deletion attempt detected";
        }
        else if (MatchesRecoveryDisablePattern(lower_command)) {
            event.detection_reason = L"System recovery disable attempt detected";
        }
        else if (event.suspicion_score > 0.5) {
            event.detection_reason = L"Suspicious system command detected";
        }

        // Store event if suspicious
        if (event.suspicion_score > 0.3 && !event.is_legitimate) {
            std::lock_guard<std::mutex> lock(history_mutex_);
            event_history_.push_back(event);

            // Keep only recent history (last 1000 events)
            if (event_history_.size() > 1000) {
                event_history_.erase(event_history_.begin());
            }
        }

        return event;
    }

    /**
     * @brief Check if process is legitimate for shadow operations
     */
    bool ShadowCopyDeletionDetector::IsLegitimateProcess(
        const std::wstring& process_name,
        const std::wstring& command_line) const
    {
        // Check if it's a known legitimate process
        for (const auto& legit : LEGITIMATE_PROCESSES) {
            if (process_name.find(legit) != std::wstring::npos) {
                return true;
            }
        }

        // Check if it's backup software
        for (const auto& backup : BACKUP_SOFTWARE) {
            if (process_name.find(backup) != std::wstring::npos ||
                command_line.find(backup) != std::wstring::npos) {
                return true;
            }
        }

        // Check if running under system context with proper signature
        // This would require additional Windows API calls in production

        return false;
    }

    /**
     * @brief Get recent shadow deletion events
     */
    std::vector<ShadowDeletionEvent> ShadowCopyDeletionDetector::GetRecentEvents(
        std::chrono::seconds max_age) const
    {
        std::lock_guard<std::mutex> lock(history_mutex_);

        auto now = std::chrono::steady_clock::now();
        std::vector<ShadowDeletionEvent> recent;

        for (const auto& event : event_history_) {
            if (now - event.timestamp <= max_age) {
                recent.push_back(event);
            }
        }

        return recent;
    }

    /**
     * @brief Clear event history
     */
    void ShadowCopyDeletionDetector::ClearHistory()
    {
        std::lock_guard<std::mutex> lock(history_mutex_);
        event_history_.clear();
    }

    /**
     * @brief Score command suspicion level
     */
    double ShadowCopyDeletionDetector::ScoreCommandSuspicion(const std::wstring& command) const
    {
        double score = 0.0;

        // Check for shadow deletion commands
        for (const auto& pattern : SHADOW_DELETION_COMMANDS) {
            std::wstring lower_pattern = pattern;
            std::transform(lower_pattern.begin(), lower_pattern.end(),
                lower_pattern.begin(), ::towlower);

            if (command.find(lower_pattern) != std::wstring::npos) {
                score = std::max(score, 0.9);
                break;
            }
        }

        // Check for specific dangerous parameters
        if (command.find(L"/quiet") != std::wstring::npos ||
            command.find(L"/all") != std::wstring::npos ||
            command.find(L"-quiet") != std::wstring::npos ||
            command.find(L"-all") != std::wstring::npos) {
            score = std::min(score + 0.2, 1.0);
        }

        // Check for recovery disable patterns
        for (const auto& pattern : RECOVERY_DISABLE_COMMANDS) {
            std::wstring lower_pattern = pattern;
            std::transform(lower_pattern.begin(), lower_pattern.end(),
                lower_pattern.begin(), ::towlower);

            if (command.find(lower_pattern) != std::wstring::npos) {
                score = std::max(score, 0.8);
            }
        }

        return score;
    }

    /**
     * @brief Score process context
     */
    double ShadowCopyDeletionDetector::ScoreProcessContext(
        const std::wstring& process_name, ULONG parent_pid) const
    {
        double score = 0.0;

        // Unknown or suspicious process names
        if (process_name.empty() || process_name == L"Unknown") {
            score += 0.3;
        }

        // Check if spawned from suspicious parent
        // In production, would check actual parent process name
        if (parent_pid == 0 || parent_pid == 4) {
            // System process, less suspicious
            score -= 0.1;
        }

        // Check for temp directory execution
        if (process_name.find(L"\\Temp\\") != std::wstring::npos ||
            process_name.find(L"\\tmp\\") != std::wstring::npos) {
            score += 0.4;
        }

        // Check for suspicious naming patterns
        if (process_name.find(L".tmp") != std::wstring::npos ||
            process_name.find(L"~") != std::wstring::npos) {
            score += 0.2;
        }

        return std::max(0.0, std::min(score, 1.0));
    }

    /**
     * @brief Check for shadow deletion patterns
     */
    bool ShadowCopyDeletionDetector::MatchesShadowDeletionPattern(const std::wstring& command) const
    {
        // Common shadow deletion patterns
        return (command.find(L"vssadmin") != std::wstring::npos &&
            command.find(L"delete") != std::wstring::npos &&
            command.find(L"shadows") != std::wstring::npos) ||
            (command.find(L"wmic") != std::wstring::npos &&
                command.find(L"shadowcopy") != std::wstring::npos &&
                command.find(L"delete") != std::wstring::npos) ||
            (command.find(L"wbadmin") != std::wstring::npos &&
                command.find(L"delete") != std::wstring::npos);
    }

    /**
     * @brief Check for recovery disable patterns
     */
    bool ShadowCopyDeletionDetector::MatchesRecoveryDisablePattern(const std::wstring& command) const
    {
        return (command.find(L"bcdedit") != std::wstring::npos &&
            command.find(L"recoveryenabled") != std::wstring::npos &&
            command.find(L"no") != std::wstring::npos) ||
            (command.find(L"bcdedit") != std::wstring::npos &&
                command.find(L"bootstatuspolicy") != std::wstring::npos &&
                command.find(L"ignoreallfailures") != std::wstring::npos);
    }

    // Static member definitions for RegistryModificationTracker
    const std::vector<std::wstring> RegistryModificationTracker::CRITICAL_REGISTRY_KEYS = {
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Services",
        L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot"
    };

    const std::vector<std::wstring> RegistryModificationTracker::STARTUP_KEYS = {
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
    };

    const std::vector<std::wstring> RegistryModificationTracker::SECURITY_KEYS = {
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows Defender",
        L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"
    };

    const std::vector<std::wstring> RegistryModificationTracker::DEFENDER_KEYS = {
        L"DisableAntiSpyware",
        L"DisableAntiVirus",
        L"DisableRealtimeMonitoring",
        L"DisableBehaviorMonitoring",
        L"DisableOnAccessProtection",
        L"DisableScanOnRealtimeEnable"
    };

    /**
     * @brief Constructor
     */
    RegistryModificationTracker::RegistryModificationTracker()
    {
        modification_history_.reserve(5000);
    }

    /**
     * @brief Analyze registry modification
     */
    RegistryThreatAnalysis RegistryModificationTracker::AnalyzeRegistryChange(
        const std::wstring& key_path,
        const std::wstring& value_name,
        const std::wstring& old_value,
        const std::wstring& new_value,
        ULONG process_id)
    {
        RegistryThreatAnalysis analysis;

        // Create modification event
        RegistryModificationEvent event;
        event.key_path = key_path;
        event.value_name = value_name;
        event.old_value = old_value;
        event.new_value = new_value;
        event.process_id = process_id;
        event.timestamp = std::chrono::steady_clock::now();

        // Check key types
        event.is_critical_key = IsCriticalKey(key_path);
        event.is_startup_key = IsStartupModification(key_path);
        event.is_security_key = IsSecurityBypass(key_path, new_value);

        // Store event
        {
            std::lock_guard<std::mutex> lock(history_mutex_);
            size_t event_index = modification_history_.size();
            modification_history_.push_back(event);
            process_modifications_[process_id].push_back(event_index);
        }

        // Calculate risk score
        double risk_score = CalculateRiskScore(event);

        // Build analysis result
        analysis.is_suspicious = risk_score > 0.5;
        analysis.confidence_score = risk_score;
        analysis.affected_keys.push_back(key_path);

        // Determine threat type
        if (IsDisablingDefender(key_path, new_value)) {
            analysis.threat_type = L"Security software tampering";
            analysis.requires_immediate_action = true;
        }
        else if (event.is_startup_key && !old_value.empty()) {
            analysis.threat_type = L"Startup modification";
        }
        else if (MatchesRansomwarePattern(key_path, new_value)) {
            analysis.threat_type = L"Ransomware registry pattern";
            analysis.requires_immediate_action = true;
        }
        else if (event.is_security_key) {
            analysis.threat_type = L"Security policy modification";
        }
        else {
            analysis.threat_type = L"Registry modification";
        }

        // Build description
        std::wstringstream desc;
        desc << L"Modified " << key_path << L"\\" << value_name;
        if (!old_value.empty()) {
            desc << L" from '" << old_value << L"'";
        }
        desc << L" to '" << new_value << L"'";
        analysis.description = desc.str();

        return analysis;
    }

    /**
     * @brief Check if key is critical
     */
    bool RegistryModificationTracker::IsCriticalKey(const std::wstring& key_path) const
    {
        for (const auto& critical : CRITICAL_REGISTRY_KEYS) {
            if (key_path.find(critical) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Check if startup modification
     */
    bool RegistryModificationTracker::IsStartupModification(const std::wstring& key_path) const
    {
        for (const auto& startup : STARTUP_KEYS) {
            if (key_path.find(startup) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Check if security bypass attempt
     */
    bool RegistryModificationTracker::IsSecurityBypass(
        const std::wstring& key_path, const std::wstring& value) const
    {
        for (const auto& security : SECURITY_KEYS) {
            if (key_path.find(security) != std::wstring::npos) {
                // Check if disabling something
                if (value == L"0" || value == L"false" || value == L"disabled") {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @brief Get modification history for process
     */
    std::vector<RegistryModificationEvent> RegistryModificationTracker::GetProcessHistory(
        ULONG process_id) const
    {
        std::lock_guard<std::mutex> lock(history_mutex_);

        std::vector<RegistryModificationEvent> process_events;

        auto it = process_modifications_.find(process_id);
        if (it != process_modifications_.end()) {
            for (size_t index : it->second) {
                if (index < modification_history_.size()) {
                    process_events.push_back(modification_history_[index]);
                }
            }
        }

        return process_events;
    }

    /**
     * @brief Clear modification history
     */
    void RegistryModificationTracker::ClearHistory(std::chrono::seconds older_than)
    {
        std::lock_guard<std::mutex> lock(history_mutex_);

        auto now = std::chrono::steady_clock::now();

        // Remove old entries
        modification_history_.erase(
            std::remove_if(modification_history_.begin(), modification_history_.end(),
                [&](const RegistryModificationEvent& event) {
                    return now - event.timestamp > older_than;
                }),
            modification_history_.end()
        );

        // Rebuild process modifications map
        process_modifications_.clear();
        for (size_t i = 0; i < modification_history_.size(); ++i) {
            process_modifications_[modification_history_[i].process_id].push_back(i);
        }
    }

    /**
     * @brief Calculate modification risk score
     */
    double RegistryModificationTracker::CalculateRiskScore(
        const RegistryModificationEvent& event) const
    {
        double score = 0.0;

        // Critical key modification
        if (event.is_critical_key) {
            score += 0.4;
        }

        // Startup modification
        if (event.is_startup_key) {
            score += 0.3;
        }

        // Security bypass
        if (event.is_security_key) {
            score += 0.5;
        }

        // Check for defender disabling
        if (IsDisablingDefender(event.key_path, event.new_value)) {
            score = 1.0;  // Maximum risk
        }

        // Check for ransomware patterns
        if (MatchesRansomwarePattern(event.key_path, event.new_value)) {
            score = std::max(score, 0.9);
        }

        return std::min(score, 1.0);
    }

    /**
     * @brief Check for ransomware-like registry patterns
     */
    bool RegistryModificationTracker::MatchesRansomwarePattern(
        const std::wstring& key_path, const std::wstring& value) const
    {
        // Check for wallpaper changes
        if (key_path.find(L"Control Panel\\Desktop") != std::wstring::npos &&
            value.find(L"Wallpaper") != std::wstring::npos) {
            return true;
        }

        // Check for file association hijacking
        if (key_path.find(L"\\shell\\open\\command") != std::wstring::npos) {
            return true;
        }

        // Check for shadow copy service disabling
        if (key_path.find(L"VSS") != std::wstring::npos &&
            value == L"4") {  // Disabled state
            return true;
        }

        return false;
    }

    /**
     * @brief Check if disabling Windows Defender
     */
    bool RegistryModificationTracker::IsDisablingDefender(
        const std::wstring& key_path, const std::wstring& value) const
    {
        if (key_path.find(L"Windows Defender") == std::wstring::npos &&
            key_path.find(L"WinDefend") == std::wstring::npos) {
            return false;
        }

        for (const auto& defender_value : DEFENDER_KEYS) {
            if (key_path.find(defender_value) != std::wstring::npos &&
                (value == L"1" || value == L"true")) {
                return true;
            }
        }

        return false;
    }

    /**
     * @brief Constructor
     */
    SystemActivityMonitor::SystemActivityMonitor()
        : monitor_shadow_copy_(true)
        , monitor_registry_(true)
        , monitor_boot_config_(true)
        , total_commands_analyzed_(0)
        , suspicious_activities_detected_(0)
    {
        // Initialize monitoring components
        shadow_detector_ = std::make_unique<ShadowCopyDeletionDetector>();
        registry_tracker_ = std::make_unique<RegistryModificationTracker>();
        boot_monitor_ = std::make_unique<BootConfigurationMonitor>();
        behavior_analyzer_ = std::make_unique<ProcessBehaviorAnalyzer>();
    }

    /**
     * @brief Destructor
     */
    SystemActivityMonitor::~SystemActivityMonitor() = default;

    /**
     * @brief Analyze command line execution
     */
    CommandLineAnalysis SystemActivityMonitor::AnalyzeCommandLine(
        const std::wstring& command_line,
        const std::wstring& process_name,
        ULONG process_id,
        ULONG parent_pid)
    {
        total_commands_analyzed_++;

        CommandLineAnalysis analysis;
        analysis.is_suspicious = false;
        analysis.suspicion_score = 0.0;

        if (monitor_shadow_copy_) {
            // Check for shadow copy operations
            auto shadow_event = shadow_detector_->AnalyzeCommandLine(
                command_line, process_name, process_id, parent_pid
            );

            if (shadow_event.suspicion_score > 0.5) {
                analysis.is_suspicious = true;
                analysis.suspicion_score = std::max(analysis.suspicion_score,
                    shadow_event.suspicion_score);
                analysis.matched_patterns.push_back(L"Shadow copy deletion");
                analysis.primary_threat_type = L"System recovery tampering";

                // Update process behavior
                behavior_analyzer_->UpdateProcessBehavior(
                    process_id,
                    ProcessBehaviorAnalyzer::BehaviorFlags::DELETES_SHADOWS
                );
            }
        }

        if (monitor_boot_config_) {
            // Check for boot configuration changes
            auto boot_event = boot_monitor_->AnalyzeBootCommand(command_line, process_id);

            if (boot_event.disables_recovery || boot_event.modifies_safeboot) {
                analysis.is_suspicious = true;
                analysis.suspicion_score = std::max(analysis.suspicion_score, 0.8);
                analysis.matched_patterns.push_back(L"Boot configuration change");

                if (analysis.primary_threat_type.empty()) {
                    analysis.primary_threat_type = L"Boot security tampering";
                }

                // Update process behavior
                behavior_analyzer_->UpdateProcessBehavior(
                    process_id,
                    ProcessBehaviorAnalyzer::BehaviorFlags::CHANGES_BOOT_CONFIG
                );
            }
        }

        // Set recommended action based on suspicion level
        if (analysis.suspicion_score >= 0.9) {
            analysis.recommended_action = L"Block and terminate process immediately";
            suspicious_activities_detected_++;
        }
        else if (analysis.suspicion_score >= 0.7) {
            analysis.recommended_action = L"Monitor closely and prepare remediation";
        }
        else if (analysis.suspicion_score >= 0.5) {
            analysis.recommended_action = L"Log and continue monitoring";
        }

        return analysis;
    }

    /**
     * @brief Analyze registry modification
     */
    RegistryThreatAnalysis SystemActivityMonitor::AnalyzeRegistryChange(
        const std::wstring& key_path,
        const std::wstring& value_name,
        const std::wstring& old_value,
        const std::wstring& new_value,
        ULONG process_id)
    {
        if (!monitor_registry_) {
            RegistryThreatAnalysis empty;
            empty.is_suspicious = false;
            empty.confidence_score = 0.0;
            return empty;
        }

        auto analysis = registry_tracker_->AnalyzeRegistryChange(
            key_path, value_name, old_value, new_value, process_id
        );

        if (analysis.is_suspicious) {
            suspicious_activities_detected_++;

            // Update process behavior
            behavior_analyzer_->UpdateProcessBehavior(
                process_id,
                ProcessBehaviorAnalyzer::BehaviorFlags::MODIFIES_REGISTRY
            );

            if (analysis.threat_type == L"Security software tampering") {
                behavior_analyzer_->UpdateProcessBehavior(
                    process_id,
                    ProcessBehaviorAnalyzer::BehaviorFlags::DISABLES_SECURITY
                );
            }
        }

        return analysis;
    }

    /**
     * @brief Get process suspicion score
     */
    double SystemActivityMonitor::GetProcessSuspicionScore(ULONG process_id) const
    {
        return behavior_analyzer_->CalculateProcessRiskScore(process_id);
    }

    /**
     * @brief Get system activity summary
     */
    SystemActivitySummary SystemActivityMonitor::GetActivitySummary(
        std::chrono::seconds time_window) const
    {
        SystemActivitySummary summary;
        summary.analysis_timestamp = std::chrono::steady_clock::now();

        // Get shadow deletion events
        if (shadow_detector_) {
            auto shadow_events = shadow_detector_->GetRecentEvents(time_window);
            summary.shadow_deletion_attempts = shadow_events.size();
        }

        // Get registry modifications
        // Note: Would need to implement time-based filtering in registry tracker
        summary.registry_modifications = 0;  // Placeholder

        // Get boot config changes
        if (boot_monitor_) {
            auto boot_changes = boot_monitor_->GetRecentChanges(100);
            summary.boot_config_changes = boot_changes.size();
        }

        // Get high risk processes
        summary.high_risk_processes.clear();
        auto high_risk = behavior_analyzer_->GetHighRiskProcesses(0.7);
        for (ULONG pid : high_risk) {
            summary.high_risk_processes.push_back(
                L"Process " + std::to_wstring(pid)
            );
        }

        // Calculate overall threat score
        double threat_factors = 0.0;
        if (summary.shadow_deletion_attempts > 0) threat_factors += 0.3;
        if (summary.registry_modifications > 10) threat_factors += 0.2;
        if (summary.boot_config_changes > 0) threat_factors += 0.3;
        if (!summary.high_risk_processes.empty()) threat_factors += 0.2;

        summary.overall_system_threat_score = std::min(threat_factors, 1.0);

        return summary;
    }

    /**
     * @brief Clear all monitoring data
     */
    void SystemActivityMonitor::ClearAllData()
    {
        if (shadow_detector_) {
            shadow_detector_->ClearHistory();
        }
        if (registry_tracker_) {
            registry_tracker_->ClearHistory();
        }
        // Reset statistics
        total_commands_analyzed_ = 0;
        suspicious_activities_detected_ = 0;
    }

    /**
     * @brief Configure monitoring settings
     */
    void SystemActivityMonitor::ConfigureMonitoring(bool enable_shadow,
        bool enable_registry,
        bool enable_boot)
    {
        monitor_shadow_copy_ = enable_shadow;
        monitor_registry_ = enable_registry;
        monitor_boot_config_ = enable_boot;
    }

    // BootConfigurationMonitor implementation (simplified)
    const std::vector<std::wstring> BootConfigurationMonitor::BCDEDIT_COMMANDS = {
        L"bcdedit.exe",
        L"bcdedit"
    };

    const std::vector<std::wstring> BootConfigurationMonitor::RECOVERY_DISABLE_PARAMS = {
        L"recoveryenabled no",
        L"bootstatuspolicy ignoreallfailures"
    };

    BootConfigurationMonitor::BootConfigurationMonitor()
    {
        change_history_.reserve(100);
    }

    BootConfigChangeEvent BootConfigurationMonitor::AnalyzeBootCommand(
        const std::wstring& command_line, ULONG process_id)
    {
        BootConfigChangeEvent event;
        event.command_line = command_line;
        event.process_id = process_id;
        event.timestamp = std::chrono::steady_clock::now();

        // Convert to lowercase
        std::wstring lower_command = command_line;
        std::transform(lower_command.begin(), lower_command.end(),
            lower_command.begin(), ::towlower);

        // Check if it's a bcdedit command
        bool is_bcdedit = false;
        for (const auto& cmd : BCDEDIT_COMMANDS) {
            if (lower_command.find(cmd) != std::wstring::npos) {
                is_bcdedit = true;
                break;
            }
        }

        if (is_bcdedit) {
            event.disables_recovery = DisablesRecoveryOptions(lower_command);
            event.modifies_safeboot = ModifiesSafeBoot(lower_command);

            // Store if significant
            if (event.disables_recovery || event.modifies_safeboot) {
                std::lock_guard<std::mutex> lock(history_mutex_);
                change_history_.push_back(event);
            }
        }

        return event;
    }

    bool BootConfigurationMonitor::DisablesRecoveryOptions(const std::wstring& command_line) const
    {
        for (const auto& param : RECOVERY_DISABLE_PARAMS) {
            if (command_line.find(param) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

    bool BootConfigurationMonitor::ModifiesSafeBoot(const std::wstring& command_line) const
    {
        return command_line.find(L"safeboot") != std::wstring::npos ||
            command_line.find(L"safebootalternateshell") != std::wstring::npos;
    }

    std::vector<BootConfigChangeEvent> BootConfigurationMonitor::GetRecentChanges(
        size_t max_count) const
    {
        std::lock_guard<std::mutex> lock(history_mutex_);

        std::vector<BootConfigChangeEvent> recent;
        size_t start = change_history_.size() > max_count ?
            change_history_.size() - max_count : 0;

        for (size_t i = start; i < change_history_.size(); ++i) {
            recent.push_back(change_history_[i]);
        }

        return recent;
    }

    // ProcessBehaviorAnalyzer implementation
    ProcessBehaviorAnalyzer::ProcessBehaviorAnalyzer()
    {
    }

    void ProcessBehaviorAnalyzer::UpdateProcessBehavior(ULONG process_id, BehaviorFlags behavior)
    {
        std::lock_guard<std::mutex> lock(profiles_mutex_);

        auto& profile = process_profiles_[process_id];
        if (profile.process_id == 0) {
            profile.process_id = process_id;
            profile.first_seen = std::chrono::steady_clock::now();
            profile.risk_score = 0.0;
        }

        profile.behavior_flags |= static_cast<uint32_t>(behavior);
        profile.last_activity = std::chrono::steady_clock::now();
        profile.suspicious_actions++;

        // Update detected behaviors
        switch (behavior) {
        case BehaviorFlags::DELETES_SHADOWS:
            profile.detected_behaviors.push_back(L"Shadow copy deletion");
            break;
        case BehaviorFlags::MODIFIES_REGISTRY:
            profile.detected_behaviors.push_back(L"Registry modification");
            break;
        case BehaviorFlags::CHANGES_BOOT_CONFIG:
            profile.detected_behaviors.push_back(L"Boot configuration change");
            break;
        case BehaviorFlags::DISABLES_SECURITY:
            profile.detected_behaviors.push_back(L"Security software tampering");
            break;
        }

        // Recalculate risk score
        profile.risk_score = CalculateProcessRiskScore(process_id);
    }

    std::optional<ProcessBehaviorAnalyzer::ProcessRiskProfile>
        ProcessBehaviorAnalyzer::GetProcessRiskProfile(ULONG process_id) const
    {
        std::lock_guard<std::mutex> lock(profiles_mutex_);

        auto it = process_profiles_.find(process_id);
        if (it != process_profiles_.end()) {
            return it->second;
        }

        return std::nullopt;
    }

    double ProcessBehaviorAnalyzer::CalculateProcessRiskScore(ULONG process_id) const
    {
        auto it = process_profiles_.find(process_id);
        if (it == process_profiles_.end()) {
            return 0.0;
        }

        const auto& profile = it->second;
        double score = 0.0;

        // Each behavior flag adds to risk
        uint32_t flags = profile.behavior_flags;

        if (flags & static_cast<uint32_t>(BehaviorFlags::DELETES_SHADOWS))
            score += 0.3;
        if (flags & static_cast<uint32_t>(BehaviorFlags::MODIFIES_REGISTRY))
            score += 0.2;
        if (flags & static_cast<uint32_t>(BehaviorFlags::CHANGES_BOOT_CONFIG))
            score += 0.3;
        if (flags & static_cast<uint32_t>(BehaviorFlags::DISABLES_SECURITY))
            score += 0.4;
        if (flags & static_cast<uint32_t>(BehaviorFlags::FILE_ENCRYPTION))
            score += 0.5;

        // Multiple suspicious actions increase risk
        if (profile.suspicious_actions > 5) {
            score = std::min(score + 0.2, 1.0);
        }

        return std::min(score, 1.0);
    }

    std::vector<ULONG> ProcessBehaviorAnalyzer::GetHighRiskProcesses(double min_score) const
    {
        std::lock_guard<std::mutex> lock(profiles_mutex_);

        std::vector<ULONG> high_risk;
        for (const auto& [pid, profile] : process_profiles_) {
            if (profile.risk_score >= min_score) {
                high_risk.push_back(pid);
            }
        }

        return high_risk;
    }

} // namespace CryptoShield::Detection