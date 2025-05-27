#pragma once

#include <vector>
#include <string>
#include <map>
#include <chrono>
#include "../../Common/Shared.h"

/**
 * @class TraditionalDetectionEngine
 * @brief Traditional ransomware detection using entropy analysis and behavioral patterns
 * 
 * This engine implements proven techniques for ransomware detection:
 * - Shannon entropy analysis for encrypted file detection
 * - Mass file modification pattern detection  
 * - Shadow copy deletion detection
 * - Suspicious process behavior analysis
 */
class TraditionalDetectionEngine {
public:
    TraditionalDetectionEngine();
    ~TraditionalDetectionEngine();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsActive() const;
    
    // Core detection methods
    double CalculateEntropy(const std::vector<uint8_t>& data);
    bool IsHighEntropy(double entropy, const std::string& file_extension);
    bool DetectMassFileModification(const std::vector<FileOperation>& operations);
    bool DetectShadowCopyDeletion(const std::wstring& command_line);
    
    // Analysis functions
    DetectionResult AnalyzeFileOperation(const FileOperation& operation);
    DetectionResult AnalyzeProcessOperation(const ProcessOperation& operation);
    
    // Configuration
    void SetEntropyThreshold(double threshold);
    void SetMassOperationThreshold(size_t threshold);
    void SetTimeWindow(std::chrono::seconds window);

private:
    // Configuration parameters
    double entropy_threshold_;
    size_t mass_operation_threshold_;
    std::chrono::seconds time_window_;
    bool is_active_;
    
    // State tracking
    std::vector<FileOperation> recent_operations_;
    std::chrono::steady_clock::time_point last_cleanup_;
    
    // Detection helpers
    void CleanupOldOperations();
    bool IsSuspiciousFileExtension(const std::string& extension);
    bool IsSuspiciousCommandLine(const std::wstring& command_line);
    double CalculateShannonEntropy(const std::vector<uint8_t>& data);
    
    // Constants for detection
    static const std::vector<std::string> SUSPICIOUS_EXTENSIONS;
    static const std::vector<std::wstring> SHADOW_COPY_COMMANDS;
};