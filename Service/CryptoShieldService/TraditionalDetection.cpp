#include "TraditionalDetection.h"
#include <iostream>
#include <algorithm>
#include <cmath>
#include <array>

// Static constants for detection
const std::vector<std::string> TraditionalDetectionEngine::SUSPICIOUS_EXTENSIONS = {
    ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".locky", ".cerber"
};

const std::vector<std::wstring> TraditionalDetectionEngine::SHADOW_COPY_COMMANDS = {
    L"vssadmin delete shadows",
    L"wmic shadowcopy delete",
    L"bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    L"bcdedit /set {default} recoveryenabled no"
};

TraditionalDetectionEngine::TraditionalDetectionEngine() 
    : entropy_threshold_(6.5), 
      mass_operation_threshold_(50), 
      time_window_(std::chrono::seconds(60)),
      is_active_(false) {
    
    std::wcout << L"[TraditionalDetection] Engine constructed\n";
}

TraditionalDetectionEngine::~TraditionalDetectionEngine() {
    Shutdown();
    std::wcout << L"[TraditionalDetection] Engine destroyed\n";
}

bool TraditionalDetectionEngine::Initialize() {
    std::wcout << L"[TraditionalDetection] Initializing engine...\n";
    
    // Initialize detection parameters
    last_cleanup_ = std::chrono::steady_clock::now();
    recent_operations_.clear();
    recent_operations_.reserve(1000); // Pre-allocate for performance
    
    is_active_ = true;
    std::wcout << L"[TraditionalDetection] Engine initialized successfully\n";
    return true;
}

void TraditionalDetectionEngine::Shutdown() {
    if (is_active_) {
        std::wcout << L"[TraditionalDetection] Shutting down engine...\n";
        is_active_ = false;
        recent_operations_.clear();
        std::wcout << L"[TraditionalDetection] Engine shutdown complete\n";
    }
}

bool TraditionalDetectionEngine::IsActive() const {
    return is_active_;
}

double TraditionalDetectionEngine::CalculateEntropy(const std::vector<uint8_t>& data) {
    return CalculateShannonEntropy(data);
}

double TraditionalDetectionEngine::CalculateShannonEntropy(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return 0.0;
    }
    
    // Count byte frequencies
    std::array<size_t, 256> frequency = {};
    for (uint8_t byte : data) {
        frequency[byte]++;
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    double data_size = static_cast<double>(data.size());
    
    for (size_t freq : frequency) {
        if (freq > 0) {
            double probability = static_cast<double>(freq) / data_size;
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

bool TraditionalDetectionEngine::IsHighEntropy(double entropy, const std::string& file_extension) {
    // Adjust threshold based on file type
    double adjusted_threshold = entropy_threshold_;
    
    // Some file types naturally have high entropy
    if (file_extension == ".zip" || file_extension == ".rar" || 
        file_extension == ".7z" || file_extension == ".gz") {
        adjusted_threshold = 7.8; // Higher threshold for compressed files
    }
    
    return entropy > adjusted_threshold;
}

bool TraditionalDetectionEngine::DetectMassFileModification(const std::vector<FileOperation>& operations) {
    if (operations.size() < mass_operation_threshold_) {
        return false;
    }
    
    // Check if operations occurred within time window
    auto now = std::chrono::steady_clock::now();
    size_t recent_count = 0;
    
    for (const auto& op : operations) {
        if (now - op.timestamp <= time_window_) {
            recent_count++;
        }
    }
    
    if (recent_count >= mass_operation_threshold_) {
        std::wcout << L"[TraditionalDetection] Mass file modification detected: " 
                  << recent_count << L" operations in time window\n";
        return true;
    }
    
    return false;
}

bool TraditionalDetectionEngine::DetectShadowCopyDeletion(const std::wstring& command_line) {
    std::wstring lower_command = command_line;
    std::transform(lower_command.begin(), lower_command.end(), 
                  lower_command.begin(), ::towlower);
    
    for (const auto& suspicious_cmd : SHADOW_COPY_COMMANDS) {
        std::wstring lower_suspicious = suspicious_cmd;
        std::transform(lower_suspicious.begin(), lower_suspicious.end(), 
                      lower_suspicious.begin(), ::towlower);
        
        if (lower_command.find(lower_suspicious) != std::wstring::npos) {
            std::wcout << L"[TraditionalDetection] Shadow copy deletion detected: " 
                      << command_line << L"\n";
            return true;
        }
    }
    
    return false;
}

DetectionResult TraditionalDetectionEngine::AnalyzeFileOperation(const FileOperation& operation) {
    DetectionResult result;
    result.confidence_score = 0.0;
    result.threat_level = ThreatLevel::NONE;
    result.is_suspicious = false;
    result.source_process_id = operation.process_id;
    result.source_file_path = WStringToString(operation.file_path);
    result.timestamp = operation.timestamp;
    result.description = "Traditional file analysis";
    
    // TODO: Implement full analysis logic
    // For now, just basic placeholder
    
    return result;
}

DetectionResult TraditionalDetectionEngine::AnalyzeProcessOperation(const ProcessOperation& operation) {
    DetectionResult result;
    result.confidence_score = 0.0;
    result.threat_level = ThreatLevel::NONE;
    result.is_suspicious = false;
    result.source_process_id = operation.process_id;
    result.timestamp = operation.timestamp;
    result.description = "Traditional process analysis";
    
    // Check for shadow copy deletion
    if (DetectShadowCopyDeletion(operation.command_line)) {
        result.confidence_score = 0.8;
        result.threat_level = ThreatLevel::HIGH;
        result.is_suspicious = true;
        result.description = "Shadow copy deletion detected";
        result.detected_patterns.push_back("shadow_copy_deletion");
    }
    
    return result;
}

void TraditionalDetectionEngine::SetEntropyThreshold(double threshold) {
    entropy_threshold_ = threshold;
    std::wcout << L"[TraditionalDetection] Entropy threshold set to: " << threshold << L"\n";
}

void TraditionalDetectionEngine::SetMassOperationThreshold(size_t threshold) {
    mass_operation_threshold_ = threshold;
    std::wcout << L"[TraditionalDetection] Mass operation threshold set to: " << threshold << L"\n";
}

void TraditionalDetectionEngine::SetTimeWindow(std::chrono::seconds window) {
    time_window_ = window;
    std::wcout << L"[TraditionalDetection] Time window set to: " << window.count() << L" seconds\n";
}

void TraditionalDetectionEngine::CleanupOldOperations() {
    auto now = std::chrono::steady_clock::now();
    auto cutoff_time = now - time_window_;
    
    recent_operations_.erase(
        std::remove_if(recent_operations_.begin(), recent_operations_.end(),
            [cutoff_time](const FileOperation& op) {
                return op.timestamp < cutoff_time;
            }),
        recent_operations_.end());
    
    last_cleanup_ = now;
}

bool TraditionalDetectionEngine::IsSuspiciousFileExtension(const std::string& extension) {
    return std::find(SUSPICIOUS_EXTENSIONS.begin(), SUSPICIOUS_EXTENSIONS.end(), 
                    extension) != SUSPICIOUS_EXTENSIONS.end();
}

bool TraditionalDetectionEngine::IsSuspiciousCommandLine(const std::wstring& command_line) {
    return DetectShadowCopyDeletion(command_line);
}