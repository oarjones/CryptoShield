/**
 * @file EntropyAnalyzer.cpp
 * @brief Entropy analysis implementation for ransomware detection
 * @details Optimized Shannon entropy, Chi-square, and Hamming distance calculations
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */
#define NOMINMAX
#include "EntropyAnalyzer.h"
#include <algorithm>
#include <numeric>
#include <cstring>
#include <filesystem>
#include <unordered_map>
#include <sstream>

namespace CryptoShield::Detection {

    // Static member definitions
    const std::vector<std::pair<std::vector<uint8_t>, FileType>> FileTypeDetector::MAGIC_NUMBERS = {
        {{0x89, 0x50, 0x4E, 0x47}, FileType::IMAGE},           // PNG
        {{0xFF, 0xD8, 0xFF}, FileType::IMAGE},                 // JPEG
        {{0x47, 0x49, 0x46, 0x38}, FileType::IMAGE},          // GIF
        {{0x4D, 0x5A}, FileType::EXECUTABLE},                   // EXE/DLL
        {{0x50, 0x4B, 0x03, 0x04}, FileType::COMPRESSED},      // ZIP
        {{0x52, 0x61, 0x72, 0x21}, FileType::COMPRESSED},      // RAR
        {{0x25, 0x50, 0x44, 0x46}, FileType::TEXT_DOCUMENT},   // PDF
        {{0x49, 0x44, 0x33}, FileType::MEDIA},                 // MP3
        {{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, FileType::MEDIA}, // MP4
    };

    const std::unordered_map<std::wstring, FileType> FileTypeDetector::EXTENSION_MAP = {
        {L".txt", FileType::TEXT_DOCUMENT},
        {L".doc", FileType::TEXT_DOCUMENT},
        {L".docx", FileType::TEXT_DOCUMENT},
        {L".pdf", FileType::TEXT_DOCUMENT},
        {L".jpg", FileType::IMAGE},
        {L".jpeg", FileType::IMAGE},
        {L".png", FileType::IMAGE},
        {L".gif", FileType::IMAGE},
        {L".bmp", FileType::IMAGE},
        {L".exe", FileType::EXECUTABLE},
        {L".dll", FileType::EXECUTABLE},
        {L".sys", FileType::EXECUTABLE},
        {L".zip", FileType::COMPRESSED},
        {L".rar", FileType::COMPRESSED},
        {L".7z", FileType::COMPRESSED},
        {L".tar", FileType::COMPRESSED},
        {L".gz", FileType::COMPRESSED},
        {L".db", FileType::DATABASE},
        {L".mdb", FileType::DATABASE},
        {L".sqlite", FileType::DATABASE},
        {L".mp3", FileType::MEDIA},
        {L".mp4", FileType::MEDIA},
        {L".avi", FileType::MEDIA},
        {L".mkv", FileType::MEDIA},
        {L".wav", FileType::MEDIA},
    };

    /**
     * @brief Constructor
     */
    ShannonEntropyAnalyzer::ShannonEntropyAnalyzer()
        : lookup_table_initialized_(false)
    {
        InitializeLookupTable();
    }

    /**
     * @brief Initialize lookup table for log2 calculations
     */
    void ShannonEntropyAnalyzer::InitializeLookupTable()
    {
        std::lock_guard<std::mutex> lock(lookup_mutex_);

        if (lookup_table_initialized_) {
            return;
        }

        // Pre-calculate log2 values for common probabilities
        for (size_t i = 0; i < LOOKUP_TABLE_SIZE; ++i) {
            double value = static_cast<double>(i) / LOOKUP_TABLE_SIZE;
            if (value > 0) {
                log2_lookup_table_[i] = -value * std::log2(value);
            }
            else {
                log2_lookup_table_[i] = 0.0;
            }
        }

        lookup_table_initialized_ = true;
    }

    /**
     * @brief Fast log2 calculation using lookup table
     */
    inline double ShannonEntropyAnalyzer::FastLog2(double value) const
    {
        if (value <= 0 || value >= 1.0) {
            return 0.0;
        }

        size_t index = static_cast<size_t>(value * LOOKUP_TABLE_SIZE);
        if (index >= LOOKUP_TABLE_SIZE) {
            index = LOOKUP_TABLE_SIZE - 1;
        }

        return log2_lookup_table_[index];
    }

    /**
     * @brief Calculate Shannon entropy
     */
    double ShannonEntropyAnalyzer::CalculateEntropy(const uint8_t* data, size_t length)
    {
        if (!data || length == 0) {
            return 0.0;
        }

        // Count byte frequencies
        std::array<size_t, 256> frequencies = { 0 };
        for (size_t i = 0; i < length; ++i) {
            frequencies[data[i]]++;
        }

        // Calculate entropy using lookup table
        double entropy = 0.0;
        double length_double = static_cast<double>(length);

        for (size_t freq : frequencies) {
            if (freq > 0) {
                double probability = freq / length_double;
                entropy += FastLog2(probability);
            }
        }

        return entropy;
    }

    /**
     * @brief Calculate Shannon entropy (vector version)
     */
    double ShannonEntropyAnalyzer::CalculateEntropy(const std::vector<uint8_t>& data)
    {
        return CalculateEntropy(data.data(), data.size());
    }

    /**
     * @brief Check if entropy indicates encryption
     */
    bool ShannonEntropyAnalyzer::IsHighEntropy(double entropy, FileType file_type) const
    {
        double threshold = GetAdaptiveThreshold(file_type);
        return entropy > threshold;
    }

    /**
     * @brief Get adaptive threshold for file type
     */
    double ShannonEntropyAnalyzer::GetAdaptiveThreshold(FileType file_type) const
    {
        switch (file_type) {
        case FileType::TEXT_DOCUMENT:
            return THRESHOLD_TEXT;
        case FileType::IMAGE:
            return THRESHOLD_IMAGE;
        case FileType::EXECUTABLE:
            return THRESHOLD_EXECUTABLE;
        case FileType::COMPRESSED:
            return THRESHOLD_COMPRESSED;
        case FileType::DATABASE:
            return THRESHOLD_DATABASE;
        case FileType::MEDIA:
            return THRESHOLD_MEDIA;
        case FileType::UNKNOWN:
        default:
            return THRESHOLD_UNKNOWN;
        }
    }

    /**
     * @brief Perform Chi-square test for randomness
     */
    double ShannonEntropyAnalyzer::PerformChiSquareTest(const std::vector<uint8_t>& data)
    {
        if (data.empty()) {
            return 0.0;
        }

        // Count byte frequencies
        std::array<size_t, 256> observed = { 0 };
        for (uint8_t byte : data) {
            observed[byte]++;
        }

        // Expected frequency for uniform distribution
        double expected = static_cast<double>(data.size()) / 256.0;

        // Calculate chi-square statistic
        double chi_square = 0.0;
        for (size_t freq : observed) {
            double diff = freq - expected;
            chi_square += (diff * diff) / expected;
        }

        return chi_square;
    }

    /**
     * @brief Check if distribution is random
     */
    bool ShannonEntropyAnalyzer::IsRandomDistribution(double chi_square_value) const
    {
        // Using chi-square critical value for 255 degrees of freedom at 95% confidence
        return chi_square_value < CHI_SQUARE_THRESHOLD;
    }

    /**
     * @brief Calculate Hamming distance between two buffers
     */
    double ShannonEntropyAnalyzer::CalculateHammingDistance(const std::vector<uint8_t>& before,
        const std::vector<uint8_t>& after)
    {
        if (before.empty() || after.empty()) {
            return 0.0;
        }

        size_t min_size = std::min(before.size(), after.size());
        size_t different_bits = 0;

        // Count different bits
        for (size_t i = 0; i < min_size; ++i) {
            uint8_t xor_result = before[i] ^ after[i];
            // Count set bits using Brian Kernighan's algorithm
            while (xor_result) {
                different_bits++;
                xor_result &= xor_result - 1;
            }
        }

        // Add difference for size mismatch
        size_t size_diff = std::abs(static_cast<long>(before.size() - after.size()));
        different_bits += size_diff * 8;

        // Normalize to 0-1 range
        size_t total_bits = std::max(before.size(), after.size()) * 8;
        return static_cast<double>(different_bits) / total_bits;
    }

    /**
     * @brief Constructor
     */
    AdvancedEntropyAnalysis::AdvancedEntropyAnalysis()
        : shannon_analyzer_(std::make_unique<ShannonEntropyAnalyzer>())
    {
        // Initialize reference distributions
        // Text files typically have lower entropy
        std::fill(text_distribution_.begin(), text_distribution_.end(), 1.0 / 256.0);
        // Common ASCII characters have higher probability
        for (int i = 32; i < 127; ++i) {
            text_distribution_[i] = 5.0 / 256.0;
        }

        // Normalize
        double sum = std::accumulate(text_distribution_.begin(), text_distribution_.end(), 0.0);
        for (auto& val : text_distribution_) {
            val /= sum;
        }

        // Executable and image distributions can be initialized similarly
        std::fill(executable_distribution_.begin(), executable_distribution_.end(), 1.0 / 256.0);
        std::fill(image_distribution_.begin(), image_distribution_.end(), 1.0 / 256.0);
    }

    /**
     * @brief Calculate block-based entropy
     */
    std::vector<double> AdvancedEntropyAnalysis::CalculateBlockEntropy(
        const std::vector<uint8_t>& data, size_t block_size)
    {
        std::vector<double> block_entropies;

        if (data.empty() || block_size < MIN_BLOCK_SIZE) {
            return block_entropies;
        }

        size_t num_blocks = (data.size() + block_size - 1) / block_size;
        block_entropies.reserve(num_blocks);

        for (size_t i = 0; i < data.size(); i += block_size) {
            size_t current_block_size = std::min(block_size, data.size() - i);
            double entropy = shannon_analyzer_->CalculateEntropy(
                data.data() + i, current_block_size
            );
            block_entropies.push_back(entropy);
        }

        return block_entropies;
    }

    /**
     * @brief Analyze entropy trend over time
     */
    EntropyTrend AdvancedEntropyAnalysis::AnalyzeEntropyTrend(
        const std::vector<double>& entropy_history)
    {
        EntropyTrend trend;

        if (entropy_history.empty()) {
            return trend;
        }

        trend.entropy_history = entropy_history;
        trend.initial_entropy = entropy_history.front();
        trend.final_entropy = entropy_history.back();
        trend.delta = trend.final_entropy - trend.initial_entropy;

        // Calculate trend slope
        trend.trend_coefficient = CalculateTrendSlope(entropy_history);

        // Significant change if delta > 2.0 or trend is steep
        trend.significant_change = (std::abs(trend.delta) > 2.0) ||
            (std::abs(trend.trend_coefficient) > 0.5);

        return trend;
    }

    /**
     * @brief Analyze frequency distribution
     */
    FrequencyProfile AdvancedEntropyAnalysis::AnalyzeFrequencyDistribution(
        const std::vector<uint8_t>& data)
    {
        FrequencyProfile profile = {};

        if (data.empty()) {
            return profile;
        }

        // Count frequencies
        std::array<size_t, 256> counts = { 0 };
        for (uint8_t byte : data) {
            counts[byte]++;
        }

        // Convert to probabilities
        double data_size = static_cast<double>(data.size());
        for (size_t i = 0; i < 256; ++i) {
            profile.byte_frequencies[i] = counts[i] / data_size;
        }

        // Calculate uniformity score (0 = perfectly uniform, 1 = highly skewed)
        double expected = 1.0 / 256.0;
        double variance_sum = 0.0;

        for (double freq : profile.byte_frequencies) {
            double diff = freq - expected;
            variance_sum += diff * diff;
        }

        profile.uniformity_score = std::sqrt(variance_sum / 256.0) * 256.0;

        // Find most and least common bytes
        auto [min_it, max_it] = std::minmax_element(
            profile.byte_frequencies.begin(),
            profile.byte_frequencies.end()
        );

        profile.least_common_byte = *min_it;
        profile.most_common_byte = *max_it;

        // Calculate deviation from natural language distribution
        //auto& text_dist = GetReferenceDistribution(FileType::TEXT_DOCUMENT);
        const auto& text_dist = GetReferenceDistribution(FileType::TEXT_DOCUMENT);
        profile.deviation_from_natural = CalculateKLDivergence(data, text_dist);

        return profile;
    }

    /**
     * @brief Detect partial encryption
     */
    double AdvancedEntropyAnalysis::DetectPartialEncryption(
        const std::vector<double>& block_entropies)
    {
        if (block_entropies.empty()) {
            return 0.0;
        }

        size_t encrypted_blocks = 0;
        for (double entropy : block_entropies) {
            if (entropy > ENCRYPTED_BLOCK_THRESHOLD) {
                encrypted_blocks++;
            }
        }

        return static_cast<double>(encrypted_blocks) / block_entropies.size();
    }

    /**
     * @brief Calculate Kullback-Leibler divergence
     */
    double AdvancedEntropyAnalysis::CalculateKLDivergence(
        const std::vector<uint8_t>& data,
        const std::array<double, 256>& reference_distribution)
    {
        if (data.empty()) {
            return 0.0;
        }

        // Calculate observed distribution
        std::array<double, 256> observed = { 0 };
        for (uint8_t byte : data) {
            observed[byte] += 1.0;
        }

        // Normalize
        double sum = static_cast<double>(data.size());
        for (auto& val : observed) {
            val /= sum;
        }

        // Calculate KL divergence
        double kl_divergence = 0.0;
        for (size_t i = 0; i < 256; ++i) {
            if (observed[i] > 0 && reference_distribution[i] > 0) {
                kl_divergence += observed[i] * std::log(observed[i] / reference_distribution[i]);
            }
        }

        return kl_divergence;
    }

    /**
     * @brief Perform comprehensive entropy analysis
     */
    EntropyAnalysisResult AdvancedEntropyAnalysis::PerformComprehensiveAnalysis(
        const std::vector<uint8_t>& data, FileType file_type)
    {
        EntropyAnalysisResult result = {};

        if (data.empty()) {
            result.analysis_notes = "Empty data provided";
            return result;
        }

        // Calculate Shannon entropy
        result.shannon_entropy = shannon_analyzer_->CalculateEntropy(data);

        // Check if high entropy
        result.is_high_entropy = shannon_analyzer_->IsHighEntropy(
            result.shannon_entropy, file_type
        );

        // Perform Chi-square test
        result.chi_square_value = shannon_analyzer_->PerformChiSquareTest(data);
        result.is_random_distribution = shannon_analyzer_->IsRandomDistribution(
            result.chi_square_value
        );

        // Calculate confidence score
        double threshold = shannon_analyzer_->GetAdaptiveThreshold(file_type);
        if (result.shannon_entropy > threshold) {
            result.confidence_score = std::min(
                (result.shannon_entropy - threshold) / (8.0 - threshold),
                1.0
            );
        }

        // Adjust confidence based on chi-square test
        if (result.is_random_distribution) {
            result.confidence_score = std::min(result.confidence_score + 0.2, 1.0);
        }

        // Build analysis notes
        std::stringstream notes;
        notes << "File type: " << static_cast<int>(file_type)
            << ", Entropy: " << result.shannon_entropy
            << ", Threshold: " << threshold;

        if (result.is_high_entropy) {
            notes << " [HIGH ENTROPY DETECTED]";
        }
        if (result.is_random_distribution) {
            notes << " [RANDOM DISTRIBUTION]";
        }

        result.analysis_notes = notes.str();

        return result;
    }

    /**
     * @brief Calculate linear regression for trend
     */
    double AdvancedEntropyAnalysis::CalculateTrendSlope(const std::vector<double>& values)
    {
        if (values.size() < 2) {
            return 0.0;
        }

        size_t n = values.size();
        double sum_x = 0.0, sum_y = 0.0, sum_xy = 0.0, sum_x2 = 0.0;

        for (size_t i = 0; i < n; ++i) {
            double x = static_cast<double>(i);
            double y = values[i];
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
        }

        double denominator = n * sum_x2 - sum_x * sum_x;
        if (std::abs(denominator) < 1e-10) {
            return 0.0;
        }

        return (n * sum_xy - sum_x * sum_y) / denominator;
    }

    /**
     * @brief Get reference distribution for file type
     */
    std::array<double, 256> AdvancedEntropyAnalysis::GetReferenceDistribution(FileType file_type)
    {
        switch (file_type) {
        case FileType::TEXT_DOCUMENT:
            return text_distribution_;
        case FileType::EXECUTABLE:
            return executable_distribution_;
        case FileType::IMAGE:
            return image_distribution_;
        default:
            // Return uniform distribution for unknown types
            std::array<double, 256> uniform = {};
            std::fill(uniform.begin(), uniform.end(), 1.0 / 256.0);
            return uniform;
        }
    }

    /**
     * @brief Detect file type from path
     */
    FileType FileTypeDetector::DetectFileType(const std::wstring& file_path)
    {
        // Extract extension
        std::filesystem::path path(file_path);
        std::wstring extension = path.extension().wstring();

        // Convert to lowercase
        std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);

        // Look up in extension map
        auto it = EXTENSION_MAP.find(extension);
        if (it != EXTENSION_MAP.end()) {
            return it->second;
        }

        return FileType::UNKNOWN;
    }

    /**
     * @brief Detect file type from content
     */
    FileType FileTypeDetector::DetectFileTypeFromContent(const std::vector<uint8_t>& data)
    {
        if (data.empty()) {
            return FileType::UNKNOWN;
        }

        // Check magic numbers
        for (const auto& [magic, type] : MAGIC_NUMBERS) {
            if (data.size() >= magic.size()) {
                bool match = true;
                for (size_t i = 0; i < magic.size(); ++i) {
                    if (data[i] != magic[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return type;
                }
            }
        }

        return FileType::UNKNOWN;
    }

} // namespace CryptoShield::Detection