#pragma once
/**
 * @file EntropyAnalyzer.h
 * @brief Entropy analysis for ransomware detection
 * @details Implements Shannon entropy, Chi-square, and Hamming distance analysis
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include "TraditionalEngine.h"
#include <array>
#include <vector>
#include <memory>
#include <mutex>
#include <cmath>
#include <unordered_map>

namespace CryptoShield::Detection {

    /**
     * @brief Entropy analysis result structure
     */
    struct EntropyAnalysisResult {
        double shannon_entropy;
        double chi_square_value;
        double hamming_distance;
        bool is_high_entropy;
        bool is_random_distribution;
        double confidence_score;
        std::string analysis_notes;
    };

    /**
     * @brief Frequency distribution profile
     */
    struct FrequencyProfile {
        std::array<double, 256> byte_frequencies;
        double uniformity_score;
        double deviation_from_natural;
        double most_common_byte;
        double least_common_byte;
    };

    /**
     * @brief Entropy trend analysis
     */
    struct EntropyTrend {
        double initial_entropy;
        double final_entropy;
        double delta;
        double trend_coefficient;
        bool significant_change;
        std::vector<double> entropy_history;
    };

    /**
     * @brief Shannon entropy analyzer with optimization
     * @details Uses lookup tables for performance optimization
     */
    class ShannonEntropyAnalyzer {
    public:
        /**
         * @brief Constructor
         */
        ShannonEntropyAnalyzer();

        /**
         * @brief Destructor
         */
        ~ShannonEntropyAnalyzer() = default;

        /**
         * @brief Calculate Shannon entropy
         * @param data Data buffer to analyze
         * @param length Size of data buffer
         * @return Entropy value (0-8 bits)
         */
        double CalculateEntropy(const uint8_t* data, size_t length);

        /**
         * @brief Calculate Shannon entropy
         * @param data Vector of data to analyze
         * @return Entropy value (0-8 bits)
         */
        double CalculateEntropy(const std::vector<uint8_t>& data);

        /**
         * @brief Check if entropy indicates encryption
         * @param entropy Entropy value
         * @param file_type Type of file for adaptive threshold
         * @return true if entropy is suspiciously high
         */
        bool IsHighEntropy(double entropy, FileType file_type) const;

        /**
         * @brief Get adaptive threshold for file type
         * @param file_type Type of file
         * @return Entropy threshold
         */
        double GetAdaptiveThreshold(FileType file_type) const;

        /**
         * @brief Perform Chi-square test for randomness
         * @param data Data to analyze
         * @return Chi-square value
         */
        double PerformChiSquareTest(const std::vector<uint8_t>& data);

        /**
         * @brief Check if distribution is random
         * @param chi_square_value Chi-square test result
         * @return true if distribution appears random
         */
        bool IsRandomDistribution(double chi_square_value) const;

        /**
         * @brief Calculate Hamming distance between two buffers
         * @param before Original data
         * @param after Modified data
         * @return Hamming distance (0-1, normalized)
         */
        double CalculateHammingDistance(const std::vector<uint8_t>& before,
            const std::vector<uint8_t>& after);

    private:
        /**
         * @brief Initialize lookup table for log2 calculations
         */
        void InitializeLookupTable();

        /**
         * @brief Fast log2 calculation using lookup table
         * @param value Input value
         * @return log2(value)
         */
        inline double FastLog2(double value) const;

    private:
        // Lookup table for performance optimization
        static constexpr size_t LOOKUP_TABLE_SIZE = 10000;
        std::array<double, LOOKUP_TABLE_SIZE> log2_lookup_table_;
        bool lookup_table_initialized_;
        mutable std::mutex lookup_mutex_;

        // Entropy thresholds by file type
        static constexpr double THRESHOLD_TEXT = 4.5;
        static constexpr double THRESHOLD_IMAGE = 7.0;
        static constexpr double THRESHOLD_EXECUTABLE = 6.0;
        static constexpr double THRESHOLD_COMPRESSED = 7.8;
        static constexpr double THRESHOLD_DATABASE = 5.5;
        static constexpr double THRESHOLD_MEDIA = 7.2;
        static constexpr double THRESHOLD_UNKNOWN = 6.5;

        // Chi-square threshold for randomness (95% confidence)
        static constexpr double CHI_SQUARE_THRESHOLD = 293.25;
    };

    /**
     * @brief Advanced entropy analysis techniques
     */
    class AdvancedEntropyAnalysis {
    public:
        /**
         * @brief Constructor
         */
        AdvancedEntropyAnalysis();

        /**
         * @brief Destructor
         */
        ~AdvancedEntropyAnalysis() = default;

        /**
         * @brief Calculate block-based entropy
         * @param data Data to analyze
         * @param block_size Size of each block
         * @return Vector of entropy values per block
         */
        std::vector<double> CalculateBlockEntropy(const std::vector<uint8_t>& data,
            size_t block_size = 4096);

        /**
         * @brief Analyze entropy trend over time
         * @param entropy_history Historical entropy values
         * @return Entropy trend analysis
         */
        EntropyTrend AnalyzeEntropyTrend(const std::vector<double>& entropy_history);

        /**
         * @brief Analyze frequency distribution
         * @param data Data to analyze
         * @return Frequency distribution profile
         */
        FrequencyProfile AnalyzeFrequencyDistribution(const std::vector<uint8_t>& data);

        /**
         * @brief Detect partial encryption
         * @param block_entropies Entropy values per block
         * @return Percentage of blocks likely encrypted
         */
        double DetectPartialEncryption(const std::vector<double>& block_entropies);

        /**
         * @brief Calculate Kullback-Leibler divergence
         * @param data Data to analyze
         * @param reference_distribution Expected distribution
         * @return KL divergence value
         */
        double CalculateKLDivergence(const std::vector<uint8_t>& data,
            const std::array<double, 256>& reference_distribution);

        /**
         * @brief Perform comprehensive entropy analysis
         * @param data Data to analyze
         * @param file_type Type of file
         * @return Complete analysis result
         */
        EntropyAnalysisResult PerformComprehensiveAnalysis(const std::vector<uint8_t>& data,
            FileType file_type);


        // Este método delega la llamada al miembro privado de forma segura
        double GetAdaptiveThreshold(FileType file_type) const {
            if (shannon_analyzer_) {
                return shannon_analyzer_->GetAdaptiveThreshold(file_type);
            }
            // Devuelve un valor por defecto muy alto si el analizador no existe
            return 8.0;
        }

    private:
        /**
         * @brief Calculate linear regression for trend
         * @param values Y values (entropy)
         * @return Slope of trend line
         */
        double CalculateTrendSlope(const std::vector<double>& values);

        /**
         * @brief Get reference distribution for file type
         * @param file_type Type of file
         * @return Expected byte distribution
         */
        std::array<double, 256> GetReferenceDistribution(FileType file_type);

    private:
        // Shannon entropy analyzer instance
        std::unique_ptr<ShannonEntropyAnalyzer> shannon_analyzer_;

        // Reference distributions for different file types
        std::array<double, 256> text_distribution_;
        std::array<double, 256> executable_distribution_;
        std::array<double, 256> image_distribution_;

        // Threshold for detecting encrypted blocks
        static constexpr double ENCRYPTED_BLOCK_THRESHOLD = 7.5;

        // Minimum block size for analysis
        static constexpr size_t MIN_BLOCK_SIZE = 256;
    };

    /**
     * @brief Utility class for file type detection
     */
    class FileTypeDetector {
    public:
        /**
         * @brief Detect file type from path
         * @param file_path Path to file
         * @return Detected file type
         */
        static FileType DetectFileType(const std::wstring& file_path);

        /**
         * @brief Detect file type from content
         * @param data File content (first few bytes)
         * @return Detected file type
         */
        static FileType DetectFileTypeFromContent(const std::vector<uint8_t>& data);

    private:
        // Magic numbers for file type detection
        static const std::vector<std::pair<std::vector<uint8_t>, FileType>> MAGIC_NUMBERS;

        // Extension to file type mapping
        static const std::unordered_map<std::wstring, FileType> EXTENSION_MAP;
    };

} // namespace CryptoShield::Detection