#include "pch.h"
#include <nlohmann/json.hpp>


// Incluir las cabeceras de los componentes a probar
#include "Utils\StringUtils.h"
#include "Detection\EntropyAnalyzer.h"
#include "Detection\BehavioralDetector.h"
#include "Detection\DetectionConfig.h"

#include "SyntheticDataGenerator.h"


// --- INICIO DE NUEVOS TESTS ---

// Suite de tests para el Analizador de Entropía
class EntropyAnalysisTests : public ::testing::Test {
protected:
    std::unique_ptr<CryptoShield::Detection::AdvancedEntropyAnalysis> analyzer;

    void SetUp() override {
        analyzer = std::make_unique<CryptoShield::Detection::AdvancedEntropyAnalysis>();
    }

    std::vector<uint8_t> GenerateData(size_t size, int randomness) {
        std::vector<uint8_t> data(size);
        if (randomness == 0) { // All same byte
            std::fill(data.begin(), data.end(), 0x41);
        }
        else if (randomness == 1) { // Simple sequence
            for (size_t i = 0; i < size; ++i) {
                data[i] = (i % 2 == 0) ? 0xAA : 0xBB;
            }
        }
        else { // "Random" data
            std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<int> dist(0, 255);
            for (size_t i = 0; i < size; ++i) {
                data[i] = static_cast<uint8_t>(dist(rng));
            }
        }
        return data;
    }
};

TEST_F(EntropyAnalysisTests, TestShannonEntropyCalculation) {
    // La entropía de datos con un solo byte debe ser 0
    auto zeros = GenerateData(1024, 0);
    ASSERT_NEAR(analyzer->PerformComprehensiveAnalysis(zeros, CryptoShield::Detection::FileType::UNKNOWN).shannon_entropy, 0.0, 0.01);

    // La entropía de una secuencia simple de 2 bytes (0.5 prob cada uno) debe ser 1.0
    auto simple_seq = GenerateData(1024, 1);
    ASSERT_NEAR(analyzer->PerformComprehensiveAnalysis(simple_seq, CryptoShield::Detection::FileType::UNKNOWN).shannon_entropy, 1.0, 0.01);

    // La entropía de datos aleatorios debe ser alta (cercana a 8.0)
    auto random_data = GenerateData(4096, 2);
    ASSERT_GT(analyzer->PerformComprehensiveAnalysis(random_data, CryptoShield::Detection::FileType::UNKNOWN).shannon_entropy, 7.85);
}

TEST_F(EntropyAnalysisTests, TestEntropyThresholds) {
    // Simula un archivo de texto con baja entropía
    std::string text_str = "This is a typical sentence found in a document. It has low entropy.";
    std::vector<uint8_t> text_data(text_str.begin(), text_str.end());
    auto text_result = analyzer->PerformComprehensiveAnalysis(text_data, CryptoShield::Detection::FileType::TEXT_DOCUMENT);
    ASSERT_FALSE(text_result.is_high_entropy);
    ASSERT_LT(text_result.shannon_entropy, analyzer->GetAdaptiveThreshold(CryptoShield::Detection::FileType::TEXT_DOCUMENT));

    // Simula un archivo comprimido/cifrado con alta entropía
    auto random_data = GenerateData(4096, 2);
    auto encrypted_result = analyzer->PerformComprehensiveAnalysis(random_data, CryptoShield::Detection::FileType::COMPRESSED);
    ASSERT_TRUE(encrypted_result.is_high_entropy);
    ASSERT_GT(encrypted_result.shannon_entropy, analyzer->GetAdaptiveThreshold(CryptoShield::Detection::FileType::COMPRESSED));
}

TEST_F(EntropyAnalysisTests, TestChiSquareAnalysis) {
    // Datos aleatorios deben tener una distribución uniforme (Chi-Square bajo)
    auto random_data = GenerateData(8192, 2);
    auto random_result = analyzer->PerformComprehensiveAnalysis(random_data, CryptoShield::Detection::FileType::UNKNOWN);
    ASSERT_TRUE(random_result.is_random_distribution) << "Chi-Square value was: " << random_result.chi_square_value;

    // Datos de texto no son uniformes (Chi-Square alto)
    std::string text_str(8192, ' ');
    for (size_t i = 0; i < text_str.size(); ++i) text_str[i] = "This is a test sentence."[i % 25];
    std::vector<uint8_t> text_data(text_str.begin(), text_str.end());
    auto text_result = analyzer->PerformComprehensiveAnalysis(text_data, CryptoShield::Detection::FileType::TEXT_DOCUMENT);
    ASSERT_FALSE(text_result.is_random_distribution) << "Chi-Square value was: " << text_result.chi_square_value;
}


// Suite de tests para Detección por Comportamiento
class BehavioralPatternTests : public ::testing::Test {
protected:
    std::unique_ptr<CryptoShield::Detection::BehavioralDetector> detector;
    CryptoShield::Detection::DetectionEngineConfig config;

    void SetUp() override {
        config = CryptoShield::Detection::DetectionConfigManager::GetDefaultConfiguration();
        detector = std::make_unique<CryptoShield::Detection::BehavioralDetector>(config.behavioral);
    }

    CryptoShield::FileOperationInfo CreateOperation(uint32_t pid, const std::wstring& path, CryptoShield::FileOperationType type) {
        CryptoShield::FileOperationInfo op;
        op.process_id = pid;
        op.file_path = path;
        op.type = type;
        // La marca de tiempo se puede simplificar para los tests
        GetSystemTimeAsFileTime(&op.timestamp);
        return op;
    }
};

TEST_F(BehavioralPatternTests, TestMassFileModificationDetection) {
    uint32_t suspicious_pid = 1234;
    size_t op_count = config.behavioral.min_operations_threshold + 10;
    size_t dir_count = config.behavioral.min_directories_threshold + 1;
    size_t ext_count = config.behavioral.min_extensions_threshold + 1;

    CryptoShield::Detection::BehavioralAnalysisResult result;
    for (size_t i = 0; i < op_count; ++i) {
        std::wstring path = L"C:\\Users\\Test\\Documents\\Dir" + std::to_wstring(i % dir_count) + L"\\file" + std::to_wstring(i) + L".ext" + std::to_wstring(i % ext_count);
        result = detector->AnalyzeOperation(CreateOperation(suspicious_pid, path, CryptoShield::FileOperationType::Write));
    }

    // Debería ser detectado como sospechoso después de suficientes operaciones
    ASSERT_TRUE(result.is_suspicious);
    ASSERT_GT(result.confidence_score, config.behavioral.suspicion_score_threshold);
    ASSERT_EQ(result.operations_count, op_count);
    ASSERT_EQ(result.directories_affected, dir_count);
}

TEST_F(BehavioralPatternTests, TestBenignBehaviorIsNotSuspicious) {
    uint32_t benign_pid = 5678;
    // Operaciones por debajo del umbral
    size_t op_count = config.behavioral.min_operations_threshold - 10;

    CryptoShield::Detection::BehavioralAnalysisResult result;
    for (size_t i = 0; i < op_count; ++i) {
        std::wstring path = L"C:\\Program Files\\MyApp\\file" + std::to_wstring(i) + L".log";
        result = detector->AnalyzeOperation(CreateOperation(benign_pid, path, CryptoShield::FileOperationType::Write));
    }

    ASSERT_FALSE(result.is_suspicious);
    ASSERT_LT(result.confidence_score, config.behavioral.suspicion_score_threshold);
}

TEST_F(BehavioralPatternTests, TestFileExtensionChangeDetection) {
    uint32_t pid = 4321;
    // Usamos el subcomponente directamente para este test
    auto extension_monitor = std::make_unique<CryptoShield::Detection::FileExtensionMonitor>(config.behavioral);

    // Escenario 1: Cambio a extensión sospechosa
    auto suspicious_change = extension_monitor->AnalyzeFileRename(L"C:\\image.jpg", L"C:\\image.jpg.locked", pid);
    ASSERT_TRUE(suspicious_change.is_suspicious);
    ASSERT_GT(suspicious_change.suspicion_score, 0.8);
    ASSERT_EQ(suspicious_change.new_extension, L".locked");

    // Escenario 2: Cambio a extensión benigna
    auto benign_change = extension_monitor->AnalyzeFileRename(L"C:\\document.tmp", L"C:\\document.docx", pid);
    ASSERT_FALSE(benign_change.is_suspicious);
    ASSERT_EQ(benign_change.new_extension, L".docx");

    // Escenario 3: Cambio que coincide con un patrón regex sospechoso
    auto regex_change = extension_monitor->AnalyzeFileRename(L"C:\\file.data", L"C:\\file.data.id-1234ABCD.user@domain.com", pid);
    ASSERT_TRUE(regex_change.is_suspicious);
    ASSERT_GT(regex_change.suspicion_score, 0.7);

}

TEST_F(BehavioralPatternTests, SimulateLegitimateBackupActivity) {
    uint32_t backup_pid = 9988;
    std::vector<CryptoShield::FileOperationInfo> operations;

    // Simula la lectura de muchos archivos
    for (int i = 0; i < 100; ++i) {
        operations.push_back(CreateOperation(backup_pid, L"C:\\Users\\User\\Photos\\image" + std::to_wstring(i) + L".jpg", CryptoShield::FileOperationType::Create));
    }
    // Simula la escritura a un único archivo de backup
    for (int i = 0; i < 20; ++i) {
        operations.push_back(CreateOperation(backup_pid, L"D:\\Backups\\MyBackup.zip", CryptoShield::FileOperationType::Write));
    }

    CryptoShield::Detection::BehavioralAnalysisResult result;
    for (const auto& op : operations) {
        result = detector->AnalyzeOperation(op);
    }

    // Aunque hay muchas operaciones, el patrón no debería ser clasificado como ransomware
    // Nota: Este test es más complejo y su éxito depende de la implementación del FalsePositiveMinimizer
    // Por ahora, comprobamos que no alcance el umbral más alto de sospecha.
    ASSERT_LT(result.confidence_score, 0.9);
}


// --- Nuevo Test usando el Generador Sintético ---
TEST_F(BehavioralPatternTests, SimulateRansomwareEncryptorBehavior) {
    // 1. Preparación del escenario
    CryptoShield::Testing::SyntheticDataGenerator generator;
    std::vector<CryptoShield::FileOperationInfo> ransomware_ops;
    const std::wstring test_dir = L".\\temp_ransomware_test";

    // Crear directorio de prueba y limpiarlo si ya existe
    if (std::filesystem::exists(test_dir)) {
        std::filesystem::remove_all(test_dir);
    }
    std::filesystem::create_directory(test_dir);

    // Generar el comportamiento de un ataque de ransomware
    generator.GenerateFileEncryptorBehavior(test_dir, ransomware_ops);

    // 2. Ejecución del test
    CryptoShield::Detection::BehavioralAnalysisResult final_result;
    for (const auto& op : ransomware_ops) {
        final_result = detector->AnalyzeOperation(op);
    }

    // 3. Aserciones (Verificación)
    // El comportamiento simulado DEBE ser detectado como altamente sospechoso
    ASSERT_TRUE(final_result.is_suspicious);
    ASSERT_GT(final_result.confidence_score, 0.8) << "The confidence score should be high for a full ransomware simulation.";
    ASSERT_TRUE(final_result.description.find(L"Directories: 1") != std::wstring::npos);
    ASSERT_TRUE(final_result.description.find(L"Extensions: 5") != std::wstring::npos); // 4 originales + 1 .locked

    // Limpieza
    std::filesystem::remove_all(test_dir);
}

TEST_F(BehavioralPatternTests, SimulateLegitimateBackupFPTest) {
    // 1. Preparación del escenario
    CryptoShield::Testing::SyntheticDataGenerator generator;
    std::vector<CryptoShield::FileOperationInfo> backup_ops;
    const std::wstring source_dir = L".\\temp_backup_source";
    const std::wstring backup_file = L".\\temp_backup_file.bak";

    // Limpieza previa
    if (std::filesystem::exists(source_dir)) std::filesystem::remove_all(source_dir);
    if (std::filesystem::exists(backup_file)) std::filesystem::remove(backup_file);

    // Generar comportamiento de software de backup
    generator.GenerateBackupSoftwareBehavior(source_dir, backup_file, backup_ops);

    // 2. Ejecución
    CryptoShield::Detection::BehavioralAnalysisResult final_result;
    for (const auto& op : backup_ops) {
        final_result = detector->AnalyzeOperation(op);
    }

    // 3. Aserción
    // A pesar del alto número de operaciones, esto NO debería ser marcado como sospechoso
    // gracias al FalsePositiveMinimizer (que se probaría aquí implícitamente).
    ASSERT_FALSE(final_result.is_suspicious);
    ASSERT_LT(final_result.confidence_score, config.behavioral.suspicion_score_threshold);

    // Limpieza final
    if (std::filesystem::exists(source_dir)) std::filesystem::remove_all(source_dir);
    if (std::filesystem::exists(backup_file)) std::filesystem::remove(backup_file);
}



/**
 * @brief Test fixture for configuration loading tests.
 * @details Creates a temporary config file for testing and cleans it up afterwards.
 */
class ConfigLoadingTests : public ::testing::Test {
protected:
    const std::wstring test_config_path_ = L".\\test_config.json";

    /**
     * @brief Creates a known configuration file before each test.
     */
    void SetUp() override {
        std::ofstream ofs(test_config_path_);
        ASSERT_TRUE(ofs.is_open());

        // Usamos nlohmann/json para crear un JSON de prueba con valores conocidos
        nlohmann::json j;
        j["global"]["enable_detection"] = false;
        j["global"]["thread_pool_size"] = 8;
        j["behavioral_detection"]["min_operations"] = 99;
        j["behavioral_detection"]["suspicious_extensions"] = { ".test1", ".test2" };
        j["scoring"]["entropy_weight"] = 0.99;

        ofs << j.dump(4);
        ofs.close();
    }

    /**
     * @brief Deletes the temporary configuration file after each test.
     */
    void TearDown() override {
        if (std::filesystem::exists(test_config_path_)) {
            std::filesystem::remove(test_config_path_);
        }
    }
};

/**
 * @test Tests if the DetectionConfigManager can correctly load and parse a JSON config file.
 * @details Verifies that specific values from the test JSON are correctly reflected in the config struct.
 */
TEST_F(ConfigLoadingTests, CorrectlyLoadsValuesFromFile) {
    // Arrange
    auto config_manager = std::make_unique<CryptoShield::Detection::DetectionConfigManager>();

    // Act
    bool load_success = config_manager->LoadConfiguration(test_config_path_);

    // Assert
    ASSERT_TRUE(load_success);

    // Obtener la configuración cargada y verificar los valores
    CryptoShield::Detection::DetectionEngineConfig loaded_config = config_manager->GetConfiguration();

    // Verificar valores de diferentes tipos
    EXPECT_FALSE(loaded_config.global.enable_detection);
    EXPECT_EQ(loaded_config.global.thread_pool_size, 8);
    EXPECT_EQ(loaded_config.behavioral.min_operations_threshold, 99);
    EXPECT_DOUBLE_EQ(loaded_config.scoring.entropy_weight, 0.99);

    // Verificar el contenido de un vector
    ASSERT_EQ(loaded_config.behavioral.suspicious_extensions.size(), 2);
    EXPECT_EQ(loaded_config.behavioral.suspicious_extensions[0], L".test1");
    EXPECT_EQ(loaded_config.behavioral.suspicious_extensions[1], L".test2");
}

/**
 * @test Tests that loading a non-existent file returns false.
 */
TEST_F(ConfigLoadingTests, FailsToLoadNonExistentFile)
{
    // Arrange
    auto config_manager = std::make_unique<CryptoShield::Detection::DetectionConfigManager>();

    // Act
    bool load_success = config_manager->LoadConfiguration(L".\\non_existent_file.json");

    // Assert
    ASSERT_FALSE(load_success);
}