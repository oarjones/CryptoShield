# Tarea 2: Motor de Detección Tradicional Completo

## 🎯 Objetivos de la Tarea
Implementar un motor de detección robusto basado en técnicas tradicionales probabilísticas y patrones de comportamiento para detectar ransomware conocido y variantes.

## 📋 Alcance
- **Duración estimada**: 2 semanas
- **Prioridad**: ALTA (Core detection capabilities)
- **Dependencias**: Tarea 1 (Minifilter básico)
- **Entregables**: Motor de detección completo + Testing suite

## 🏗️ Arquitectura de la Tarea

```
┌─── TRADITIONAL DETECTION ENGINE ─────────────────────┐
│                                                      │
│  ┌─── Entropy Analysis ─────────────────────────┐    │
│  │  ├── Shannon Entropy Calculator              │    │
│  │  ├── Chi-Square Test                         │    │
│  │  ├── Hamming Distance Analysis               │    │
│  │  └── File Type Adaptive Thresholds          │    │
│  └─────────────────────────────────────────────┘    │
│                                                      │
│  ┌─── Behavioral Pattern Detection ─────────────┐    │
│  │  ├── Mass File Modification Detector        │    │
│  │  ├── File Extension Change Monitor          │    │
│  │  ├── Directory Traversal Pattern            │    │
│  │  └── Temporal Correlation Analysis          │    │
│  └─────────────────────────────────────────────┘    │
│                                                      │
│  ┌─── System Activity Analysis ─────────────────┐    │
│  │  ├── Shadow Copy Deletion Detector          │    │
│  │  ├── Boot Configuration Monitor             │    │
│  │  ├── Registry Modification Tracker          │    │
│  │  └── Process Behavior Analyzer              │    │
│  └─────────────────────────────────────────────┘    │
│                                                      │
│  ┌─── Scoring & Decision Engine ────────────────┐    │
│  │  ├── Multi-criteria Scoring                 │    │
│  │  ├── Confidence Level Calculator            │    │
│  │  ├── False Positive Minimizer               │    │
│  │  └── Threat Level Classifier                │    │
│  └─────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

## 📂 Estructura de Archivos

### Archivos del Motor de Detección
```
Service/CryptoShieldService/Detection/
├── TraditionalEngine.h/cpp         # Engine principal
├── EntropyAnalyzer.h/cpp           # Análisis de entropía
├── BehavioralDetector.h/cpp        # Patrones de comportamiento
├── SystemActivityMonitor.h/cpp     # Monitoreo de sistema
├── ScoringEngine.h/cpp             # Sistema de puntuación
├── PatternDatabase.h/cpp           # Base de datos de patrones
└── DetectionConfig.h/cpp           # Configuración del motor
```

### Archivos de Testing
```
Test/TraditionalDetection/
├── EntropyTests.cpp                # Tests de entropía
├── BehavioralTests.cpp             # Tests de comportamiento
├── SyntheticSampleGenerator.cpp    # Generador de muestras
├── PerformanceBenchmarks.cpp       # Benchmarks de rendimiento
└── FalsePositiveTests.cpp          # Tests de falsos positivos
```

## 🔧 Componentes a Implementar

### 1. Entropy Analysis Engine

#### 1.1 Shannon Entropy Calculator (EntropyAnalyzer.h/cpp)
```cpp
class ShannonEntropyAnalyzer {
private:
    static constexpr size_t LOOKUP_TABLE_SIZE = 1000;
    static double log2_lookup_table_[LOOKUP_TABLE_SIZE];
    static bool lookup_table_initialized_;
    
public:
    // Cálculo optimizado de entropía con lookup table
    double CalculateEntropy(const std::vector<uint8_t>& data);
    double CalculateEntropy(const uint8_t* buffer, size_t length);
    
    // Análisis adaptativo por tipo de archivo
    bool IsHighEntropy(double entropy, FileType file_type);
    double GetAdaptiveThreshold(FileType file_type);
    
    // Chi-Square test para aleatoriedad
    double PerformChiSquareTest(const std::vector<uint8_t>& data);
    bool IsRandomDistribution(double chi_square_value);
    
    // Hamming distance para comparación de archivos
    double CalculateHammingDistance(const std::vector<uint8_t>& before, 
                                   const std::vector<uint8_t>& after);
};

// Thresholds adaptativos por tipo de archivo
enum class FileType {
    TEXT_DOCUMENT,    // .txt, .doc, .pdf (threshold: 4.5)
    IMAGE,           // .jpg, .png, .gif (threshold: 7.0)
    EXECUTABLE,      // .exe, .dll, .sys (threshold: 6.0)
    COMPRESSED,      // .zip, .rar, .7z (threshold: 7.8)
    DATABASE,        // .db, .mdb, .sqlite (threshold: 5.5)
    UNKNOWN          // Archivos desconocidos (threshold: 6.5)
};
```

#### 1.2 Advanced Entropy Techniques
```cpp
class AdvancedEntropyAnalysis {
public:
    // Block-based entropy para detectar encryption parcial
    std::vector<double> CalculateBlockEntropy(const std::vector<uint8_t>& data, 
                                            size_t block_size = 4096);
    
    // Entropy trend analysis
    struct EntropyTrend {
        double initial_entropy;
        double final_entropy;
        double delta;
        double trend_coefficient;
        bool significant_change;
    };
    
    EntropyTrend AnalyzeEntropyTrend(const std::vector<double>& entropy_history);
    
    // Frequency distribution analysis
    struct FrequencyProfile {
        std::array<double, 256> byte_frequencies;
        double uniformity_score;
        double deviation_from_natural;
    };
    
    FrequencyProfile AnalyzeFrequencyDistribution(const std::vector<uint8_t>& data);
};
```

### 2. Behavioral Pattern Detection

#### 2.1 Mass File Modification Detector (BehavioralDetector.h/cpp)
```cpp
class MassFileModificationDetector {
private:
    struct OperationWindow {
        std::chrono::steady_clock::time_point start_time;
        std::vector<FileOperation> operations;
        std::set<std::wstring> affected_directories;
        std::set<std::string> file_extensions;
        std::map<uint32_t, size_t> process_operation_count;
    };
    
    OperationWindow current_window_;
    std::chrono::seconds window_duration_;
    
    // Thresholds configurables
    size_t min_operations_threshold_;
    size_t min_directories_threshold_;
    size_t min_extensions_threshold_;
    double max_operations_per_second_;
    
public:
    struct DetectionResult {
        bool is_suspicious;
        double confidence_score;
        std::string description;
        size_t operations_count;
        size_t directories_affected;
        size_t extensions_affected;
        double operations_per_second;
    };
    
    DetectionResult AnalyzeOperation(const FileOperation& operation);
    void ResetWindow();
    void ConfigureThresholds(size_t ops, size_t dirs, size_t exts, double rate);
    
private:
    double CalculateSuspicionScore() const;
    bool IsRapidEncryptionPattern() const;
    bool IsWideSpreadModification() const;
};
```

#### 2.2 File Extension Change Monitor
```cpp
class FileExtensionMonitor {
private:
    // Mapeo de archivos originales a extensiones cambiadas
    std::map<std::wstring, std::string> original_extensions_;
    
    // Patrones de extensiones sospechosas
    static const std::vector<std::string> RANSOMWARE_EXTENSIONS;
    static const std::vector<std::string> SUSPICIOUS_PATTERNS;
    
public:
    struct ExtensionChangeEvent {
        std::wstring file_path;
        std::string original_extension;
        std::string new_extension;
        std::chrono::steady_clock::time_point timestamp;
        uint32_t process_id;
        bool is_suspicious;
    };
    
    bool AnalyzeFileRename(const std::wstring& old_path, 
                          const std::wstring& new_path,
                          uint32_t process_id);
    
    double CalculateExtensionSuspicion(const std::string& extension);
    bool IsKnownRansomwareExtension(const std::string& extension);
    
private:
    std::string ExtractExtension(const std::wstring& file_path);
    bool MatchesSuspiciousPattern(const std::string& extension);
};
```

### 3. System Activity Analysis

#### 3.1 Shadow Copy Deletion Detector (SystemActivityMonitor.h/cpp)
```cpp
class ShadowCopyDeletionDetector {
private:
    // Comandos sospechosos conocidos
    static const std::vector<std::wstring> SHADOW_DELETION_COMMANDS;
    static const std::vector<std::wstring> BOOT_CONFIG_COMMANDS;
    static const std::vector<std::wstring> RECOVERY_DISABLE_COMMANDS;
    
    // Procesos que pueden ejecutar estos comandos legítimamente
    static const std::vector<std::wstring> LEGITIMATE_PROCESSES;
    
public:
    struct ShadowDeletionEvent {
        std::wstring command_line;
        std::wstring process_name;
        uint32_t process_id;
        uint32_t parent_process_id;
        std::chrono::steady_clock::time_point timestamp;
        double suspicion_score;
        std::string detection_reason;
    };
    
    ShadowDeletionEvent AnalyzeCommandLine(const std::wstring& command_line,
                                          const std::wstring& process_name,
                                          uint32_t process_id,
                                          uint32_t parent_pid);
    
    bool IsLegitimateProcess(const std::wstring& process_name, 
                            const std::wstring& command_line);
    
private:
    double ScoreCommandSuspicion(const std::wstring& command);
    double ScoreProcessContext(const std::wstring& process_name, uint32_t parent_pid);
};
```

#### 3.2 Registry Modification Tracker
```cpp
class RegistryModificationTracker {
private:
    // Claves críticas del registro a monitorear
    static const std::vector<std::wstring> CRITICAL_REGISTRY_KEYS;
    static const std::vector<std::wstring> STARTUP_KEYS;
    static const std::vector<std::wstring> SECURITY_KEYS;
    
    struct RegistryChange {
        std::wstring key_path;
        std::wstring value_name;
        std::wstring old_value;
        std::wstring new_value;
        uint32_t process_id;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    std::vector<RegistryChange> recent_changes_;
    
public:
    struct RegistryThreatAnalysis {
        bool is_suspicious;
        double confidence_score;
        std::string threat_type;
        std::vector<std::string> affected_keys;
        std::string description;
    };
    
    RegistryThreatAnalysis AnalyzeRegistryChange(const std::wstring& key_path,
                                               const std::wstring& value_name,
                                               uint32_t process_id);
    
    bool IsCriticalKey(const std::wstring& key_path);
    bool IsStartupModification(const std::wstring& key_path);
    bool IsSecurityBypass(const std::wstring& key_path, const std::wstring& value);
};
```

### 4. Scoring & Decision Engine

#### 4.1 Multi-criteria Scoring System (ScoringEngine.h/cpp)
```cpp
class TraditionalScoringEngine {
private:
    struct WeightConfiguration {
        double entropy_weight = 0.3;
        double behavioral_weight = 0.25;
        double system_activity_weight = 0.25;
        double temporal_weight = 0.2;
    };
    
    WeightConfiguration weights_;
    
public:
    struct ComprehensiveAnalysis {
        // Individual component scores
        double entropy_score;
        double behavioral_score;
        double system_activity_score;
        double temporal_score;
        
        // Combined results
        double overall_confidence;
        ThreatLevel threat_level;
        std::vector<std::string> contributing_factors;
        std::string detailed_explanation;
        
        // Metadata
        std::chrono::steady_clock::time_point analysis_timestamp;
        uint32_t primary_process_id;
        std::vector<std::wstring> affected_files;
    };
    
    ComprehensiveAnalysis AnalyzeComprehensively(
        const EntropyAnalysisResult& entropy_result,
        const BehavioralAnalysisResult& behavioral_result,
        const SystemActivityResult& system_result,
        const std::vector<FileOperation>& recent_operations
    );
    
    ThreatLevel ClassifyThreatLevel(double overall_confidence);
    void UpdateWeights(const WeightConfiguration& new_weights);
    
private:
    double CalculateTemporalScore(const std::vector<FileOperation>& operations);
    std::string GenerateExplanation(const ComprehensiveAnalysis& analysis);
    double ApplyFalsePositiveReduction(double raw_score, 
                                      const std::string& process_name);
};
```

#### 4.2 False Positive Minimizer
```cpp
class FalsePositiveMinimizer {
private:
    // Whitelist de procesos legítimos
    static const std::vector<std::wstring> LEGITIMATE_PROCESSES;
    static const std::vector<std::wstring> BACKUP_SOFTWARE;
    static const std::vector<std::wstring> COMPRESSION_TOOLS;
    static const std::vector<std::wstring> MEDIA_ENCODERS;
    
    // Patrones de comportamiento legítimo
    struct LegitimatePattern {
        std::wstring process_name;
        std::vector<std::string> allowed_extensions;
        double max_entropy_threshold;
        size_t max_operations_per_minute;
    };
    
    std::vector<LegitimatePattern> legitimate_patterns_;
    
public:
    struct FalsePositiveAnalysis {
        bool likely_false_positive;
        double adjustment_factor;  // Factor de reducción de score (0-1)
        std::string reason;
        std::vector<std::string> legitimacy_indicators;
    };
    
    FalsePositiveAnalysis AnalyzeLegitimacy(
        const std::wstring& process_name,
        const std::vector<FileOperation>& operations,
        double original_score
    );
    
    bool IsLegitimateBackupActivity(const std::vector<FileOperation>& operations);
    bool IsLegitimateCompressionActivity(const std::wstring& process_name,
                                        const std::vector<FileOperation>& operations);
    bool IsLegitimateMediaProcessing(const std::vector<FileOperation>& operations);
    
private:
    double CalculateProcessReputationScore(const std::wstring& process_name);
    bool MatchesLegitimatePattern(const LegitimatePattern& pattern,
                                 const std::vector<FileOperation>& operations);
};
```

## 🧪 Testing y Validación

### Test Suite Comprehensive

#### 1. Entropy Analysis Tests
```cpp
class EntropyAnalysisTests {
public:
    // Test básicos de entropía
    void TestShannonEntropyCalculation();
    void TestEntropyThresholds();
    void TestChiSquareAnalysis();
    void TestHammingDistance();
    
    // Test con datos reales
    void TestWithEncryptedFiles();
    void TestWithCompressedFiles();
    void TestWithNormalDocuments();
    void TestWithExecutables();
    
    // Performance tests
    void BenchmarkEntropyCalculation();
    void TestLookupTableAccuracy();
    
private:
    std::vector<uint8_t> GenerateRandomData(size_t size);
    std::vector<uint8_t> GenerateTextData(size_t size);
    std::vector<uint8_t> LoadTestFile(const std::string& filename);
};
```

#### 2. Behavioral Pattern Tests
```cpp
class BehavioralPatternTests {
public:
    void TestMassFileModificationDetection();
    void TestFileExtensionChangeDetection();
    void TestTemporalPatternAnalysis();
    void TestFalsePositiveScenarios();
    
    // Synthetic ransomware simulation
    void SimulateRansomwareBehavior();
    void SimulateLegitimateBackupActivity();
    void SimulateCompressionSoftware();
    void SimulateMediaProcessing();
    
private:
    void CreateTestFileSet(const std::wstring& directory, size_t count);
    void SimulateFileEncryption(const std::vector<std::wstring>& files);
    void SimulateFileCompression(const std::vector<std::wstring>& files);
};
```

#### 3. Synthetic Sample Generator
```cpp
class SyntheticRansomwareGenerator {
public:
    // Generación de comportamiento de ransomware sintético
    void GenerateFileEncryptorBehavior(const std::wstring& target_directory);
    void GenerateShadowDeletionBehavior();
    void GenerateRegistryModificationBehavior();
    void GenerateNetworkPropagationBehavior();
    
    // Generación de comportamiento legítimo para test de falsos positivos
    void GenerateBackupSoftwareBehavior();
    void GenerateCompilerBehavior();
    void GenerateVideoEncodingBehavior();
    void GenerateArchiveExtractionBehavior();
    
private:
    void CreateTestFiles(const std::wstring& directory, 
                        const std::vector<std::string>& extensions,
                        size_t files_per_extension);
    void EncryptTestFiles(const std::vector<std::wstring>& files);
    void ExecuteSystemCommands(const std::vector<std::wstring>& commands);
};
```

## 📊 Métricas de Éxito

### Detection Accuracy
- **True Positive Rate**: > 99% para ransomware conocido
- **False Positive Rate**: < 0.1% en uso normal
- **Detection Time**: < 30 segundos promedio
- **Coverage**: Detección de 95% de familias de ransomware

### Performance Metrics
- **CPU Usage**: < 3% durante análisis activo
- **Memory Usage**: < 50MB para el motor de detección
- **Disk I/O Impact**: < 5% de overhead
- **Response Time**: < 1 segundo para scoring

### Reliability Metrics
- **Uptime**: 99.9% availability
- **Crash Rate**: 0 crashes en 1000 horas de operación
- **Memory Leaks**: 0 memory leaks detectados
- **Resource Cleanup**: 100% cleanup en shutdown

## 🚀 Plan de Implementación

### Semana 1: Core Detection Engine

**Días 1-2**: Entropy Analysis
- Implementar Shannon entropy calculator con lookup tables
- Desarrollar adaptive thresholds por tipo de archivo
- Crear Chi-square test implementation
- Implementar Hamming distance calculator

**Días 3-4**: Behavioral Pattern Detection
- Desarrollar mass file modification detector
- Implementar file extension change monitor
- Crear temporal pattern analyzer
- Desarrollar directory traversal detector

**Días 5-7**: System Activity Monitoring
- Implementar shadow copy deletion detector
- Crear registry modification tracker
- Desarrollar boot configuration monitor
- Implementar process behavior analyzer

### Semana 2: Integration & Testing

**Días 1-2**: Scoring Engine
- Desarrollar multi-criteria scoring system
- Implementar threat level classifier
- Crear false positive minimizer
- Desarrollar confidence calculator

**Días 3-4**: Testing Suite
- Crear synthetic sample generator
- Implementar comprehensive test cases
- Desarrollar performance benchmarks
- Crear false positive test scenarios

**Días 5-7**: Integration & Validation
- Integrar todos los componentes
- Ejecutar testing suite completo
- Optimizar performance
- Documentar resultados y configuraciones

## 🔧 Configuración y Tuning

### Configuration File (detection_config.json)
```json
{
  "entropy_analysis": {
    "enabled": true,
    "thresholds": {
      "text_files": 4.5,
      "images": 7.0,
      "executables": 6.0,
      "compressed": 7.8,
      "databases": 5.5,
      "unknown": 6.5
    },
    "block_size": 4096,
    "enable_chi_square": true
  },
  "behavioral_detection": {
    "enabled": true,
    "mass_modification": {
      "min_operations": 50,
      "min_directories": 3,
      "min_extensions": 2,
      "time_window_seconds": 60,
      "max_ops_per_second": 10.0
    },
    "extension_monitoring": {
      "track_changes": true,
      "suspicious_patterns": ["*.encrypted", "*.locked", "*.crypto"]
    }
  },
  "system_monitoring": {
    "enabled": true,
    "shadow_copy_detection": true,
    "registry_monitoring": true,
    "boot_config_monitoring": true
  },
  "scoring": {
    "weights": {
      "entropy": 0.30,
      "behavioral": 0.25,
      "system_activity": 0.25,
      "temporal": 0.20
    },
    "threat_thresholds": {
      "low": 0.3,
      "medium": 0.6,
      "high": 0.8,
      "critical": 0.95
    },
    "false_positive_reduction": true
  }
}
```

## 📋 Checklist de Completitud

### Core Components
- [ ] Shannon entropy calculator implementado
- [ ] Chi-square test implementado  
- [ ] Hamming distance calculator implementado
- [ ] Mass file modification detector implementado
- [ ] File extension change monitor implementado
- [ ] Shadow copy deletion detector implementado
- [ ] Registry modification tracker implementado
- [ ] Multi-criteria scoring engine implementado
- [ ] False positive minimizer implementado

### Testing Suite
- [ ] Entropy analysis tests implementados
- [ ] Behavioral pattern tests implementados
- [ ] System activity tests implementados
- [ ] Synthetic sample generator implementado
- [ ] Performance benchmarks implementados
- [ ] False positive test cases implementados
- [ ] Integration tests implementados

### Performance & Quality
- [ ] CPU usage < 3% verificado
- [ ] Memory usage < 50MB verificado
- [ ] Detection accuracy > 99% verificado
- [ ] False positive rate < 0.1% verificado
- [ ] No memory leaks detectados
- [ ] Thread safety verificado
- [ ] Exception handling implementado

### Documentation
- [ ] API documentation completa
- [ ] Configuration guide completa
- [ ] Testing procedures documentadas
- [ ] Performance benchmarks documentados
- [ ] Troubleshooting guide completa

## 🎯 Entregables de la Tarea

1. **Traditional Detection Engine** - Motor completo con todos los componentes
2. **Comprehensive Test Suite** - Tests automatizados y manuales
3. **Synthetic Sample Generator** - Herramienta para generar comportamiento de prueba
4. **Performance Benchmarks** - Métricas de rendimiento documentadas
5. **Configuration System** - Sistema flexible de configuración
6. **Integration Layer** - Integración con Tarea 1 (minifilter)
7. **Documentation Package** - Documentación técnica completa

Esta tarea establece las bases sólidas de detección que serán complementadas por las técnicas avanzadas de ML en las siguientes tareas.