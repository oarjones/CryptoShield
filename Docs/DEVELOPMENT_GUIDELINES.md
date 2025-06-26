# CryptoShield - Instrucciones de Desarrollo

## 🎯 Principios Fundamentales

### Seguridad Primero
- **Nunca comprometer la seguridad por performance**: La seguridad es la prioridad #1
- **Validar todas las entradas**: Especialmente en interfaces kernel-user y APIs externas
- **Principio de menor privilegio**: Solicitar solo los permisos mínimos necesarios
- **Fail-safe por defecto**: En caso de error, denegar acceso/operación

### Estabilidad del Sistema
- **Zero crashes**: El código debe ser robusto contra crashes del sistema
- **Manejo defensivo**: Asumir que las entradas pueden ser maliciosas
- **Recovery automático**: Implementar mecanismos de auto-recuperación
- **Resource cleanup**: Always cleanup resources, especialmente en kernel mode

## 💻 Estándares de Código

### Comentarios y Documentación
```cpp
/**
 * @brief Descripción concisa de la función (una línea)
 * @details Descripción detallada si es necesario (máximo 3 líneas)
 * 
 * @param param_name Descripción del parámetro
 * @return Descripción del valor de retorno
 * @throws Exception_type Cuándo y por qué se lanza
 * 
 * @note Notas importantes sobre uso o limitaciones
 * @warning Advertencias críticas de seguridad o uso
 * @example Ejemplo de uso si la función es compleja
 */
```

### Naming Conventions
- **Clases**: PascalCase (`TelemetryCollector`)
- **Funciones**: PascalCase (`CalculateEntropy`)
- **Variables**: snake_case (`detection_result`)
- **Constantes**: UPPER_SNAKE_CASE (`MAX_BUFFER_SIZE`)
- **Miembros privados**: trailing underscore (`config_`, `is_active_`)

### Error Handling
```cpp
// Siempre usar HRESULT en Windows APIs
HRESULT result = SomeWindowsFunction();
if (FAILED(result)) {
    LogError("Operation failed", result);
    return result; // Propagar error
}

// Try-catch solo para casos específicos, no como control de flujo
try {
    RiskyOperation();
} catch (const std::specific_exception& e) {
    LogError("Specific error occurred", e.what());
    // Handle gracefully
}
```

## 🧠 Gestión de Memoria

### Principios de Memoria
- **RAII obligatorio**: Usar smart pointers y wrappers automáticos
- **No raw pointers**: Except para interfaces C y kernel APIs
- **Pool allocation**: Usar memory pools para allocaciones frecuentes
- **Stack over heap**: Preferir stack allocation cuando sea posible

### Memory Management Patterns
```cpp
// Preferir smart pointers
std::unique_ptr<Component> component = std::make_unique<Component>();

// Para kernel: Always pair allocation/deallocation
PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, size, TAG);
if (buffer) {
    // Use buffer
    ExFreePoolWithTag(buffer, TAG);
}

// Pre-allocate para hot paths
class HotPathClass {
    std::array<uint8_t, BUFFER_SIZE> fixed_buffer_; // Stack allocation
    std::vector<Data> data_; // Reserve capacity en constructor
};
```

## ⚡ Optimización de Performance

### Hot Path Optimization
- **Minimize allocations**: Pre-allocate buffers en hot paths
- **Cache-friendly data**: Struct of Arrays mejor que Array of Structs
- **Branch prediction**: Organizar conditionals por probabilidad
- **Inline critical functions**: Marcar funciones críticas como inline

### Concurrency Patterns
```cpp
// Preferir shared_mutex para read-heavy workloads
mutable std::shared_mutex data_mutex_;
std::shared_lock<std::shared_mutex> read_lock(data_mutex_); // Para reads
std::unique_lock<std::shared_mutex> write_lock(data_mutex_); // Para writes

// Atomic para flags simples
std::atomic<bool> is_active_{false};

// Lock-free cuando sea posible
std::atomic<size_t> counter_{0};
```

## 🔒 Código Kernel-Specific

### Kernel Development Rules
- **IRQL awareness**: Verificar IRQL antes de operations
- **Non-paged pool**: Usar NonPagedPool para estructuras accedidas en DISPATCH_LEVEL
- **Exception handling**: Usar __try/__except, no try/catch
- **Time limits**: No operations largas en DISPATCH_LEVEL

### Kernel Patterns
```c
// Siempre verificar parámetros
if (!Data || !FltObjects) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Memory allocation con tag
PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, size, CRYPTOSHIELD_TAG);
if (!buffer) {
    return STATUS_INSUFFICIENT_RESOURCES;
}

// Cleanup en todos los paths
__try {
    // Operation
} __finally {
    if (buffer) {
        ExFreePoolWithTag(buffer, CRYPTOSHIELD_TAG);
    }
}
```

## 🧪 Testing Standards

### Unit Testing Requirements
- **Coverage mínima**: 80% line coverage para componentes críticos
- **Mocking**: Mock todas las dependencias externas
- **Edge cases**: Testear boundary conditions y error paths
- **Performance tests**: Incluir benchmarks para hot paths

### Testing Patterns
```cpp
class ComponentTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup común
        component_ = std::make_unique<Component>();
        ASSERT_TRUE(component_->Initialize());
    }
    
    void TearDown() override {
        component_->Shutdown();
    }
    
    std::unique_ptr<Component> component_;
};

TEST_F(ComponentTest, HandlesMaliciousInput) {
    // Arrange
    std::vector<uint8_t> malicious_data = GenerateMaliciousData();
    
    // Act & Assert
    EXPECT_FALSE(component_->ProcessData(malicious_data));
    EXPECT_EQ(component_->GetLastError(), ERROR_INVALID_DATA);
}
```

## 🔍 Logging y Telemetría

### Logging Levels
- **ERROR**: Solo para errores que afectan funcionalidad
- **WARNING**: Para situaciones anómalas pero manejables
- **INFO**: Para eventos importantes del sistema
- **DEBUG**: Para desarrollo, removido en release builds

### Logging Patterns
```cpp
// Structured logging con contexto
void LogEvent(LogLevel level, const std::string& component, 
              const std::string& event, const std::string& details = "") {
    logger_.Log(level, "[{}] {}: {}", component, event, details);
}

// Performance logging para métricas
class ScopedTimer {
    auto start_ = std::chrono::high_resolution_clock::now();
    std::string operation_name_;
public:
    explicit ScopedTimer(const std::string& name) : operation_name_(name) {}
    ~ScopedTimer() {
        auto duration = std::chrono::high_resolution_clock::now() - start_;
        RecordPerformanceMetric(operation_name_, duration.count());
    }
};
```

## 🚀 Performance Guidelines

### Critical Performance Metrics
- **Detection latency**: < 100ms para análisis de archivos típicos
- **Memory usage**: < 2% system memory en operación normal
- **CPU usage**: < 5% en idle, < 20% durante scans
- **I/O impact**: < 10% overhead en operaciones de archivo

### Optimization Checklist
- [ ] Hot paths identificados y optimizados
- [ ] Memory pools implementados para allocaciones frecuentes
- [ ] Cache-friendly data structures
- [ ] Minimal locking en critical sections
- [ ] Lazy initialization donde sea apropiado
- [ ] Bulk operations preferidas sobre operaciones individuales

## 🔐 Security Guidelines

### Input Validation
```cpp
// Validar TODOS los inputs externos
bool ValidateInput(const InputData& data) {
    if (data.size > MAX_ALLOWED_SIZE) return false;
    if (data.buffer == nullptr) return false;
    if (!IsValidFormat(data)) return false;
    return true;
}

// Sanitizar strings antes de logging
std::string SanitizeForLog(const std::string& input) {
    // Remove control characters, limit length
    std::string sanitized = input.substr(0, MAX_LOG_LENGTH);
    std::replace_if(sanitized.begin(), sanitized.end(),
                   [](char c) { return std::iscntrl(c); }, '?');
    return sanitized;
}
```

### Cryptographic Standards
- **Hash functions**: SHA-256 mínimo, preferir SHA-3 para nuevo código
- **Symmetric encryption**: AES-256-GCM
- **Key derivation**: PBKDF2 con 100,000+ iterations
- **Random generation**: Usar CryptGenRandom o equivalent

## 📁 File Organization

### Project Structure Standards
```
Component/
├── Include/
│   └── ComponentName.h          # Public interface
├── Source/
│   ├── ComponentName.cpp        # Implementation
│   ├── ComponentNamePrivate.cpp # Private implementation details
│   └── ComponentNameUtils.cpp   # Utility functions
├── Tests/
│   ├── ComponentNameTest.cpp    # Unit tests
│   └── ComponentNameBench.cpp   # Performance tests
└── Documentation/
    └── ComponentName.md         # Component documentation
```

### Header File Standards
```cpp
#pragma once

// System includes primero
#include <windows.h>
#include <vector>

// Shared project includes
#include "../../Common/Shared.h"

// Forward declarations preferidas sobre includes
class ForwardDeclaredClass;

// Namespace para componentes internos
namespace CryptoShield::Internal {
    // Implementation details
}
```

## 🔄 Version Control

### Commit Standards
- **Formato**: `[Component] Type: Brief description`
- **Tipos**: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`
- **Ejemplo**: `[TelemetryCollector] feat: Add predictive analytics support`

### Branch Strategy
- **main**: Production-ready code only
- **develop**: Integration branch for features
- **feature/task-N-feature-name**: Individual feature development
- **hotfix/issue-description**: Critical production fixes

## 🎯 Quality Gates

### Code Review Checklist
- [ ] Security review completed
- [ ] Performance impact assessed
- [ ] Memory leaks verificados
- [ ] Error handling completo
- [ ] Tests escritos y pasando
- [ ] Documentation actualizada

### Pre-Commit Requirements
- [ ] Compilación sin warnings
- [ ] Static analysis clean (PVS-Studio/Clang-Tidy)
- [ ] Unit tests pasando
- [ ] Memory leak detection clean
- [ ] Code formatting consistent (clang-format)

## 📈 Metrics y Monitoring

### Key Performance Indicators
- **Code Quality**: Technical debt ratio < 5%
- **Test Coverage**: > 80% para componentes críticos
- **Bug Density**: < 1 bug per 1000 lines of code
- **Performance**: All operations within SLA targets

### Telemetry Requirements
- **Operations logging**: All major operations logged with timing
- **Error telemetry**: All errors captured with context
- **Performance metrics**: CPU, memory, I/O tracked continuously
- **User experience**: Response times y user satisfaction tracked

---

## 🚨 Principios No Negociables

1. **Security Over Performance**: Nunca sacrificar seguridad por velocidad
2. **Stability Over Features**: Sistema estable > funcionalidades extras  
3. **Clear Code Over Clever Code**: Código legible > código "inteligente"
4. **Test Coverage**: Código crítico debe tener tests
5. **Resource Cleanup**: Always cleanup, especialmente en kernel mode
6. **Error Handling**: Nunca ignorar errores, siempre handle gracefully
7. **Documentation**: Código complejo debe estar documentado
8. **Performance SLAs**: Cumplir targets de performance establecidos

Estas instrucciones deben seguirse consistentemente en todas las implementaciones de CryptoShield para garantizar un producto robusto, seguro y de alta calidad.