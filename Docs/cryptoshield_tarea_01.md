# Tarea 1: Minifilter Básico y Comunicación Kernel-User

## ?? Objetivos de la Tarea
Implementar un minifilter driver funcional que intercepte operaciones de archivo del sistema y establezca comunicación bidireccional con el servicio de usuario. 
En la raiz del repositorio encontrarás el documento de las guías de desarrollo (DEVELOPMENT_GUIDELINES.md) que hay que seguir en cada implementación.

## ?? Alcance
- **Duración estimada**: 1-2 semanas
- **Prioridad**: CRÍTICA (Fundación del proyecto)
- **Dependencias**: Ninguna
- **Entregables**: Driver funcional + Servicio de comunicación

## ??? Arquitectura de la Tarea

```
+--- KERNEL SPACE -------------------------------------+
¦  CryptoShield.sys                                    ¦
¦  +-- DriverEntry + FilterUnload                      ¦
¦  +-- Pre/Post Operation Callbacks                    ¦
¦  ¦   +-- IRP_MJ_CREATE                              ¦
¦  ¦   +-- IRP_MJ_WRITE                               ¦
¦  ¦   +-- IRP_MJ_SET_INFORMATION                     ¦
¦  ¦   +-- IRP_MJ_CLEANUP                             ¦
¦  +-- Communication Port                              ¦
¦  ¦   +-- Connect/Disconnect Callbacks               ¦
¦  ¦   +-- Message Handler                            ¦
¦  +-- Data Structures & Memory Management             ¦
+-----------------------------------------------------+
         ? (FilterMessage Communication)
+--- USER SPACE ---------------------------------------+
¦  CryptoShieldService.exe                             ¦
¦  +-- Driver Communication Manager                    ¦
¦  +-- Message Queue Handler                           ¦
¦  +-- Basic File Operation Logger                     ¦
¦  +-- Simple Response Mechanism                       ¦
+-----------------------------------------------------+
```

## ?? Estructura de Archivos

### Archivos del Driver
```
Driver/CryptoShield/
+-- CryptoShield.h          # Definiciones principales
+-- CryptoShield.c          # Entry point y callbacks principales
+-- FileMonitor.c           # Monitoreo de operaciones de archivo
+-- Communication.c         # Comunicación con user mode
+-- Utilities.c             # Funciones de utilidad
+-- CryptoShield.inf        # Archivo de instalación actualizado
+-- CryptoShield.vcxproj    # Proyecto actualizado
```

### Archivos del Servicio
```
Service/CryptoShieldService/
+-- CommunicationManager.h/cpp   # Gestión de comunicación con driver
+-- MessageProcessor.h/cpp       # Procesamiento de mensajes
+-- FileOperationLogger.h/cpp    # Logging básico de operaciones
+-- Main.cpp                     # Entry point actualizado
```

## ?? Componentes a Implementar

### 1. Kernel Driver (CryptoShield.sys)

#### 1.1 Estructura Principal (CryptoShield.h)
```c
// Contexto global del driver
typedef struct _CRYPTOSHIELD_CONTEXT {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    
    // Configuración
    BOOLEAN MonitoringEnabled;
    ULONG DetectionSensitivity;
    
    // Estadísticas
    ULONG FileOperationCount;
    ULONG MessagesSent;
    
    // Sincronización
    KSPIN_LOCK StatisticsLock;
    
} CRYPTOSHIELD_CONTEXT, *PCRYPTOSHIELD_CONTEXT;

// Mensaje de comunicación
typedef struct _FILTER_MESSAGE {
    FILTER_MESSAGE_HEADER Header;
    ULONG MessageType;
    ULONG ProcessId;
    ULONG ThreadId;
    LARGE_INTEGER Timestamp;
    WCHAR FilePath[260];
    ULONG FilePathLength;
    ULONG OperationType;
} FILTER_MESSAGE, *PFILTER_MESSAGE;

// Tipos de mensaje
#define MSG_FILE_OPERATION    1
#define MSG_STATUS_REQUEST    2
#define MSG_CONFIG_UPDATE     3
```

#### 1.2 Entry Point (CryptoShield.c)
```c
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS FilterUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

// Configuración del filtro
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_WRITE, 0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_SET_INFORMATION, 0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_CLEANUP, 0, PreOperationCallback, NULL },
    { IRP_MJ_OPERATION_END }
};
```

#### 1.3 Operation Callbacks (FileMonitor.c)
```c
FLT_PREOP_CALLBACK_STATUS PreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// Función para enviar notificación al user mode
NTSTATUS SendFileOperationNotification(
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING FilePath,
    _In_ ULONG OperationType
);
```

#### 1.4 Communication (Communication.c)
```c
// Callbacks de comunicación
NTSTATUS ConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
);

VOID DisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS MessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);
```

### 2. User Service (CryptoShieldService.exe)

#### 2.1 Communication Manager (CommunicationManager.h/cpp)
```cpp
class CommunicationManager {
private:
    HANDLE filter_port_;
    HANDLE completion_port_;
    std::thread message_thread_;
    std::atomic<bool> running_;
    
public:
    bool Initialize();
    void Shutdown();
    bool SendMessage(const FilterMessage& message);
    void ProcessMessages();
    
private:
    static DWORD WINAPI MessageThreadProc(LPVOID lpParam);
    void HandleFileOperationMessage(const FilterMessage& message);
    void HandleStatusRequest();
};
```

#### 2.2 Message Processor (MessageProcessor.h/cpp)
```cpp
struct FileOperationInfo {
    uint32_t process_id;
    std::wstring file_path;
    uint32_t operation_type;
    std::chrono::steady_clock::time_point timestamp;
};

class MessageProcessor {
private:
    std::queue<FileOperationInfo> operation_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::thread processing_thread_;
    
public:
    void EnqueueOperation(const FileOperationInfo& operation);
    void ProcessOperations();
    void StartProcessing();
    void StopProcessing();
};
```

## ?? Testing y Validación

### Test Cases Básicos
1. **Driver Loading/Unloading**: Verificar carga y descarga sin errores
2. **File Operation Interception**: Confirmar que se interceptan operaciones
3. **Communication Functionality**: Verificar comunicación bidireccional
4. **Memory Management**: Confirmar ausencia de memory leaks
5. **Performance Impact**: Medir overhead de rendimiento

### Test Framework
```cpp
class BasicTestFramework {
public:
    bool TestDriverCommunication();
    bool TestFileOperationCapture();
    bool TestMessageQueuing();
    bool TestPerformanceOverhead();
    void GenerateTestReport();
};
```

## ?? Métricas de Éxito

### Funcionales
- ? Driver se carga/descarga sin BSODs
- ? Intercepta operaciones de archivo correctamente
- ? Comunicación kernel-user funcional
- ? Gestiona memoria correctamente (sin leaks)

### Performance
- ? Overhead < 2% en operaciones de archivo
- ? Latencia < 100ms para comunicación
- ? Uso de memoria kernel < 10MB
- ? Sin impacto visible en UI del sistema

## ?? Plan de Implementación

### Semana 1: Kernel Driver
**Días 1-2**: Configuración y estructura básica
- Actualizar archivos .inf y .vcxproj
- Implementar DriverEntry y FilterUnload
- Configurar registro del minifilter

**Días 3-4**: Operation Callbacks
- Implementar Pre/Post operation callbacks
- Configurar intercepcción de IRPs críticos
- Implementar logging básico con DbgPrint

**Días 5-7**: Communication Port
- Crear puerto de comunicación
- Implementar callbacks de conexión/desconexión
- Implementar manejo básico de mensajes

### Semana 2: User Service
**Días 1-3**: Communication Manager
- Implementar conexión al driver
- Crear thread de procesamiento de mensajes
- Implementar queue de mensajes

**Días 4-5**: Message Processing
- Implementar procesador de mensajes
- Crear logging de operaciones de archivo
- Implementar respuestas básicas al driver

**Días 6-7**: Testing y Validación
- Crear test cases básicos
- Ejecutar pruebas de estabilidad
- Medir performance overhead
- Documentar resultados

## ?? Herramientas Necesarias

### Desarrollo
- Visual Studio 2022 con WDK
- Windows 10/11 SDK
- Virtual Machine para testing (VMware/VirtualBox)
- WinDbg para debugging de kernel

### Testing
- Driver Verifier
- Application Verifier
- DebugView para captura de logs
- Performance Toolkit

## ?? Consideraciones de Seguridad

### Driver Signing
- Configurar test signing durante desarrollo
- Obtener certificado de código para release
- Configurar cross-signing para compatibility

### Memory Safety
- Usar Pool tags para tracking
- Implementar proper cleanup en error paths
- Validar todos los parámetros de entrada

### Exception Handling
- Usar __try/__except en código crítico
- Implementar rollback en caso de errores
- Logging detallado para debugging

## ?? Checklist de Completitud

### Driver Implementation
- [ ] DriverEntry funcional
- [ ] FilterUnload funcional
- [ ] Pre/Post operation callbacks
- [ ] Communication port setup
- [ ] Message handling
- [ ] Memory management
- [ ] Error handling
- [ ] Logging system

### Service Implementation  
- [ ] Driver connection
- [ ] Message thread
- [ ] Message queue
- [ ] File operation logging
- [ ] Basic response system
- [ ] Configuration management
- [ ] Error handling
- [ ] Status reporting

### Testing
- [ ] Driver load/unload tests
- [ ] Communication tests
- [ ] File operation capture tests
- [ ] Performance tests
- [ ] Memory leak tests
- [ ] Stability tests
- [ ] Integration tests

### Documentation
- [ ] Code documentation
- [ ] Installation guide
- [ ] Testing procedures
- [ ] Troubleshooting guide

## ?? Entregables de la Tarea

1. **CryptoShield.sys** - Driver funcional que se carga sin errores
2. **CryptoShieldService.exe** - Servicio que se comunica con el driver
3. **Test Suite** - Conjunto de tests básicos
4. **Installation Package** - Scripts de instalación/desinstalación
5. **Documentation** - Guías de uso y troubleshooting

Una vez completada esta tarea, tendremos la fundación sólida para agregar las capacidades de detección y respuesta en las siguientes tareas.