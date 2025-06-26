# Tarea 7: Management Console y APIs REST

## 🎯 Objetivos de la Tarea
Desarrollar una interfaz de gestión completa que incluya APIs REST para integración empresarial, dashboard web para monitoreo, SIEM integration, y herramientas de configuración y reporting.

## 📋 Alcance
- **Duración estimada**: 2-3 semanas
- **Prioridad**: ALTA (Usabilidad y gestión empresarial)
- **Dependencias**: Todas las tareas anteriores (1-6)
- **Entregables**: APIs REST + Web Dashboard + SIEM Integration + Management Tools

## 🏗️ Arquitectura de la Tarea

```
┌─── MANAGEMENT & API LAYER ───────────────────────────────┐
│                                                          │
│  ┌─── RESTful API Gateway ──────────────────────────────┐ │
│  │  ├── Authentication & Authorization                  │ │
│  │  ├── Rate Limiting & Throttling                      │ │
│  │  ├── API Versioning & Documentation                  │ │
│  │  ├── Request/Response Validation                     │ │
│  │  └── Logging & Audit Trail                          │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌─── Core API Endpoints ───────────────────────────────┐ │
│  │  ├── System Status & Health                          │ │
│  │  ├── Threat Management                               │ │
│  │  ├── Configuration Management                        │ │
│  │  ├── Quarantine Management                           │ │
│  │  ├── User & Role Management                          │ │
│  │  ├── Reporting & Analytics                           │ │
│  │  └── Integration Webhooks                            │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌─── Web Management Dashboard ─────────────────────────┐ │
│  │  ├── Real-time Monitoring                           │ │
│  │  ├── Threat Visualization                            │ │
│  │  ├── Configuration Interface                         │ │
│  │  ├── User Management                                 │ │
│  │  ├── Reports & Analytics                             │ │
│  │  └── System Administration                           │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌─── Enterprise Integration ───────────────────────────┐ │
│  │  ├── SIEM Integration (Splunk, QRadar, etc.)        │ │
│  │  ├── Active Directory Integration                    │ │
│  │  ├── LDAP Authentication                             │ │
│  │  ├── SMTP Email Notifications                        │ │
│  │  ├── SNMP Monitoring Integration                     │ │
│  │  └── Third-party API Connectors                     │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

## 📂 Estructura de Archivos

### Archivos de API REST
```
Service/CryptoShieldService/Management/
├── RestApiServer.h/cpp             # Servidor API REST principal
├── ApiGateway.h/cpp                # Gateway con auth y rate limiting
├── ApiEndpoints.h/cpp              # Definición de endpoints
├── ApiValidation.h/cpp             # Validación de requests/responses
├── ApiDocumentation.h/cpp          # Documentación automática
└── ApiAuditLog.h/cpp               # Logging y auditoría
```

### Archivos de Endpoints Específicos
```
Service/CryptoShieldService/Management/Endpoints/
├── SystemStatusEndpoints.h/cpp     # Status y health endpoints
├── ThreatEndpoints.h/cpp           # Gestión de amenazas
├── QuarantineEndpoints.h/cpp       # Gestión de cuarentena
├── ConfigurationEndpoints.h/cpp    # Configuración del sistema
├── UserManagementEndpoints.h/cpp   # Gestión de usuarios
├── ReportingEndpoints.h/cpp        # Reportes y analytics
└── WebhookEndpoints.h/cpp          # Webhooks para integración
```

### Archivos de Dashboard Web
```
Service/CryptoShieldService/WebDashboard/
├── WebServer.h/cpp                 # Servidor web integrado
├── DashboardController.h/cpp       # Controlador principal
├── RealtimeMonitoring.h/cpp        # Monitoreo en tiempo real
├── ThreatVisualization.h/cpp       # Visualización de amenazas
├── ConfigurationUI.h/cpp           # Interfaz de configuración
└── UserInterface.h/cpp             # Gestión de usuarios web
```

### Archivos de Integración Empresarial
```
Service/CryptoShieldService/Integration/
├── SIEMIntegration.h/cpp           # Integración con SIEM
├── ActiveDirectoryAuth.h/cpp       # Autenticación AD
├── LDAPAuthentication.h/cpp        # Autenticación LDAP
├── EmailNotifications.h/cpp        # Notificaciones por email
├── SNMPIntegration.h/cpp           # Integración SNMP
└── ThirdPartyConnectors.h/cpp      # Conectores API externos
```

### Archivos de Testing
```
Test/ManagementAPI/
├── ApiEndpointTests.cpp            # Tests de endpoints API
├── AuthenticationTests.cpp         # Tests de autenticación
├── PerformanceTests.cpp            # Tests de rendimiento API
├── IntegrationTests.cpp            # Tests de integración
└── SecurityTests.cpp               # Tests de seguridad API
```

## 🔧 Componentes a Implementar

### 1. RESTful API System

#### 1.1 REST API Server (RestApiServer.h/cpp)
```cpp
class RestApiServer {
private:
    // HTTP server components
    std::unique_ptr<HttpServer> http_server_;
    std::unique_ptr<ApiGateway> api_gateway_;
    std::unique_ptr<ApiEndpoints> api_endpoints_;
    
    // Configuration
    RestApiConfig config_;
    
    // Security
    std::unique_ptr<AuthenticationManager> auth_manager_;
    std::unique_ptr<AuthorizationManager> authz_manager_;
    
    // Performance
    std::unique_ptr<RateLimiter> rate_limiter_;
    std::unique_ptr<RequestValidator> validator_;
    
    // Monitoring
    struct ApiMetrics {
        std::atomic<uint64_t> total_requests{0};
        std::atomic<uint64_t> successful_requests{0};
        std::atomic<uint64_t> failed_requests{0};
        std::atomic<uint64_t> authentication_failures{0};
        std::atomic<double> average_response_time_ms{0.0};
        std::chrono::steady_clock::time_point start_time;
    } metrics_;
    
public:
    struct RestApiConfig {
        std::string bind_address = "127.0.0.1";
        uint16_t port = 8443;
        bool enable_https = true;
        std::string ssl_cert_path;
        std::string ssl_key_path;
        
        // Authentication
        bool require_authentication = true;
        std::string auth_method = "JWT"; // JWT, API_KEY, LDAP
        std::chrono::hours token_expiry{24};
        
        // Rate limiting
        bool enable_rate_limiting = true;
        size_t requests_per_minute = 1000;
        size_t burst_limit = 100;
        
        // CORS
        bool enable_cors = true;
        std::vector<std::string> allowed_origins;
        std::vector<std::string> allowed_methods;
        
        // API versioning
        std::string current_version = "v1";
        std::vector<std::string> supported_versions;
    };
    
    struct ApiResponse {
        int status_code;
        std::string content_type;
        std::string body;
        std::map<std::string, std::string> headers;
        std::chrono::milliseconds processing_time;
    };
    
    struct ApiRequest {
        std::string method;
        std::string path;
        std::string query_string;
        std::map<std::string, std::string> headers;
        std::string body;
        std::string client_ip;
        std::chrono::steady_clock::time_point timestamp;
        std::string user_id;
        std::vector<std::string> user_roles;
    };
    
    RestApiServer();
    ~RestApiServer();
    
    // Lifecycle
    HRESULT Initialize(const RestApiConfig& config);
    HRESULT Start();
    HRESULT Stop();
    void Shutdown();
    
    // Endpoint registration
    void RegisterEndpoint(const std::string& method,
                         const std::string& path,
                         std::function<ApiResponse(const ApiRequest&)> handler,
                         const std::vector<std::string>& required_roles = {});
    
    void RegisterMiddleware(std::function<bool(ApiRequest&)> middleware);
    
    // Built-in endpoints
    void RegisterSystemEndpoints();
    void RegisterThreatEndpoints();
    void RegisterQuarantineEndpoints();
    void RegisterConfigurationEndpoints();
    void RegisterUserManagementEndpoints();
    void RegisterReportingEndpoints();
    void RegisterWebhookEndpoints();
    
    // Configuration
    void UpdateConfiguration(const RestApiConfig& new_config);
    RestApiConfig GetCurrentConfiguration() const;
    
    // Monitoring
    ApiMetrics GetApiMetrics() const;
    std::vector<std::string> GetActiveConnections() const;
    void ResetMetrics();
    
    // Security
    HRESULT GenerateApiKey(const std::string& user_id, 
                          const std::vector<std::string>& roles,
                          std::chrono::hours expiry = std::chrono::hours{24});
    
    bool RevokeApiKey(const std::string& api_key);
    std::vector<std::string> GetActiveApiKeys() const;
    
private:
    // Request processing
    ApiResponse ProcessRequest(const ApiRequest& request);
    bool AuthenticateRequest(const ApiRequest& request);
    bool AuthorizeRequest(const ApiRequest& request, const std::vector<std::string>& required_roles);
    bool ValidateRequest(const ApiRequest& request);
    
    // Middleware chain
    bool ProcessMiddleware(ApiRequest& request);
    void LogRequest(const ApiRequest& request, const ApiResponse& response);
    
    // Error handling
    ApiResponse CreateErrorResponse(int status_code, const std::string& error_message);
    ApiResponse CreateSuccessResponse(const std::string& data, const std::string& content_type = "application/json");
    
    void LogApiEvent(const std::string& event, const ApiRequest& request);
};
```

#### 1.2 API Endpoints Implementation (ApiEndpoints.h/cpp)
```cpp
class ApiEndpoints {
private:
    // Service references
    CryptoShieldService* service_;
    RestApiServer* api_server_;
    
public:
    ApiEndpoints(CryptoShieldService* service, RestApiServer* api_server);
    ~ApiEndpoints();
    
    // System Status Endpoints
    RestApiServer::ApiResponse GetSystemStatus(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetSystemHealth(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetSystemInfo(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetPerformanceMetrics(const RestApiServer::ApiRequest& request);
    
    // Threat Management Endpoints
    RestApiServer::ApiResponse GetActiveThreats(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetThreatDetails(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetThreatHistory(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse UpdateThreatStatus(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse DeleteThreat(const RestApiServer::ApiRequest& request);
    
    // Quarantine Management Endpoints
    RestApiServer::ApiResponse GetQuarantinedFiles(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse QuarantineFile(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse RestoreQuarantinedFile(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse DeleteQuarantinedFile(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetQuarantineStatistics(const RestApiServer::ApiRequest& request);
    
    // Configuration Management Endpoints
    RestApiServer::ApiResponse GetConfiguration(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse UpdateConfiguration(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetConfigurationSchema(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse ValidateConfiguration(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse ResetConfiguration(const RestApiServer::ApiRequest& request);
    
    // User Management Endpoints (Admin only)
    RestApiServer::ApiResponse GetUsers(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse CreateUser(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse UpdateUser(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse DeleteUser(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetUserRoles(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse UpdateUserRoles(const RestApiServer::ApiRequest& request);
    
    // Reporting Endpoints
    RestApiServer::ApiResponse GenerateReport(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetAvailableReports(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetReportStatus(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse DownloadReport(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse ScheduleReport(const RestApiServer::ApiRequest& request);
    
    // Analytics Endpoints
    RestApiServer::ApiResponse GetThreatStatistics(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetDetectionTrends(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetPerformanceAnalytics(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetNetworkAnalytics(const RestApiServer::ApiRequest& request);
    
    // Webhook Management Endpoints
    RestApiServer::ApiResponse RegisterWebhook(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse UpdateWebhook(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse DeleteWebhook(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetWebhooks(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse TestWebhook(const RestApiServer::ApiRequest& request);
    
    // Whitelist/Blacklist Management
    RestApiServer::ApiResponse GetWhitelist(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse AddToWhitelist(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse RemoveFromWhitelist(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse GetBlacklist(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse AddToBlacklist(const RestApiServer::ApiRequest& request);
    RestApiServer::ApiResponse RemoveFromBlacklist(const RestApiServer::ApiRequest& request);
    
private:
    // Helper methods
    std::string SerializeToJson(const nlohmann::json& data);
    nlohmann::json DeserializeFromJson(const std::string& json_str);
    
    bool ValidateJsonSchema(const nlohmann::json& data, const std::string& schema);
    std::string ExtractPathParameter(const std::string& path, const std::string& param_name);
    std::map<std::string, std::string> ParseQueryParameters(const std::string& query_string);
    
    // Data transformation
    nlohmann::json ThreatToJson(const DetectionResult& threat);
    nlohmann::json QuarantineEntryToJson(const FileQuarantine::QuarantineEntry& entry);
    nlohmann::json SystemStatusToJson();
    nlohmann::json PerformanceMetricsToJson();
    
    void LogEndpointAccess(const std::string& endpoint, const std::string& user_id);
};
```

### 2. Web Management Dashboard

#### 2.1 Web Dashboard Controller (DashboardController.h/cpp)
```cpp
class DashboardController {
private:
    // Web server
    std::unique_ptr<HttpServer> web_server_;
    
    // Real-time data providers
    std::unique_ptr<RealtimeMonitoring> realtime_monitor_;
    std::unique_ptr<ThreatVisualization> threat_visualizer_;
    
    // Template engine
    std::unique_ptr<TemplateEngine> template_engine_;
    
    // WebSocket connections for real-time updates
    std::set<WebSocketConnection*> websocket_connections_;
    std::mutex websocket_mutex_;
    
    // Configuration
    WebDashboardConfig config_;
    
public:
    struct WebDashboardConfig {
        std::string bind_address = "127.0.0.1";
        uint16_t port = 8080;
        bool enable_https = true;
        std::string ssl_cert_path;
        std::string ssl_key_path;
        
        // Authentication
        bool require_authentication = true;
        std::string session_secret;
        std::chrono::hours session_timeout{8};
        
        // Features
        bool enable_realtime_monitoring = true;
        bool enable_threat_visualization = true;
        bool enable_configuration_ui = true;
        bool enable_user_management = true;
        
        // Security
        bool enable_csrf_protection = true;
        bool enable_xss_protection = true;
        std::vector<std::string> allowed_hosts;
    };
    
    DashboardController(CryptoShieldService* service);
    ~DashboardController();
    
    // Lifecycle
    HRESULT Initialize(const WebDashboardConfig& config);
    HRESULT Start();
    HRESULT Stop();
    void Shutdown();
    
    // Page handlers
    HttpResponse HandleDashboardHome(const HttpRequest& request);
    HttpResponse HandleThreatMonitoring(const HttpRequest& request);
    HttpResponse HandleSystemStatus(const HttpRequest& request);
    HttpResponse HandleConfiguration(const HttpRequest& request);
    HttpResponse HandleQuarantineManagement(const HttpRequest& request);
    HttpResponse HandleUserManagement(const HttpRequest& request);
    HttpResponse HandleReports(const HttpRequest& request);
    HttpResponse HandleAnalytics(const HttpRequest& request);
    
    // API handlers for AJAX requests
    HttpResponse HandleAjaxSystemStatus(const HttpRequest& request);
    HttpResponse HandleAjaxThreatList(const HttpRequest& request);
    HttpResponse HandleAjaxQuarantineList(const HttpRequest& request);
    HttpResponse HandleAjaxConfiguration(const HttpRequest& request);
    
    // WebSocket handlers for real-time updates
    void HandleWebSocketConnection(WebSocketConnection* connection);
    void HandleWebSocketMessage(WebSocketConnection* connection, const std::string& message);
    void HandleWebSocketDisconnection(WebSocketConnection* connection);
    
    // Real-time data broadcasting
    void BroadcastThreatAlert(const DetectionResult& threat);
    void BroadcastSystemStatus(const SystemStatus& status);
    void BroadcastQuarantineUpdate(const std::string& update_type, const std::string& file_path);
    
private:
    // Template rendering
    std::string RenderTemplate(const std::string& template_name, 
                              const std::map<std::string, std::string>& variables);
    
    // Authentication and session management
    bool AuthenticateUser(const HttpRequest& request);
    std::string CreateSession(const std::string& user_id);
    bool ValidateSession(const std::string& session_id);
    void InvalidateSession(const std::string& session_id);
    
    // Security middleware
    HttpResponse ApplySecurityHeaders(HttpResponse response);
    bool ValidateCSRFToken(const HttpRequest& request);
    std::string GenerateCSRFToken();
    
    // Data serialization for web
    std::string SerializeForWeb(const nlohmann::json& data);
    nlohmann::json GetDashboardData();
    nlohmann::json GetThreatSummary();
    nlohmann::json GetSystemMetrics();
    
    void LogWebAccess(const HttpRequest& request, const HttpResponse& response);
};
```

#### 2.2 Real-time Monitoring (RealtimeMonitoring.h/cpp)
```cpp
class RealtimeMonitoring {
private:
    // Data streams
    struct MonitoringStream {
        std::string stream_id;
        std::string stream_type;
        std::chrono::seconds update_interval;
        std::function<nlohmann::json()> data_provider;
        std::chrono::steady_clock::time_point last_update;
        bool is_active;
    };
    
    std::map<std::string, MonitoringStream> monitoring_streams_;
    std::mutex streams_mutex_;
    
    // Subscribers
    struct StreamSubscriber {
        std::string subscriber_id;
        std::set<std::string> subscribed_streams;
        std::function<void(const std::string&, const nlohmann::json&)> callback;
        std::chrono::steady_clock::time_point last_activity;
    };
    
    std::map<std::string, StreamSubscriber> subscribers_;
    std::mutex subscribers_mutex_;
    
    // Update thread
    std::thread update_thread_;
    std::atomic<bool> monitoring_active_;
    
    // Service reference
    CryptoShieldService* service_;
    
public:
    RealtimeMonitoring(CryptoShieldService* service);
    ~RealtimeMonitoring();
    
    // Lifecycle
    HRESULT Initialize();
    void Start();
    void Stop();
    void Shutdown();
    
    // Stream management
    void RegisterStream(const std::string& stream_id,
                       const std::string& stream_type,
                       std::chrono::seconds update_interval,
                       std::function<nlohmann::json()> data_provider);
    
    void UnregisterStream(const std::string& stream_id);
    std::vector<std::string> GetAvailableStreams() const;
    
    // Subscription management
    std::string Subscribe(const std::vector<std::string>& stream_ids,
                         std::function<void(const std::string&, const nlohmann::json&)> callback);
    
    void Unsubscribe(const std::string& subscriber_id);
    void UpdateSubscription(const std::string& subscriber_id, 
                           const std::vector<std::string>& stream_ids);
    
    // Manual data push
    void PushStreamUpdate(const std::string& stream_id, const nlohmann::json& data);
    void BroadcastAlert(const std::string& alert_type, const nlohmann::json& alert_data);
    
    // Built-in monitoring streams
    void RegisterBuiltInStreams();
    
private:
    // Update loop
    void MonitoringUpdateLoop();
    void UpdateStream(MonitoringStream& stream);
    void NotifySubscribers(const std::string& stream_id, const nlohmann::json& data);
    
    // Built-in data providers
    nlohmann::json GetSystemStatusData();
    nlohmann::json GetThreatActivityData();
    nlohmann::json GetPerformanceMetricsData();
    nlohmann::json GetNetworkStatusData();
    nlohmann::json GetQuarantineStatusData();
    
    // Cleanup
    void CleanupInactiveSubscribers();
    
    void LogMonitoringEvent(const std::string& event);
};
```

### 3. Enterprise Integration

#### 3.1 SIEM Integration (SIEMIntegration.h/cpp)
```cpp
class SIEMIntegration {
private:
    // SIEM connectors
    std::unique_ptr<SplunkConnector> splunk_connector_;
    std::unique_ptr<QRadarConnector> qradar_connector_;
    std::unique_ptr<ArcSightConnector> arcsight_connector_;
    std::unique_ptr<SentinelConnector> sentinel_connector_;
    std::unique_ptr<GenericSyslogConnector> syslog_connector_;
    
    // Configuration
    SIEMIntegrationConfig config_;
    
    // Event queue
    std::queue<SIEMEvent> event_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    // Processing thread
    std::thread processing_thread_;
    std::atomic<bool> processing_active_;
    
public:
    enum SIEMType {
        SPLUNK,
        IBM_QRADAR,
        MICRO_FOCUS_ARCSIGHT,
        MICROSOFT_SENTINEL,
        GENERIC_SYSLOG,
        CUSTOM_API
    };
    
    struct SIEMEvent {
        std::string event_id;
        std::string event_type;
        std::chrono::steady_clock::time_point timestamp;
        std::string severity;
        std::string source_ip;
        std::string destination_ip;
        std::string user_context;
        std::string process_name;
        std::string file_path;
        std::string threat_type;
        double confidence_score;
        std::map<std::string, std::string> custom_fields;
        
        // CEF (Common Event Format) fields
        std::string cef_version;
        std::string device_vendor;
        std::string device_product;
        std::string device_version;
        std::string signature_id;
        std::string name;
        std::string severity_label;
    };
    
    struct SIEMConnectorConfig {
        SIEMType type;
        std::string endpoint_url;
        std::string username;
        std::string password;
        std::string api_key;
        std::string certificate_path;
        
        // Connection settings
        std::chrono::seconds connection_timeout{30};
        size_t max_retries{3};
        std::chrono::seconds retry_delay{5};
        
        // Event formatting
        std::string event_format; // CEF, LEEF, JSON, XML
        std::map<std::string, std::string> field_mappings;
        
        // Filtering
        std::vector<std::string> event_types_to_send;
        double minimum_confidence_threshold{0.5};
    };
    
    SIEMIntegration();
    ~SIEMIntegration();
    
    // Lifecycle
    HRESULT Initialize(const SIEMIntegrationConfig& config);
    void Shutdown();
    
    // SIEM connector management
    HRESULT AddSIEMConnector(const SIEMConnectorConfig& connector_config);
    HRESULT RemoveSIEMConnector(SIEMType type);
    std::vector<SIEMType> GetActiveSIEMConnectors() const;
    
    // Event submission
    void SendThreatEvent(const DetectionResult& detection);
    void SendQuarantineEvent(const std::string& action, const std::string& file_path);
    void SendSystemEvent(const std::string& event_type, const std::string& description);
    void SendCustomEvent(const SIEMEvent& event);
    
    // Batch operations
    void SendEventBatch(const std::vector<SIEMEvent>& events);
    void FlushEventQueue();
    
    // Health monitoring
    struct SIEMHealth {
        SIEMType siem_type;
        bool is_connected;
        std::chrono::steady_clock::time_point last_successful_send;
        size_t events_sent_today;
        size_t failed_sends_today;
        double success_rate;
        std::chrono::milliseconds average_send_time;
    };
    
    std::vector<SIEMHealth> GetSIEMHealthStatus() const;
    
    // Testing and validation
    HRESULT TestSIEMConnection(SIEMType type);
    HRESULT SendTestEvent(SIEMType type);
    
private:
    // Event processing
    void EventProcessingLoop();
    void ProcessEvent(const SIEMEvent& event);
    
    // Event formatting
    std::string FormatEventAsCEF(const SIEMEvent& event);
    std::string FormatEventAsLEEF(const SIEMEvent& event);
    std::string FormatEventAsJSON(const SIEMEvent& event);
    std::string FormatEventAsXML(const SIEMEvent& event);
    
    // Event transformation
    SIEMEvent TransformDetectionToSIEMEvent(const DetectionResult& detection);
    void EnrichEventWithContext(SIEMEvent& event);
    bool ShouldSendEvent(const SIEMEvent& event, const SIEMConnectorConfig& config);
    
    void LogSIEMEvent(const std::string& event, SIEMType siem_type);
};
```

#### 3.2 Email Notifications (EmailNotifications.h/cpp)
```cpp
class EmailNotifications {
private:
    // SMTP configuration
    struct SMTPConfig {
        std::string smtp_server;
        uint16_t smtp_port{587};
        bool use_tls{true};
        bool use_ssl{false};
        std::string username;
        std::string password;
        std::string from_address;
        std::string from_name;
        
        // Connection settings
        std::chrono::seconds connection_timeout{30};
        size_t max_retries{3};
        std::chrono::seconds retry_delay{5};
    };
    
    SMTPConfig smtp_config_;
    
    // Email templates
    std::map<std::string, EmailTemplate> email_templates_;
    
    // Notification settings
    struct NotificationSettings {
        std::vector<std::string> admin_emails;
        std::vector<std::string> user_emails;
        std::vector<std::string> security_team_emails;
        
        // Notification triggers
        bool notify_on_threat_detection{true};
        bool notify_on_high_threats_only{false};
        bool notify_on_quarantine_action{true};
        bool notify_on_system_errors{true};
        bool notify_on_service_status_change{true};
        
        // Rate limiting
        std::chrono::minutes min_notification_interval{5};
        size_t max_notifications_per_hour{20};
    };
    
    NotificationSettings notification_settings_;
    
    // Email queue
    std::queue<EmailMessage> email_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    // Processing thread
    std::thread email_thread_;
    std::atomic<bool> email_processing_active_;
    
    // Rate limiting
    std::map<std::string, std::chrono::steady_clock::time_point> last_notification_times_;
    std::map<std::string, size_t> hourly_notification_counts_;
    
public:
    struct EmailTemplate {
        std::string template_id;
        std::string subject_template;
        std::string html_body_template;
        std::string text_body_template;
        std::vector<std::string> required_variables;
        std::string template_description;
    };
    
    struct EmailMessage {
        std::string message_id;
        std::vector<std::string> to_addresses;
        std::vector<std::string> cc_addresses;
        std::vector<std::string> bcc_addresses;
        std::string subject;
        std::string html_body;
        std::string text_body;
        std::string priority; // high, normal, low
        std::chrono::steady_clock::time_point created_time;
        size_t retry_count{0};
        bool is_sent{false};
    };
    
    EmailNotifications();
    ~EmailNotifications();
    
    // Lifecycle
    HRESULT Initialize(const SMTPConfig& smtp_config, 
                      const NotificationSettings& notification_settings);
    void Shutdown();
    
    // Template management
    void RegisterEmailTemplate(const EmailTemplate& email_template);
    void UpdateEmailTemplate(const EmailTemplate& email_template);
    void RemoveEmailTemplate(const std::string& template_id);
    std::vector<EmailTemplate> GetEmailTemplates() const;
    
    // Threat notifications
    void SendThreatAlert(const DetectionResult& detection);
    void SendThreatSummary(const std::vector<DetectionResult>& threats,
                          std::chrono::hours time_period);
    
    // System notifications
    void SendSystemAlert(const std::string& alert_type, const std::string& message);
    void SendServiceStatusNotification(const std::string& status, const std::string& details);
    void SendQuarantineNotification(const std::string& action, 
                                   const std::vector<std::string>& files);
    
    // Custom notifications
    void SendCustomNotification(const std::string& template_id,
                               const std::vector<std::string>& recipients,
                               const std::map<std::string, std::string>& variables);
    
    // Immediate sending
    HRESULT SendEmailImmediate(const EmailMessage& message);
    
    // Configuration
    void UpdateSMTPConfig(const SMTPConfig& new_config);
    void UpdateNotificationSettings(const NotificationSettings& new_settings);
    
    // Testing
    HRESULT TestEmailConfiguration();
    HRESULT SendTestEmail(const std::string& recipient);
    
    // Statistics
    struct EmailStatistics {
        size_t total_emails_sent;
        size_t total_emails_failed;
        size_t emails_in_queue;
        double success_rate;
        std::chrono::steady_clock::time_point last_successful_send;
        std::chrono::milliseconds average_send_time;
    };
    
    EmailStatistics GetEmailStatistics() const;
    
private:
    // Email processing
    void EmailProcessingLoop();
    bool SendEmail(const EmailMessage& message);
    
    // Template processing
    std::string ProcessTemplate(const std::string& template_str,
                               const std::map<std::string, std::string>& variables);
    
    EmailMessage CreateThreatAlertEmail(const DetectionResult& detection);
    EmailMessage CreateSystemAlertEmail(const std::string& alert_type, 
                                       const std::string& message);
    
    // Rate limiting
    bool ShouldSendNotification(const std::string& notification_type);
    void UpdateNotificationRateLimit(const std::string& notification_type);
    void ResetHourlyCounters();
    
    // SMTP operations
    bool ConnectToSMTPServer();
    bool AuthenticateWithSMTP();
    bool SendSMTPMessage(const EmailMessage& message);
    void DisconnectFromSMTPServer();
    
    void LogEmailEvent(const std::string& event);
};
```

## 📊 Métricas de Éxito

### API Performance
- **API Response Time**: < 500ms para 95% de requests
- **API Throughput**: > 1000 requests/second
- **API Availability**: > 99.9% uptime
- **Authentication Success**: < 100ms para token validation

### Dashboard Usability
- **Page Load Time**: < 3 segundos para dashboard principal
- **Real-time Update Latency**: < 2 segundos para datos críticos
- **WebSocket Connection Stability**: > 99% uptime
- **Mobile Responsiveness**: Funcional en dispositivos móviles

### Enterprise Integration
- **SIEM Integration Success**: > 95% de events enviados exitosamente
- **Email Delivery Rate**: > 98% de emails entregados
- **LDAP Authentication**: < 2 segundos para autenticación
- **API Integration Compatibility**: Compatible con 90% de herramientas empresariales

## 🚀 Plan de Implementación

### Semana 1: REST API Foundation

**Días 1-2**: Core API Infrastructure
- Implementar RestApiServer con HTTP/HTTPS support
- Desarrollar ApiGateway con authentication y rate limiting
- Crear request/response validation system
- Implementar API versioning y documentation

**Días 3-4**: Core API Endpoints
- Implementar system status endpoints
- Desarrollar threat management endpoints
- Crear quarantine management endpoints
- Implementar configuration endpoints

**Días 5-7**: Advanced API Features
- Desarrollar user management endpoints
- Implementar reporting y analytics endpoints
- Crear webhook management system
- Implementar comprehensive API testing

### Semana 2: Web Dashboard

**Días 1-2**: Web Server Foundation
- Implementar integrated web server
- Desarrollar template engine
- Crear authentication y session management
- Implementar security middleware (CSRF, XSS protection)

**Días 3-4**: Dashboard Pages
- Crear dashboard home page
- Implementar real-time monitoring interface
- Desarrollar threat visualization components
- Crear configuration management UI

**Días 5-7**: Real-time Features
- Implementar WebSocket connections
- Desarrollar real-time data streaming
- Crear push notifications para web
- Implementar interactive charts y visualizations

### Semana 3: Enterprise Integration

**Días 1-2**: SIEM Integration
- Implementar Splunk connector
- Desarrollar QRadar integration
- Crear generic syslog connector
- Implementar event formatting (CEF, LEEF, JSON)

**Días 3-4**: Authentication Integration
- Implementar Active Directory integration
- Desarrollar LDAP authentication
- Crear SSO support
- Implementar role-based access control

**Días 5-7**: Notification Systems
- Implementar email notification system
- Desarrollar SMTP integration
- Crear notification templates
- Implementar rate limiting y batching

## 🔧 Configuración

### Management API Configuration (management_config.json)
```json
{
  "rest_api": {
    "enabled": true,
    "bind_address": "0.0.0.0",
    "port": 8443,
    "enable_https": true,
    "ssl_cert_path": "/etc/cryptoshield/ssl/cert.pem",
    "ssl_key_path": "/etc/cryptoshield/ssl/key.pem",
    "require_authentication": true,
    "auth_method": "JWT",
    "token_expiry_hours": 24,
    "enable_rate_limiting": true,
    "requests_per_minute": 1000,
    "enable_cors": true,
    "allowed_origins": ["https://admin.company.com"],
    "api_version": "v1"
  },
  "web_dashboard": {
    "enabled": true,
    "bind_address": "0.0.0.0", 
    "port": 8080,
    "enable_https": true,
    "ssl_cert_path": "/etc/cryptoshield/ssl/cert.pem",
    "ssl_key_path": "/etc/cryptoshield/ssl/key.pem",
    "session_timeout_hours": 8,
    "enable_realtime_monitoring": true,
    "enable_csrf_protection": true,
    "enable_xss_protection": true
  },
  "siem_integration": {
    "enabled": true,
    "connectors": [
      {
        "type": "SPLUNK",
        "endpoint_url": "https://splunk.company.com:8088/services/collector",
        "api_key": "${SPLUNK_API_KEY}",
        "event_format": "JSON",
        "minimum_confidence_threshold": 0.7
      },
      {
        "type": "GENERIC_SYSLOG", 
        "endpoint_url": "syslog.company.com:514",
        "event_format": "CEF",
        "minimum_confidence_threshold": 0.5
      }
    ]
  },
  "email_notifications": {
    "enabled": true,
    "smtp_server": "smtp.company.com",
    "smtp_port": 587,
    "use_tls": true,
    "username": "cryptoshield@company.com",
    "password": "${EMAIL_PASSWORD}",
    "from_address": "cryptoshield@company.com",
    "from_name": "CryptoShield Security",
    "admin_emails": ["admin@company.com", "security@company.com"],
    "notify_on_threat_detection": true,
    "notify_on_high_threats_only": false,
    "max_notifications_per_hour": 20
  },
  "ldap_authentication": {
    "enabled": false,
    "ldap_server": "ldap.company.com",
    "ldap_port": 389,
    "use_ssl": false,
    "bind_dn": "CN=cryptoshield,OU=Service Accounts,DC=company,DC=com",
    "bind_password": "${LDAP_PASSWORD}",
    "search_base": "OU=Users,DC=company,DC=com",
    "user_filter": "(sAMAccountName={username})",
    "group_filter": "(member={user_dn})"
  }
}
```

## 📋 Checklist de Completitud

### REST API System
- [ ] RestApiServer implementado
- [ ] ApiGateway con auth implementado
- [ ] Rate limiting implementado
- [ ] API versioning implementado
- [ ] Request/response validation implementado
- [ ] API documentation auto-generada
- [ ] Todos los endpoints core implementados
- [ ] Webhook system implementado

### Web Dashboard
- [ ] Web server integrado implementado
- [ ] Dashboard UI implementado
- [ ] Real-time monitoring implementado
- [ ] WebSocket connections implementadas
- [ ] Template engine implementado
- [ ] Security middleware implementado
- [ ] Session management implementado
- [ ] Mobile responsive design

### Enterprise Integration
- [ ] SIEM integration implementada
- [ ] Splunk connector implementado
- [ ] Generic syslog connector implementado
- [ ] LDAP authentication implementada
- [ ] Active Directory integration implementada
- [ ] Email notifications implementadas
- [ ] SMTP integration implementada
- [ ] Notification templates implementadas

### Testing & Quality
- [ ] API endpoint tests implementados
- [ ] Authentication tests implementados
- [ ] Performance tests implementados
- [ ] Security tests implementados
- [ ] Integration tests implementados
- [ ] Load testing completado

## 🎯 Entregables de la Tarea

1. **REST API System** - Sistema completo de APIs REST
2. **Web Management Dashboard** - Dashboard web con monitoreo en tiempo real
3. **SIEM Integration Framework** - Integración con sistemas SIEM populares
4. **Enterprise Authentication** - Integración con LDAP/Active Directory
5. **Email Notification System** - Sistema completo de notificaciones
6. **API Documentation** - Documentación automática de APIs
7. **Management Tools** - Herramientas de configuración y administración
8. **Integration Testing Suite** - Tests de integración empresarial
9. **Configuration Management** - Sistema flexible de configuración
10. **Deployment Guides** - Guías de despliegue empresarial

Esta tarea proporciona a CryptoShield las interfaces de gestión y APIs necesarias para su despliegue y operación en entornos empresariales, facilitando la integración con infraestructuras existentes y proporcionando herramientas intuitivas para administradores.