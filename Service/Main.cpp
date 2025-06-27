/**
 * @file Main.cpp
 * @brief Entry point for CryptoShield service
 * @details Windows service that communicates with kernel driver
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include <windows.h>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <atomic>
#include <csignal>
#include <sstream>
#include "..\Core\CommunicationManager.h"
#include "..\Core\MessageProcessor.h"
#include "..\Core\Detection/DetectionConfig.h" // Added
#include "..\Core\Detection/TraditionalEngine.h" // Added
#include "Protection/ServiceProtection.h" // Added for critical process protection
#include "Protection/WindowsSecurityIntegration.h" // Para integración con WSC
#include "ResponseCoordinator.h" // <--- AÑADIDO PARA EL COORDINADOR DE RESPUESTAS
#include <iwscapi.h> // Para WSC_SECURITY_PRODUCT_STATE, aunque ya está en WindowsSecurityIntegration.h
#include "ServiceLogging.h" // Added for shared Event Logging

 // Service name and display name
constexpr wchar_t SERVICE_NAME[] = L"CryptoShieldService";
constexpr wchar_t SERVICE_DISPLAY_NAME[] = L"CryptoShield Anti-Ransomware Service";
constexpr wchar_t SERVICE_DESCRIPTION_FUNC[] = L"Protects system against ransomware attacks";

// Service control codes
constexpr DWORD SERVICE_CONTROL_CUSTOM_SHUTDOWN = 128;
constexpr DWORD SERVICE_CONTROL_CUSTOM_RELOAD_CONFIG = 129;

// Global service variables
SERVICE_STATUS_HANDLE g_service_status_handle = nullptr;
SERVICE_STATUS g_service_status = { 0 };
std::atomic<bool> g_running{ false };
std::atomic<bool> g_paused{ false };

// Forward declarations
VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
VOID WINAPI ServiceCtrlHandler(DWORD ctrl_code);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);
VOID WatchdogThreadProc(CryptoShield::CommunicationManager& comm_manager, std::atomic<bool>& running_flag); // Watchdog

bool InstallService();
bool UninstallService();
bool StartServiceManually();
bool StopServiceManually();
void SetServiceStatus(DWORD current_state, DWORD exit_code = NO_ERROR, DWORD wait_hint = 0);
// void WriteEventLog(WORD event_type, const std::wstring& message); // Declaration moved to ServiceLogging.h

/**
 * @brief Main entry point
 * @details Determines whether to run as service or handle command line
 *
 * @param argc Argument count
 * @param argv Argument values
 * @return Exit code
 */
int wmain(int argc, wchar_t* argv[])
{
    // Check command line arguments
    if (argc > 1) {
        std::wstring command(argv[1]);

        if (command == L"/install" || command == L"-install") {
            std::wcout << L"Installing CryptoShield Service..." << std::endl;
            if (InstallService()) {
                std::wcout << L"Service installed successfully." << std::endl;
                return 0;
            }
            else {
                std::wcerr << L"Failed to install service. Error: " << GetLastError() << std::endl;
                return 1;
            }
        }
        else if (command == L"/uninstall" || command == L"-uninstall") {
            std::wcout << L"Uninstalling CryptoShield Service..." << std::endl;
            if (UninstallService()) {
                std::wcout << L"Service uninstalled successfully." << std::endl;
                return 0;
            }
            else {
                std::wcerr << L"Failed to uninstall service. Error: " << GetLastError() << std::endl;
                return 1;
            }
        }
        else if (command == L"/start" || command == L"-start") {
            std::wcout << L"Starting CryptoShield Service..." << std::endl;
            if (StartServiceManually()) {
                std::wcout << L"Service started successfully." << std::endl;
                return 0;
            }
            else {
                std::wcerr << L"Failed to start service. Error: " << GetLastError() << std::endl;
                return 1;
            }
        }
        else if (command == L"/stop" || command == L"-stop") {
            std::wcout << L"Stopping CryptoShield Service..." << std::endl;
            if (StopServiceManually()) {
                std::wcout << L"Service stopped successfully." << std::endl;
                return 0;
            }
            else {
                std::wcerr << L"Failed to stop service. Error: " << GetLastError() << std::endl;
                return 1;
            }
        }
        else if (command == L"/debug" || command == L"-debug") {
            std::wcout << L"Running in debug mode..." << std::endl;
            // Run service logic directly for debugging
            g_running = true;
            ServiceWorkerThread(nullptr);
            return 0;
        }
        else if (command == L"/generate-config") {
            std::wcout << L"Generating default configuration file (detection_config.json)..." << std::endl;

            // Creamos una instancia del gestor de configuración
            auto config_manager = std::make_unique<CryptoShield::Detection::DetectionConfigManager>();

            // La configuración por defecto ya se carga en el constructor del manager.
            // Ahora, simplemente la guardamos a un fichero.
            if (config_manager->SaveConfiguration(L"detection_config.json")) {
                std::wcout << L"Default configuration file 'detection_config.json' created successfully." << std::endl;
                return 0;
            }
            else {
                std::wcerr << L"Failed to create default configuration file." << std::endl;
                return 1;
            }
        }
        else {
            std::wcerr << L"Unknown command: " << command << std::endl;
            std::wcerr << L"Usage: " << argv[0] << L" [/install | /uninstall | /start | /stop | /debug]" << std::endl;
            return 1;
        }
    }

    // Run as service
    SERVICE_TABLE_ENTRYW service_table[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(service_table)) {
        DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::wcerr << L"Not running as service. Use /debug flag to run in console mode." << std::endl;
        }
        else {
            std::wcerr << L"StartServiceCtrlDispatcher failed. Error: " << error << std::endl;
        }
        return 1;
    }

    return 0;
}

/**
 * @brief Service main function
 * @details Called by SCM when service starts
 *
 * @param argc Argument count
 * @param argv Argument values
 */
VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    // Register service control handler
    g_service_status_handle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
    if (g_service_status_handle == nullptr) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"RegisterServiceCtrlHandler failed");
        return;
    }

    // Initialize service status
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwServiceSpecificExitCode = 0;

    // Report initial status
    SetServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    // Perform initialization
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"CryptoShield Service starting...");

    // Create worker thread
    HANDLE worker_thread = CreateThread(
        nullptr,
        0,
        ServiceWorkerThread,
        nullptr,
        0,
        nullptr
    );

    if (worker_thread == nullptr) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"Failed to create worker thread");
        SetServiceStatus(SERVICE_STOPPED, GetLastError());
        return;
    }

    // Report running status
    SetServiceStatus(SERVICE_RUNNING);
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"CryptoShield Service components initialized, reporting SERVICE_RUNNING.");

    // Attempt to enable critical process protection
    // This is done AFTER reporting SERVICE_RUNNING, as per requirements.
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Attempting to enable critical process protection...");
    if (!EnableCriticalProcessProtection()) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"CRITICAL FAILURE: Failed to enable critical process protection. The service will stop to prevent running in an unprotected state.");
        // LogErrorW in ServiceProtection.cpp would have logged details already.
        // We need to signal the SCM that the service is stopping due to an error.
        SetServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        // It's important to also signal the worker thread to terminate if it's already running complex logic,
        // but in this structure, ServiceWorkerThread is the main execution loop.
        // If EnableCriticalProcessProtection fails, ServiceMain will terminate,
        // and the process will end. If worker_thread was already doing vital things,
        // we might need a more graceful shutdown signal for it.
        // However, worker_thread is created and then immediately waited upon.
        // If this call fails, ServiceMain exits, and the process dies.
        // If the worker thread was meant to run independently of ServiceMain's lifetime post-initialization,
        // this structure would need adjustment. Given WaitForSingleObject, this is okay.

        // Ensure g_running is false so the worker thread (if it managed to start and check g_running) exits.
        // This is a safeguard. The main control is stopping the service via SetServiceStatus.
        g_running = false;

        // We might not need to close the worker_thread handle here if the process is about to exit.
        // However, for correctness in other scenarios:
        if (worker_thread != nullptr) {
             // Signal the worker thread to stop if it's designed to check g_running
             // (already done by setting g_running = false)
             // Optionally, wait for it for a very short period, then terminate if necessary,
             // but since the service is stopping with error, a quick exit is acceptable.
            CloseHandle(worker_thread);
        }
        return; // Stop the service.
    }
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Critical process protection enabled successfully. CryptoShield Service is now running with enhanced protection.");

    // Wait for worker thread to complete
    WaitForSingleObject(worker_thread, INFINITE);
    CloseHandle(worker_thread);

    // Service has stopped
    SetServiceStatus(SERVICE_STOPPED);
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"CryptoShield Service stopped");
}

/**
 * @brief Service control handler
 * @details Handles control requests from SCM
 *
 * @param ctrl_code Control code
 */
VOID WINAPI ServiceCtrlHandler(DWORD ctrl_code)
{
    switch (ctrl_code) {
    case SERVICE_CONTROL_STOP:
        SetServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        g_running = false;
        break;

    case SERVICE_CONTROL_PAUSE:
        SetServiceStatus(SERVICE_PAUSE_PENDING, NO_ERROR, 1000);
        g_paused = true;
        SetServiceStatus(SERVICE_PAUSED);
        break;

    case SERVICE_CONTROL_CONTINUE:
        SetServiceStatus(SERVICE_CONTINUE_PENDING, NO_ERROR, 1000);
        g_paused = false;
        SetServiceStatus(SERVICE_RUNNING);
        break;

    case SERVICE_CONTROL_INTERROGATE:
        // Report current status
        SetServiceStatus(g_service_status.dwCurrentState);
        break;

    case SERVICE_CONTROL_CUSTOM_SHUTDOWN:
        // Custom shutdown with cleanup
        WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Received custom shutdown request");
        g_running = false;
        break;

    case SERVICE_CONTROL_CUSTOM_RELOAD_CONFIG:
        // Reload configuration
        WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Reloading configuration");
        // TODO: Implement config reload
        break;

    default:
        break;
    }
}

/**
 * @brief Service worker thread
 * @details Main service logic runs here. This thread initializes and orchestrates all
 * core components, including configuration loading, communication with the driver,
 * the detection engine, and the message processor. It then enters a monitoring

 * loop until a stop signal is received, after which it handles graceful shutdown.
 *
 * @param lpParam Thread parameter (unused).
 * @return Thread exit code.
 */
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);
    g_running = true;

    // --- 0. WSC INTEGRATION OBJECT ---
    // Declarar aquí para que su vida útil cubra toda la función,
    // y su destructor pueda llamar a Unregister si es necesario al final.
    std::unique_ptr<WindowsSecurityCenterIntegration> wsc_integration = nullptr; // Renombrado para claridad
    std::unique_ptr<ResponseCoordinator> response_coordinator = nullptr; // Añadido

    // --- 1. COMPONENT INITIALIZATION ---

    // Load configuration from "detection_config.json"
    auto config_manager = std::make_unique<CryptoShield::Detection::DetectionConfigManager>();
    if (!config_manager->LoadConfiguration(L"detection_config.json")) {
        WriteEventLog(EVENTLOG_WARNING_TYPE, L"Failed to load detection_config.json. Using default detection settings.");
    }
    else {
        WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Successfully loaded detection_config.json.");
    }
    CryptoShield::Detection::DetectionEngineConfig engine_config = config_manager->GetConfiguration();

    // Create the Traditional Detection Engine using the loaded configuration
    auto traditional_engine = std::make_shared<CryptoShield::Detection::TraditionalEngine>(engine_config);
    if (!traditional_engine->Initialize()) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"Failed to initialize TraditionalEngine. Service cannot start.");
        return ERROR_SERVICE_SPECIFIC_ERROR;
    }
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"TraditionalEngine initialized successfully.");

    // Configure and create the Message Processor, injecting the detection engine
    CryptoShield::ProcessorConfig processor_config;
    processor_config.enable_logging = engine_config.global.enable_logging;
    processor_config.log_directory = engine_config.global.log_directory;
    processor_config.max_queue_size = 10000;
    processor_config.processing_threads = static_cast<ULONG>(engine_config.global.thread_pool_size);
    processor_config.enable_alerts = engine_config.response.enable_alerts;
    processor_config.alert_threshold = 0; // Deprecated, engine handles thresholds now

    auto message_processor = std::make_unique<CryptoShield::MessageProcessor>(processor_config, traditional_engine);

    // Create the Communication Manager, passing the MessageProcessor instance
    auto communication_manager = std::make_unique<CryptoShield::CommunicationManager>(message_processor.get());

    // Crear instancia de WindowsSecurityCenterIntegration (antes de ResponseCoordinator)
    try {
        wsc_integration = std::make_unique<WindowsSecurityCenterIntegration>();
    } catch (const std::bad_alloc& ba) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"Failed to allocate WindowsSecurityCenterIntegration (bad_alloc) during component init. Service cannot start.");
        return ERROR_SERVICE_SPECIFIC_ERROR; // Error fatal
    } catch (...) { // Captura otras excepciones potenciales de construcción si WSCIntegration pudiera lanzarlas
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"An unknown error occurred during WindowsSecurityCenterIntegration creation. Service cannot start.");
        return ERROR_SERVICE_SPECIFIC_ERROR; // Error fatal
    }

    // Crear instancia de ResponseCoordinator, pasando la referencia a wsc_integration
    // Es importante que wsc_integration ya esté inicializado.
    try {
        response_coordinator = std::make_unique<ResponseCoordinator>(*wsc_integration);
    } catch (const std::bad_alloc& ba) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"Failed to allocate ResponseCoordinator (bad_alloc). Service cannot start.");
        // wsc_integration se limpiará automáticamente al salir del scope si esto falla.
        return ERROR_SERVICE_SPECIFIC_ERROR;
    } catch (...) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"An unknown error occurred during ResponseCoordinator creation. Service cannot start.");
        return ERROR_SERVICE_SPECIFIC_ERROR;
    }
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"ResponseCoordinator initialized successfully.");


    // --- 2. COMPONENT WIRING AND STARTUP ---

    // Set the callback for when the Communication Manager receives an operation from the driver
    communication_manager->SetMessageCallback(
        // Capture message_processor by raw pointer as its lifetime is managed by unique_ptr and outlives comm_manager here
        [mp = message_processor.get()](const CryptoShield::FileOperationInfo& operation) {
            mp->EnqueueOperation(operation);
        }
    );

    // Set the callback for when a threat is detected and an alert is generated
    message_processor->SetAlertCallback(
        [](const CryptoShield::AlertInfo& alert) {
            std::wstringstream severity_str;
            switch (alert.severity) {
            case CryptoShield::AlertSeverity::Critical:
                severity_str << L"CRITICAL";
                break;
            case CryptoShield::AlertSeverity::High:
                severity_str << L"HIGH";
                break;
            case CryptoShield::AlertSeverity::Medium:
                severity_str << L"MEDIUM";
                break;
            case CryptoShield::AlertSeverity::Low:
                severity_str << L"LOW";
                break;
            default: 
                severity_str << L"UNKNOWN";
                break;
            }

            // La construcción del mensaje ahora es segura
            std::wstring alert_message = L"[" + severity_str.str() + L"] " + alert.description;
            WriteEventLog(EVENTLOG_WARNING_TYPE, alert_message);
        }
    );

    // Registrar el callback de alertas críticas del kernel en MessageProcessor
    // Se captura response_coordinator por puntero raw ya que su lifetime está gestionado por unique_ptr
    // y se garantiza que sobrevive a message_processor si ServiceWorkerThread se ejecuta completamente.
    if (message_processor && response_coordinator) { // Asegurarse de que ambos existen
        message_processor->SetCriticalAlertCallback(
            [rc = response_coordinator.get()](const CS_TAMPER_ALERT_PAYLOAD& alert) {
                rc->HandleCriticalTamperAlert(alert);
            }
        );
        WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Critical alert callback registered with MessageProcessor.");
    } else {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"Failed to register critical alert callback: MessageProcessor or ResponseCoordinator is null.");
        // Esto podría ser un error fatal dependiendo de la política.
        // Por ahora, solo se registra el error.
    }

    // Set callback for connection status changes
    communication_manager->SetConnectionCallback(
        [](bool connected) {
            if (connected) {
                WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Connected to driver.");
            }
            else {
                WriteEventLog(EVENTLOG_WARNING_TYPE, L"Disconnected from driver.");
            }
        }
    );

    // Initialize communication with the driver
    if (!communication_manager->Initialize()) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"Failed to connect to driver. Service will stop.");
        return ERROR_SERVICE_SPECIFIC_ERROR;
    }

    // Start the message processing background threads
    if (!message_processor->Start()) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"Failed to start message processor. Service will stop.");
        communication_manager->Shutdown();
        return ERROR_SERVICE_SPECIFIC_ERROR;
    }

    // Send initial configuration to the driver
    ULONG initial_config_flags = CONFIG_FLAG_MONITORING_ENABLED;
    ULONG initial_sensitivity = 50; // Example value
    ULONG initial_response_actions = ACTION_ALLOW | ACTION_LOG_ONLY; // Example value
    communication_manager->UpdateConfiguration(initial_config_flags, initial_sensitivity, initial_response_actions);

    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Service is now fully operational and monitoring.");

    // --- WINDOWS SECURITY CENTER INTEGRATION ---
    // La inicialización de wsc_integration se movió más arriba, antes de ResponseCoordinator.
    // Aquí solo se realiza el registro y la actualización de estado.
    if (wsc_integration) { // Solo proceder si wsc_integration fue creado exitosamente
        WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Initializing Windows Security Center integration...");
        try {
            HRESULT hr_register = wsc_integration->Register();
            if (SUCCEEDED(hr_register)) {
                if (hr_register == S_OK) {
                    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Successfully registered with Windows Security Center.");
                } else { // S_FALSE
                     WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Product already registered with Windows Security Center. Will ensure state is ON.");
                }
                // Inmediatamente después del registro o si ya estaba registrado, actualizar/confirmar el estado a ON.
                HRESULT hr_update = wsc_integration->UpdateState(WSC_SECURITY_PRODUCT_STATE_ON);
                if (SUCCEEDED(hr_update)) {
                    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Product state set/confirmed as ON in Windows Security Center.");
                } else {
                    std::wstringstream ss;
                    ss << L"Failed to set product state to ON in Windows Security Center. HRESULT: 0x" << std::hex << hr_update;
                    WriteEventLog(EVENTLOG_WARNING_TYPE, ss.str());
                }
            } else {
                std::wstringstream ss;
                ss << L"Failed to register with Windows Security Center. HRESULT: 0x" << std::hex << hr_register;
                WriteEventLog(EVENTLOG_WARNING_TYPE, ss.str());
                // No se considera un error fatal que detenga el servicio.
            }
        } catch (const _com_error& e) {
            std::wstringstream ss;
            ss << L"A COM error occurred during WSC integration: "
               << (e.ErrorMessage() ? e.ErrorMessage() : L"Unknown COM error")
               << L" HRESULT: 0x" << std::hex << e.Error();
            WriteEventLog(EVENTLOG_WARNING_TYPE, ss.str());
        } catch (const std::exception& e) {
            std::string narrow_what = e.what();
            std::wstring wide_what(narrow_what.begin(), narrow_what.end());
            WriteEventLog(EVENTLOG_WARNING_TYPE, L"An exception occurred during WSC integration: " + wide_what);
        } catch (...) {
            WriteEventLog(EVENTLOG_WARNING_TYPE, L"An unknown error occurred during WSC integration initialization.");
        }
    } else {
        WriteEventLog(EVENTLOG_WARNING_TYPE, L"Windows Security Center integration skipped as wsc_integration object is null.");
    }
    // --- END WINDOWS SECURITY CENTER INTEGRATION ---

    // --- 3. WATCHDOG THREAD ---
    // The Watchdog thread needs SE_SHUTDOWN_NAME privilege to be able to initiate a system reboot.
    // This privilege should be acquired early, for example in ServiceMain or here.
    // For now, we assume it's granted. Consider adding:
    // if (!SetRequiredPrivileges(SE_SHUTDOWN_NAME)) {
    //     WriteEventLog(EVENTLOG_WARNING_TYPE, L"Failed to acquire SE_SHUTDOWN_NAME for Watchdog. System reboot capability disabled.");
    // }
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Starting Watchdog thread for driver communication monitoring.");
    std::thread watchdog_thread(WatchdogThreadProc, std::ref(*communication_manager), std::ref(g_running));

    // --- 4. MAIN SERVICE LOOP ---

    ULONGLONG last_stats_time = GetTickCount64();
    while (g_running) {
        if (!g_paused) {
            // The primary check for IsConnected and reconnection attempts are now handled by the Watchdog.
            // This loop can focus on other periodic tasks, like logging stats.
            // If IsConnected() is still needed here for other logic, it can remain.
            // For now, removing the direct IsConnected check from this loop as Watchdog handles it.

            // Log statistics periodically (e.g., every minute)
            if (GetTickCount64() - last_stats_time > 60000) {
                auto stats = message_processor->GetStatistics();
                std::wstring stats_msg = L"Statistics - Total Ops: " + std::to_wstring(stats.total_operations) +
                    L", Suspicious: " + std::to_wstring(stats.suspicious_operations) +
                    L", Queue Size: " + std::to_wstring(message_processor->GetQueueSize());
                WriteEventLog(EVENTLOG_INFORMATION_TYPE, stats_msg);
                last_stats_time = GetTickCount64();
            }
        }
        Sleep(1000); // Sleep for a second; can be adjusted.
    }

    // --- 5. GRACEFUL SHUTDOWN ---

    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Service worker thread stopping...");

    // Signal and wait for Watchdog thread to complete
    // g_running is already false here, WatchdogThreadProc should detect it and exit.
    if (watchdog_thread.joinable()) {
        WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Waiting for Watchdog thread to join...");
        watchdog_thread.join();
        WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Watchdog thread joined.");
    }

    message_processor->Stop();
    communication_manager->RequestShutdown(); // Politely ask the communication manager to stop its loops
    communication_manager->Shutdown();      // Ensure resources are released
    traditional_engine->Shutdown();

    auto final_stats = message_processor->GetStatistics();
    std::wstring final_msg = L"Final statistics - Total operations processed: " +
        std::to_wstring(final_stats.total_operations);
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, final_msg);

    // El unique_ptr wscIntegration se destruirá aquí automáticamente.
    // Su destructor llamará a Unregister() si CryptoShield se registró exitosamente
    // y m_pServices todavía es válido. Esto asegura la limpieza si el servicio se detiene
    // normalmente, en lugar de desinstalarse.

    return ERROR_SUCCESS;
}


/**
 * @brief Watchdog thread procedure to monitor driver communication.
 * @details This thread periodically checks the connection to the kernel driver.
 * If the connection is lost, it attempts to re-establish it. If reconnection
 * fails after several attempts, it logs a critical error and initiates a
 * system reboot as a fail-safe measure.
 *
 * @param comm_manager Reference to the CommunicationManager instance.
 * @param running_flag Atomic boolean indicating if the service is running.
 */
VOID WatchdogThreadProc(CryptoShield::CommunicationManager& comm_manager, std::atomic<bool>& running_flag) {
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"WatchdogThreadProc started.");

    // It's crucial that SE_SHUTDOWN_NAME privilege is available if a reboot is needed.
    // This should be acquired by the main service process.
    // A check could be added here:
    // if (!CheckPrivilege(SE_SHUTDOWN_NAME)) { // Hypothetical CheckPrivilege function
    //    WriteEventLog(EVENTLOG_WARNING_TYPE, L"Watchdog: SE_SHUTDOWN_NAME not held. Reboot capability is non-functional.");
    // }

    while (running_flag.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(3));

        if (!running_flag.load(std::memory_order_relaxed)) {
            break; // Exit if service is stopping
        }

        if (!comm_manager.IsConnected()) {
            WriteEventLog(EVENTLOG_WARNING_TYPE, L"Watchdog: Connection to driver lost. Attempting to reconnect...");

            bool reconnected = false;
            const int max_retries = 3;
            const int retry_delay_seconds = 5;

            for (int i = 0; i < max_retries; ++i) {
                if (!running_flag.load(std::memory_order_relaxed)) break; // Check before sleep and retry

                // It's possible that CommunicationManager::Shutdown() should be called before Initialize()
                // if Initialize() doesn't fully clean up a previous failed state.
                // Based on current ServiceWorkerThread, Shutdown() is called before Initialize().
                // Let's assume comm_manager.Initialize() can be called multiple times or handles its own reset.
                // If not, comm_manager.Shutdown() might be needed here.
                // comm_manager.Shutdown(); // Optional: depending on Initialize behavior
                // std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Brief pause if Shutdown is called

                WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Watchdog: Reconnection attempt " + std::to_wstring(i + 1) + L" of " + std::to_wstring(max_retries) + L".");
                if (comm_manager.Initialize()) {
                    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Watchdog: Reconnected to driver successfully.");
                    reconnected = true;
                    break;
                }
                else {
                    WriteEventLog(EVENTLOG_WARNING_TYPE, L"Watchdog: Reconnection attempt " + std::to_wstring(i + 1) + L" failed.");
                    if (i < max_retries - 1) {
                        for(int s=0; s < retry_delay_seconds; ++s) {
                            if (!running_flag.load(std::memory_order_relaxed)) break;
                             std::this_thread::sleep_for(std::chrono::seconds(1));
                        }
                    }
                }
            }

            if (!reconnected && running_flag.load(std::memory_order_relaxed)) {
                WriteEventLog(EVENTLOG_ERROR_TYPE,
                    L"CRITICAL FAILURE: Watchdog failed to reconnect to the kernel driver after multiple attempts. "
                    L"The system may be at risk. Initiating a forced system reboot to ensure system integrity.");

                // Grant SE_SHUTDOWN_NAME if not already done by the service
                // This is a last resort attempt, ideally it's set at startup.
                // if (!SetRequiredPrivileges(SE_SHUTDOWN_NAME)) {
                //     WriteEventLog(EVENTLOG_ERROR_TYPE, L"Watchdog: Failed to acquire SE_SHUTDOWN_NAME. Cannot initiate reboot.");
                // } else {
                //     // Initiate forced system reboot
                // }
                // For this implementation, we assume the privilege is available or SetRequiredPrivileges was called successfully elsewhere.

                // InitiateSystemShutdownExW requires advapi32.lib to be linked.
                // Ensure it's in the project's linker dependencies.
                BOOL reboot_initiated = InitiateSystemShutdownExW(
                    NULL,    // Target machine: local
                    const_cast<LPWSTR>(L"CryptoShield: Critical communication loss with kernel driver. System rebooting for protection."), // Message
                    30,      // Timeout in seconds
                    TRUE,    // Force applications to close
                    TRUE,    // Reboot (TRUE) vs Shutdown (FALSE)
                    SHTDN_REASON_FLAG_MAJOR_OPERATINGSYSTEM |
                    SHTDN_REASON_FLAG_MINOR_SECURITY |
                    SHTDN_REASON_FLAG_PLANNED // Though unplanned, this reason code is often used for critical system-initiated reboots
                );

                if (reboot_initiated) {
                    WriteEventLog(EVENTLOG_ERROR_TYPE, L"Watchdog: InitiateSystemShutdownExW called successfully. System should reboot shortly.");
                    // The system will reboot, effectively stopping the service.
                    // We might want to signal g_running = false here, though the process will terminate.
                    running_flag.store(false, std::memory_order_relaxed); // Signal other threads to stop
                } else {
                    DWORD error = GetLastError();
                    WriteEventLog(EVENTLOG_ERROR_TYPE, L"Watchdog: InitiateSystemShutdownExW failed. Error code: " + std::to_wstring(error) +
                                                     L". Manual intervention may be required. The service will attempt to continue but protection is compromised.");
                    // If reboot fails, the service is in a very bad state.
                    // Continue running might be an option, but it's risky.
                    // For now, we just log and the service continues in a degraded state.
                }
            }
        }
    }
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"WatchdogThreadProc finished.");
}



/**
 * @brief Sets service status
 * @details Reports status to SCM
 *
 * @param current_state New service state
 * @param exit_code Exit code if stopping
 * @param wait_hint Estimated time for pending operation
 */
void SetServiceStatus(DWORD current_state, DWORD exit_code, DWORD wait_hint)
{
    static DWORD check_point = 1;

    g_service_status.dwCurrentState = current_state;
    g_service_status.dwWin32ExitCode = exit_code;
    g_service_status.dwWaitHint = wait_hint;

    if (current_state == SERVICE_START_PENDING ||
        current_state == SERVICE_STOP_PENDING ||
        current_state == SERVICE_PAUSE_PENDING ||
        current_state == SERVICE_CONTINUE_PENDING) {
        g_service_status.dwControlsAccepted = 0;
        g_service_status.dwCheckPoint = check_point++;
    }
    else {
        g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP |
            SERVICE_ACCEPT_PAUSE_CONTINUE;
        g_service_status.dwCheckPoint = 0;
    }

    SetServiceStatus(g_service_status_handle, &g_service_status);
}

/**
 * @brief Writes to Windows event log
 * @details Logs service events for monitoring
 *
 * @param event_type Type of event (error, warning, info)
 * @param message Message to log
 */
void WriteEventLog(WORD event_type, const std::wstring& message)
{
    HANDLE event_source = RegisterEventSourceW(nullptr, SERVICE_NAME);
    if (event_source != nullptr) {
        LPCWSTR strings[1] = { message.c_str() };
        ReportEventW(event_source,
            event_type,
            0,
            0,
            nullptr,
            1,
            0,
            strings,
            nullptr);
        DeregisterEventSource(event_source);
    }
}

/**
 * @brief Installs the service
 * @details Registers service with SCM
 *
 * @return true on success
 */
bool InstallService()
{
    wchar_t service_path[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, service_path, MAX_PATH)) {
        return false;
    }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm == nullptr) {
        return false;
    }

    SC_HANDLE service = CreateServiceW(
        scm,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        service_path,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    bool success = (service != nullptr);

    if (service) {
        // Set service description
        SERVICE_DESCRIPTIONW description = { const_cast<LPWSTR>(SERVICE_DESCRIPTION_FUNC) };
        ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);

        // Set recovery options
        SERVICE_FAILURE_ACTIONSW failure_actions = { 0 };
        SC_ACTION actions[3] = {
            { SC_ACTION_RESTART, 60000 },  // Restart after 1 minute
            { SC_ACTION_RESTART, 120000 }, // Restart after 2 minutes
            { SC_ACTION_NONE, 0 }          // Do nothing
        };

        failure_actions.cActions = 3;
        failure_actions.lpsaActions = actions;
        failure_actions.dwResetPeriod = 86400; // Reset after 1 day

        ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure_actions);

        CloseServiceHandle(service);
    }

    CloseServiceHandle(scm);
    return success;
}

/**
 * @brief Uninstalls the service
 * @details Removes service from SCM
 *
 * @return true on success
 */
bool UninstallService()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm == nullptr) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service == nullptr) {
        CloseServiceHandle(scm);
        return false;
    }

    // Stop service if running
    SERVICE_STATUS status = { 0 };
    if (QueryServiceStatus(service, &status)) {
        if (status.dwCurrentState != SERVICE_STOPPED &&
            status.dwCurrentState != SERVICE_STOP_PENDING) { // Check for STOP_PENDING as well
            WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Service is running, attempting to stop it before uninstallation...");
            std::wcout << L"Service is running, attempting to stop it..." << std::endl;
            if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
                 WriteEventLog(EVENTLOG_WARNING_TYPE, L"Failed to send STOP control to service. Uninstallation might require reboot or manual stop.");
                 std::wcerr << L"Failed to send STOP control to service. Error: " << GetLastError() << std::endl;
            } else {
                // Wait for the service to stop
                int attempts = 0;
                while (QueryServiceStatus(service, &status) && status.dwCurrentState != SERVICE_STOPPED && attempts < 30) { // Wait up to 30s
                    Sleep(1000);
                    attempts++;
                }
                if (status.dwCurrentState == SERVICE_STOPPED) {
                    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Service stopped successfully.");
                    std::wcout << L"Service stopped successfully." << std::endl;
                } else {
                    WriteEventLog(EVENTLOG_WARNING_TYPE, L"Service did not stop in time. Uninstallation will proceed.");
                    std::wcerr << L"Service did not stop in time. Current state: " << status.dwCurrentState << std::endl;
                }
            }
        }
    }

    // --- UNREGISTER FROM WINDOWS SECURITY CENTER ---
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Attempting to unregister from Windows Security Center prior to service uninstallation...");
    std::wcout << L"Attempting to unregister from Windows Security Center..." << std::endl;
    try {
        // Crear una instancia temporal para desregistrar.
        // Su constructor inicializará COM, y su destructor desinicializará COM.
        WindowsSecurityCenterIntegration wscIntegrationForUnreg;
        HRESULT hr_unregister = wscIntegrationForUnreg.Unregister();
        if (SUCCEEDED(hr_unregister)) {
            if (hr_unregister == S_OK) { // S_OK significa que se desregistró activamente.
                 WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Successfully unregistered from Windows Security Center.");
                 std::wcout << L"Successfully unregistered from Windows Security Center." << std::endl;
            } else { // S_FALSE (WBEM_S_FALSE o similar si Unregister devuelve eso para "no encontrado")
                     // o si Unregister devuelve S_OK para "no encontrado" como está implementado actualmente.
                 WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Product was not found in Windows Security Center (already unregistered or never registered).");
                 std::wcout << L"Product was not found in Windows Security Center (already unregistered or never registered)." << std::endl;
            }
        } else {
            std::wstringstream ss;
            ss << L"Failed to unregister from Windows Security Center. HRESULT: 0x" << std::hex << hr_unregister;
            WriteEventLog(EVENTLOG_WARNING_TYPE, ss.str());
            std::wcerr << L"Warning: " << ss.str() << std::endl;
        }
    } catch (const _com_error& e) {
        std::wstringstream ss;
        ss << L"A COM error occurred during WSC unregistration: "
           << (e.ErrorMessage() ? e.ErrorMessage() : L"Unknown COM error")
           << L" HRESULT: 0x" << std::hex << e.Error();
        WriteEventLog(EVENTLOG_WARNING_TYPE, ss.str());
        std::wcerr << L"Warning: " << ss.str() << std::endl;
    } catch (const std::exception& e) {
        std::string narrow_what = e.what();
        std::wstring wide_what(narrow_what.begin(), narrow_what.end());
        WriteEventLog(EVENTLOG_WARNING_TYPE, L"An exception occurred during WSC unregistration: " + wide_what);
        std::wcerr << L"Warning: An exception occurred during WSC unregistration: " << wide_what << std::endl;
    } catch (...) {
        WriteEventLog(EVENTLOG_WARNING_TYPE, L"An unknown error occurred during WSC unregistration.");
        std::wcerr << L"Warning: An unknown error occurred during WSC unregistration." << std::endl;
    }
    // --- END UNREGISTER FROM WINDOWS SECURITY CENTER ---

    bool success = DeleteService(service) != 0;

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return success;
}

/**
 * @brief Starts the service manually
 * @details Used by command line interface
 *
 * @return true on success
 */
bool StartServiceManually()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm == nullptr) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service == nullptr) {
        CloseServiceHandle(scm);
        return false;
    }

    bool success = StartServiceW(service, 0, nullptr) != 0;

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return success;
}

/**
 * @brief Stops the service manually
 * @details Used by command line interface
 *
 * @return true on success
 */
bool StopServiceManually()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (scm == nullptr) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service == nullptr) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status = { 0 };
    bool success = ControlService(service, SERVICE_CONTROL_STOP, &status) != 0;

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return success;
}