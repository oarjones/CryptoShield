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
#include "CommunicationManager.h"
#include "MessageProcessor.h"

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

bool InstallService();
bool UninstallService();
bool StartServiceManually();
bool StopServiceManually();
void SetServiceStatus(DWORD current_state, DWORD exit_code = NO_ERROR, DWORD wait_hint = 0);
void WriteEventLog(WORD event_type, const std::wstring& message);

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
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"CryptoShield Service started successfully");

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
 * @details Main service logic runs here
 *
 * @param lpParam Thread parameter (unused)
 * @return Thread exit code
 */
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    g_running = true;

    // Create communication manager
    auto communication_manager = std::make_unique<CryptoShield::CommunicationManager>();

    // Create message processor with configuration
    CryptoShield::ProcessorConfig processor_config;
    processor_config.enable_logging = true;
    processor_config.log_directory = L"C:\\ProgramData\\CryptoShield\\Logs";
    processor_config.max_queue_size = 10000;
    processor_config.processing_threads = 4;
    processor_config.enable_alerts = true;
    processor_config.alert_threshold = 40;

    auto message_processor = std::make_unique<CryptoShield::MessageProcessor>(processor_config);

    // Set up callbacks
    communication_manager->SetMessageCallback(
        [&message_processor](const CryptoShield::FileOperationInfo& operation) {
            message_processor->EnqueueOperation(operation);
        }
    );

    communication_manager->SetConnectionCallback(
        [](bool connected) {
            if (connected) {
                WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Connected to driver");
            }
            else {
                WriteEventLog(EVENTLOG_WARNING_TYPE, L"Disconnected from driver");
            }
        }
    );

    message_processor->SetAlertCallback(
        [](const CryptoShield::AlertInfo& alert) {
            std::wstring severity_str;
            switch (alert.severity) {
            case CryptoShield::AlertSeverity::Critical:
                severity_str = L"CRITICAL";
                break;
            case CryptoShield::AlertSeverity::High:
                severity_str = L"HIGH";
                break;
            case CryptoShield::AlertSeverity::Medium:
                severity_str = L"MEDIUM";
                break;
            case CryptoShield::AlertSeverity::Low:
                severity_str = L"LOW";
                break;
            }

            std::wstring alert_message = L"[" + severity_str + L"] " + alert.description;
            WriteEventLog(EVENTLOG_WARNING_TYPE, alert_message);

            // In production, could also send email, SMS, or trigger other responses
        }
    );

    // Initialize communication with driver
    if (!communication_manager->Initialize()) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"Failed to connect to driver");
        return ERROR_SERVICE_SPECIFIC_ERROR;
    }

    // Start message processing
    if (!message_processor->Start()) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"Failed to start message processor");
        communication_manager->Shutdown();
        return ERROR_SERVICE_SPECIFIC_ERROR;
    }

    // Enable monitoring in driver
    // Default actions: Allow and Log. Adjust as necessary.
    ULONG initial_config_flags = CONFIG_FLAG_MONITORING_ENABLED;
    ULONG initial_sensitivity = 50;
    ULONG initial_response_actions = ACTION_ALLOW | ACTION_LOG_ONLY; // Example default actions
    
    //TODO: Descomentar
    communication_manager->UpdateConfiguration(initial_config_flags, initial_sensitivity, initial_response_actions);

    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Service worker thread started");

    // Main service loop
    DWORD last_stats_time = GetTickCount64();
    while (g_running) {
        if (!g_paused) {
            // Check connection status
            if (!communication_manager->IsConnected()) {
                WriteEventLog(EVENTLOG_WARNING_TYPE, L"Lost connection to driver, attempting reconnect...");

                // Try to reconnect
                communication_manager->Shutdown();
                Sleep(5000); // Wait 5 seconds

                if (!communication_manager->Initialize()) {
                    WriteEventLog(EVENTLOG_ERROR_TYPE, L"Failed to reconnect to driver");
                    Sleep(10000); // Wait longer before next attempt
                }
            }

            // Log statistics every minute
            DWORD current_time = GetTickCount64();
            if (current_time - last_stats_time > 60000) {
                auto stats = message_processor->GetStatistics();
                std::wstring stats_msg = L"Statistics - Total operations: " +
                    std::to_wstring(stats.total_operations) +
                    L", Queue size: " +
                    std::to_wstring(message_processor->GetQueueSize());
                WriteEventLog(EVENTLOG_INFORMATION_TYPE, stats_msg);

                // Request driver status
                CS_STATUS_REPLY_PAYLOAD driver_status = {}; // Use shared structure
                // The RequestStatus signature is bool RequestStatus(CS_STATUS_REPLY_PAYLOAD& status_reply_data)
                // The call communication_manager->RequestStatus(driver_status) is correct.
                // However, RequestStatus in CommunicationManager.cpp needs to be updated
                // to call the new SendMessage signature correctly. Assuming that fix for now.
                if (communication_manager->RequestStatus(driver_status)) {
                    std::wstring driver_msg = L"Driver status - Monitoring: " +
                        std::wstring((driver_status.CurrentConfigFlags & CONFIG_FLAG_MONITORING_ENABLED) ? L"Enabled" : L"Disabled") +
                        L", Sensitivity: " + std::to_wstring(driver_status.CurrentDetectionSensitivity) +
                        L", Driver total operations monitored: " + std::to_wstring(driver_status.TotalOperationsMonitored) +
                        L", Kernel messages sent: " + std::to_wstring(driver_status.KernelMessagesSent) +
                        L", Kernel messages received: " + std::to_wstring(driver_status.KernelMessagesReceived);
                    WriteEventLog(EVENTLOG_INFORMATION_TYPE, driver_msg);
                } else {
                    WriteEventLog(EVENTLOG_WARNING_TYPE, L"Failed to retrieve driver status.");
                }

                last_stats_time = current_time;
            }
        }

        // Sleep to prevent CPU spinning
        Sleep(100);
    }

    // Cleanup
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"Service worker thread stopping");

    // Stop message processing
    message_processor->Stop();

    // Send shutdown request to driver
    communication_manager->RequestShutdown();

    // Disconnect from driver
    communication_manager->Shutdown();

    // Log final statistics
    auto final_stats = message_processor->GetStatistics();
    std::wstring final_msg = L"Final statistics - Total operations processed: " +
        std::to_wstring(final_stats.total_operations);
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, final_msg);

    return ERROR_SUCCESS;
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
        if (status.dwCurrentState != SERVICE_STOPPED) {
            ControlService(service, SERVICE_CONTROL_STOP, &status);
            Sleep(1000);
        }
    }

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