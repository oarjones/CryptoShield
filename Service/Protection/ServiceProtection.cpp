#include "ServiceProtection.h"
#include "../ServiceLogging.h" // Incluir para WriteEventLog
#include <vector>
#include <windows.h>
#include <sstream> // Para std::wstringstream

// Helper para formatear mensajes de error con GetLastError()
static std::wstring FormatWinError(const std::wstring& customMessage, DWORD errorCode) {
    LPVOID lpMsgBuf = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpMsgBuf,
        0, NULL);

    std::wstringstream ss;
    ss << customMessage;
    if (lpMsgBuf) {
        ss << L" - Código de error: " << errorCode << L". Mensaje: " << (LPWSTR)lpMsgBuf;
        LocalFree(lpMsgBuf);
    } else {
        ss << L" - Código de error: " << errorCode << L". (No se pudo obtener el mensaje de error)";
    }
    return ss.str();
}


/**
 * @brief Habilita un privilegio específico para el token del proceso actual.
 *
 * @param privilegeName El nombre del privilegio a habilitar (e.g., SE_DEBUG_NAME).
 * @return TRUE si el privilegio se habilitó con éxito, FALSE en caso contrario.
 */
BOOL SetRequiredPrivileges(LPCTSTR privilegeName) {
    HANDLE hTokenRaw = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTokenRaw)) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, FormatWinError(L"SetRequiredPrivileges: OpenProcessToken failed", GetLastError()));
        return FALSE;
    }
    HandleWrapper hToken(hTokenRaw); // RAII wrapper

    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, FormatWinError(L"SetRequiredPrivileges: LookupPrivilegeValue failed for " + std::wstring(privilegeName), GetLastError()));
        return FALSE; // hToken se cierra automáticamente por RAII
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken.get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, FormatWinError(L"SetRequiredPrivileges: AdjustTokenPrivileges failed to enable " + std::wstring(privilegeName), GetLastError()));
        return FALSE; // hToken se cierra automáticamente por RAII
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, FormatWinError(L"SetRequiredPrivileges: The token does not have the required privilege: " + std::wstring(privilegeName), ERROR_NOT_ALL_ASSIGNED));
        return FALSE; // hToken se cierra automáticamente por RAII
    }

    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"SetRequiredPrivileges: Privilege " + std::wstring(privilegeName) + L" enabled successfully.");
    return TRUE; // hToken se cierra automáticamente por RAII
}

BOOL EnableCriticalProcessProtection() {
    // 1. Obtener privilegios necesarios
    // SE_DEBUG_NAME para RtlSetProcessIsCritical
    // SE_SHUTDOWN_NAME para InitiateSystemShutdownExW (usado por el Watchdog)
    // Es mejor obtener todos los privilegios necesarios al inicio.

    bool allPrivilegesObtained = true;
    if (!SetRequiredPrivileges(SE_DEBUG_NAME)) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, L"EnableCriticalProcessProtection: Failed to acquire SE_DEBUG_NAME. Critical process protection cannot be enabled.");
        allPrivilegesObtained = false;
        // No retornamos inmediatamente, intentaremos obtener SE_SHUTDOWN_NAME si es posible.
    } else {
        WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"EnableCriticalProcessProtection: SE_DEBUG_NAME acquired successfully.");
    }

    if (!SetRequiredPrivileges(SE_SHUTDOWN_NAME)) {
        WriteEventLog(EVENTLOG_WARNING_TYPE, L"EnableCriticalProcessProtection: Failed to acquire SE_SHUTDOWN_NAME. System reboot capability by Watchdog will be disabled.");
        // No consideramos esto un fallo fatal para EnableCriticalProcessProtection en sí mismo,
        // pero es una degradación de la funcionalidad del Watchdog.
        // allPrivilegesObtained podría usarse si quisiéramos ser más estrictos.
    } else {
        WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"EnableCriticalProcessProtection: SE_SHUTDOWN_NAME acquired successfully for Watchdog.");
    }

    if (!allPrivilegesObtained) { // Específicamente si SE_DEBUG_NAME falló
         WriteEventLog(EVENTLOG_ERROR_TYPE, L"EnableCriticalProcessProtection: Not all essential privileges acquired (SE_DEBUG_NAME). Cannot mark process as critical.");
        return FALSE; // Fallo si SE_DEBUG_NAME no se pudo obtener.
    }

    // 2. Obtener la dirección de RtlSetProcessIsCritical
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, FormatWinError(L"EnableCriticalProcessProtection: GetModuleHandleW(\"ntdll.dll\") failed", GetLastError()));
        return FALSE;
    }
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"EnableCriticalProcessProtection: Handle to ntdll.dll obtained.");

    RtlSetProcessIsCritical pRtlSetProcessIsCritical = (RtlSetProcessIsCritical)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
    if (pRtlSetProcessIsCritical == NULL) {
        WriteEventLog(EVENTLOG_ERROR_TYPE, FormatWinError(L"EnableCriticalProcessProtection: GetProcAddress(\"RtlSetProcessIsCritical\") failed", GetLastError()));
        return FALSE;
    }
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"EnableCriticalProcessProtection: Address of RtlSetProcessIsCritical obtained.");

    // 3. Invocar RtlSetProcessIsCritical
    // Parámetros:
    //   NewValue: TRUE para marcar como crítico, FALSE para desmarcar.
    //   OldValue: Puntero opcional a un BOOLEAN que recibe el estado anterior. NULL si no se necesita.
    //   IsWinlogon: Debe ser FALSE para procesos que no son Winlogon.
    NTSTATUS status = pRtlSetProcessIsCritical(TRUE, NULL, FALSE);

    // 4. Verificar el resultado
    // NT_SUCCESS(status) es la macro correcta para verificar NTSTATUS.
    // STATUS_SUCCESS es 0.
    if (status != 0) { // 0 es STATUS_SUCCESS
        std::wstringstream ss;
        ss << L"EnableCriticalProcessProtection: RtlSetProcessIsCritical failed with NTSTATUS: 0x" << std::hex << static_cast<unsigned long>(status);
        WriteEventLog(EVENTLOG_ERROR_TYPE, ss.str());
        return FALSE;
    }

    WriteEventLog(EVENTLOG_INFORMATION_TYPE, L"EnableCriticalProcessProtection: Process marked as critical successfully. The system will generate a BSOD if this process terminates unexpectedly.");
    return TRUE;
}

// Ejemplo de cómo se podría integrar un logger más formal si estuviera disponible:
/*
#include "EventLogger.h" // Suponiendo que existe esta clase

EventLogger* g_eventLogger = nullptr; // Global o gestionado de otra forma

void InitializeLogging(EventLogger* logger) {
    g_eventLogger = logger;
}

// En ServiceMain, antes de cualquier otra cosa:
// EventLogger actualLogger("CryptoShieldService");
// InitializeLogging(&actualLogger);
// ... luego las llamadas a EnableCriticalProcessProtection usarían g_eventLogger.

// Y las funciones de log se verían así:
// void LogErrorDetailed(const std::wstring& functionName, const std::wstring& message, DWORD errorCode = 0) {
//     if (g_eventLogger) {
//         std::wstring fullMsg = functionName + L": " + message;
//         if (errorCode != 0) {
//             // ... (código para convertir errorCode a mensaje de error) ...
//             fullMsg += L" (Error: " + std::to_wstring(errorCode) + L")";
//         }
//         g_eventLogger->LogError(fullMsg); // Suponiendo un método LogError
//     } else {
//         // Fallback a std::wcerr o similar si es necesario durante desarrollo temprano
//         std::wcerr << L"[ERROR] " << fullMsg << std::endl;
//     }
// }
*/
