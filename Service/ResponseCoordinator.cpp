#include "ResponseCoordinator.h"
#include "ServiceLogging.h" // Para WriteEventLog (asumiendo que está allí o accesible globalmente)
#include <windows.h> // Para InitiateSystemShutdownExW y otros
#include <string>
#include <sstream> // Para std::wstringstream

// Prototipo de WriteEventLog si no está en un header común y se define en Main.cpp
// Es mejor mover WriteEventLog a un header de utilidades o a ServiceLogging.h si es apropiado.
// extern void WriteEventLog(WORD wType, DWORD dwEventID, const std::wstring& message);
// Por el momento, se asume que ServiceLogging.h lo declara.


ResponseCoordinator::ResponseCoordinator(WindowsSecurityCenterIntegration& wsc_integration)
    : m_wsc_integration(wsc_integration) {
    // Constructor
}

void ResponseCoordinator::HandleCriticalTamperAlert(const CS_TAMPER_ALERT_PAYLOAD& alert) {
    // Paso 1: Registrar Evento Crítico
    std::wstringstream event_message;
    event_message << L"¡ALERTA DE SEGURIDAD CRÍTICA! Se ha detectado una manipulación del driver CryptoShield (Tipo: "
                  << alert.TamperType
                  << L"). Se tomarán medidas de protección drásticas.";

    // El EVENTLOG_ERROR_TYPE es correcto.
    // La función WriteEventLog actual no toma un ID de evento específico,
    // así que la información del tipo de manipulación está en el mensaje.
    WriteEventLog(EVENTLOG_ERROR_TYPE, event_message.str());


    // Paso 2: Actualizar Estado en WSC
    // WSC_SECURITY_PRODUCT_STATE_SNOOZED indica que el producto está temporalmente inactivo.
    HRESULT hr = m_wsc_integration.UpdateState(WSC_SECURITY_PRODUCT_STATE_SNOOZED);
    if (FAILED(hr)) {
        std::wstringstream error_msg_wsc; // Renombrado para evitar colisión
        error_msg_wsc << L"ResponseCoordinator: Error al actualizar el estado en WSC. HRESULT: 0x" << std::hex << hr;
        WriteEventLog(EVENTLOG_WARNING_TYPE, error_msg_wsc.str()); // Log como warning
    }

    // Paso 3: Acción de Autorreparación (Reinicio Forzado)
    // Basado en alert.TamperType, decidir si el reinicio es necesario.
    // Por ahora, asumimos que cualquier alerta de manipulación del kernel requiere reinicio.
    // Los TamperType específicos podrían ser:
    // 1: TAMPER_TYPE_CALLBACK_TABLE_MODIFIED
    // 2: TAMPER_TYPE_DRIVER_MEMORY_MODIFIED
    // 3: TAMPER_TYPE_SSDT_HOOK_DETECTED
    // Todos estos son críticos y justifican un reinicio.

    if (alert.TamperType > 0) { // Asumiendo que cualquier tipo de manipulación del driver es crítico
        std::wstring shutdown_message = L"CryptoShield: Se ha detectado una manipulación crítica en los componentes de seguridad. El sistema se reiniciará en 60 segundos para garantizar su protección.";

        // SHTDN_REASON_FLAG_PLANNED debería usarse si el usuario lo planeó.
        // Para un evento de seguridad, es mejor usar SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_SECURITY.
        // El prompt original usa SHTDN_REASON_FLAG_PLANNED, lo cual es un poco contradictorio con la naturaleza "no planeada" de una alerta.
        // Sin embargo, seguiré el prompt.
        DWORD shutdown_reason = SHTDN_REASON_FLAG_MAJOR_OPERATINGSYSTEM |
                                SHTDN_REASON_FLAG_MINOR_SECURITY |
                                SHTDN_REASON_FLAG_PLANNED;

        if (!InitiateSystemShutdownExW(
            NULL,                   // Nombre del equipo (NULL para el local)
            (LPWSTR)shutdown_message.c_str(), // Mensaje a mostrar
            60,                     // Tiempo de espera en segundos
            TRUE,                   // Forzar cierre de aplicaciones
            TRUE,                   // Reiniciar (vs apagar)
            shutdown_reason         // Razón del apagado/reinicio
        )) {
            DWORD error_code = GetLastError();
            std::wstringstream error_msg_shutdown;
            error_msg_shutdown << L"ResponseCoordinator: Error al iniciar el reinicio del sistema. Código de error: " << error_code;
            // Loggear este error crítico
            WriteEventLog(EVENTLOG_ERROR_TYPE, error_msg_shutdown.str());
        } else {
            std::wstringstream success_msg_shutdown;
            success_msg_shutdown << L"ResponseCoordinator: Reinicio del sistema iniciado debido a alerta de manipulación (Tipo: " << alert.TamperType << L").";
            WriteEventLog(EVENTLOG_INFORMATION_TYPE, success_msg_shutdown.str());
        }
    }
}
