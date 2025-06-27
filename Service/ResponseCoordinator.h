#pragma once

#include "Protection/WindowsSecurityCenterIntegration.h" // Ajustado a la ruta correcta
#include "Common/Shared.h" // Para CS_TAMPER_ALERT_PAYLOAD

// Forward declaration para evitar dependencia circular si Main.cpp incluye ResponseCoordinator.h
// y ResponseCoordinator.cpp necesita WriteEventLog de Main.cpp.
// Sin embargo, WriteEventLog es una función global/estática en Main.cpp y no debería causar este problema
// si se declara adecuadamente (e.g. en un header de utilidades o extern).
// Por ahora, asumimos que WriteEventLog estará accesible.

class ResponseCoordinator {
public:
    explicit ResponseCoordinator(WindowsSecurityCenterIntegration& wsc_integration);

    /**
     * @brief Maneja una alerta crítica de manipulación del sistema.
     * @details Esta función orquesta la respuesta a una detección de manipulación (tampering)
     *          confirmada a nivel del kernel o del servicio. La secuencia de acciones está
     *          diseñada para proteger el sistema y alertar al usuario de manera efectiva.
     *          Acciones:
     *          1. Registra un evento crítico en el Visor de Eventos de Windows.
     *          2. Actualiza el estado del producto de seguridad en el Centro de Seguridad de Windows (WSC)
     *             a 'Snoozed' (Pospropuesto), lo que generalmente indica que el producto ha sido
     *             deshabilitado temporalmente debido a una amenaza o problema.
     *          3. Inicia un reinicio forzado del sistema si la manipulación afecta componentes críticos
     *             como el driver, ya que esta es la única forma segura de intentar una autorreparación.
     * @param alert El payload de la alerta de manipulación.
     */
    void HandleCriticalTamperAlert(const CS_TAMPER_ALERT_PAYLOAD& alert);

private:
    WindowsSecurityCenterIntegration& m_wsc_integration;
    // Podríamos añadir un logger aquí si es necesario, o pasar una referencia a un logger global.
};
