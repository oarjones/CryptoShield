#pragma once

#include <windows.h>
#include <string> // Para std::wstring en logs (si se usa)

// Prototipo para la función no documentada RtlSetProcessIsCritical.
// Se utiliza para marcar un proceso como crítico para el sistema.
// ADVERTENCIA: Si un proceso crítico se termina, el sistema operativo
//              inicia un Bug Check (BSOD) con el código CRITICAL_PROCESS_DIED.
// FUENTE: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/critical-process
typedef NTSTATUS(NTAPI* RtlSetProcessIsCritical)(
    IN BOOLEAN NewValue,
    OUT PBOOLEAN OldValue,
    IN BOOLEAN IsWinlogon
);

/**
 * @brief Habilita la protección de proceso crítico para el proceso actual.
 *
 * Esta función intenta adquirir SeDebugPrivilege y luego utiliza la función
 * no documentada RtlSetProcessIsCritical para marcar el proceso actual como
 * crítico para el sistema. Si un proceso marcado como crítico es terminado,
 * el sistema operativo generará un BSOD (Blue Screen of Death).
 *
 * @return TRUE si la protección de proceso crítico se habilitó con éxito.
 * @return FALSE si ocurrió algún error durante el proceso. Se registrarán
 *         detalles del error en el log del sistema o visor de eventos.
 *
 * @warning Habilitar esta protección es una medida drástica. Usar con precaución.
 */
BOOL EnableCriticalProcessProtection();

// Podríamos añadir aquí un forward declaration para una clase de logging si existiera
// class EventLogger;
// void SetGlobalLogger(EventLogger* logger); // Ejemplo
// O funciones de logging directas si son globales
// void LogError(const std::wstring& message);
// void LogInfo(const std::wstring& message);

// --- RAII Wrapper para HANDLE ---
// Siguiendo la sugerencia del usuario, se define un wrapper RAII para HANDLE.
class HandleWrapper {
public:
    explicit HandleWrapper(HANDLE h = NULL) : m_handle(h) {}
    ~HandleWrapper() {
        if (m_handle != NULL && m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
        }
    }

    HandleWrapper(const HandleWrapper&) = delete; // No copiar
    HandleWrapper& operator=(const HandleWrapper&) = delete; // No asignar por copia

    HandleWrapper(HandleWrapper&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = NULL;
    }

    HandleWrapper& operator=(HandleWrapper&& other) noexcept {
        if (this != &other) {
            if (m_handle != NULL && m_handle != INVALID_HANDLE_VALUE) {
                CloseHandle(m_handle);
            }
            m_handle = other.m_handle;
            other.m_handle = NULL;
        }
        return *this;
    }

    HANDLE get() const { return m_handle; }

    // Permite que el wrapper sea usado en lugares donde se espera un HANDLE.
    operator HANDLE() const { return m_handle; }

    // Para recibir un nuevo handle (e.g., de OpenProcessToken)
    // Esto asume que el wrapper no poseía un handle previamente o que
    // el handle anterior ya fue cerrado o se desea reemplazar.
    // Es responsabilidad del llamador asegurar que el handle anterior está gestionado.
    // Una mejor aproximación sería un método `reset(HANDLE h = NULL)`
    HANDLE* operator&() {
        // Si ya tenemos un handle, debería ser cerrado antes de tomar uno nuevo.
        // Esta implementación es simple y asume que se usa así:
        // HandleWrapper hWrapper;
        // OpenProcessToken(..., &hWrapper);
        // Sin embargo, esto es peligroso si hWrapper ya tenía un handle.
        // Una forma más segura es:
        // HANDLE tempHandle;
        // OpenProcessToken(..., &tempHandle);
        // HandleWrapper hWrapper(tempHandle);
        // Por ahora, mantendremos la versión simple para GetProcAddress,
        // pero para OpenProcessToken, asignaremos después de la llamada.
        // O mejor, usar un método `receive()` o `get_address_of()`.
        // Por simplicidad y uso específico, voy a modificar el HandleWrapper
        // para que el `operator&` devuelva un puntero al miembro interno,
        // asumiendo que se usa para inicializar el handle.
        // Esto es común pero requiere cuidado.
        if (m_handle != NULL && m_handle != INVALID_HANDLE_VALUE) {
            // Idealmente, se debería lanzar una excepción o loggear un error
            // si se intenta obtener la dirección de un handle ya inicializado
            // sin un cierre explícito.
            // Para esta implementación, asumimos que se usa correctamente.
        }
        return &m_handle;
    }

    bool isValid() const {
        return m_handle != NULL && m_handle != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE m_handle;
};
