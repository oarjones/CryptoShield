#include "WindowsSecurityIntegration.h"
#include <comdef.h> // Para _com_error y mensajes HRESULT
#include <vector>   // Para std::vector en GetProductExePath
#include <windows.h> // Para GetModuleFileNameW, CoInitializeEx, etc.
#include <iostream> // Temporal para logging, reemplazar con el logger del proyecto

// Helper para logging (asumiré una función de log global o macro)
// Esto debería ser reemplazado por el mecanismo de logging real del proyecto.
#ifndef LOG_ERROR
#define LOG_ERROR(msg, hr) std::wcerr << L"ERROR: " << msg << L", HRESULT: 0x" << std::hex << hr << std::dec << std::endl;
#endif
#ifndef LOG_WARN
#define LOG_WARN(msg, hr) std::wcerr << L"WARN: " << msg << L", HRESULT: 0x" << std::hex << hr << std::dec << std::endl;
#endif
#ifndef LOG_INFO
#define LOG_INFO(msg) std::wcout << L"INFO: " << msg << std::endl;
#endif


WindowsSecurityCenterIntegration::WindowsSecurityCenterIntegration()
    : m_comInitialized(false), m_registered(false), m_pLocator(nullptr), m_pServices(nullptr) {
    HRESULT hr = InitializeCOM();
    if (FAILED(hr)) {
        LOG_ERROR(L"Error al inicializar COM y WMI en el constructor.", hr);
        // El objeto se crea, pero estará en un estado no funcional.
        // Las llamadas a Register/UpdateState/Unregister deberían fallar limpiamente.
    }
}

WindowsSecurityCenterIntegration::~WindowsSecurityCenterIntegration() {
    if (m_registered && m_pServices) { // Solo desregistrar si estaba registrado y tenemos conexión
        Unregister(); // Intentar desregistrar si es necesario
    }

    // CComPtr se encarga de m_pLocator y m_pServices Release()

    if (m_comInitialized) {
        CoUninitialize();
        m_comInitialized = false;
    }
}

HRESULT WindowsSecurityCenterIntegration::InitializeCOM() {
    if (m_comInitialized) {
        // Podríamos reconectar a WMI si m_pServices es nulo pero COM está inicializado.
        // Por ahora, si COM está inicializado, asumimos que ConnectToWMI también fue exitoso o falló y se logueó.
        if (m_pServices) return S_OK; // Ya inicializado y conectado
        // Si COM está inicializado pero no m_pServices, intentar conectar de nuevo.
        // Esto podría pasar si ConnectToWMI falló pero CoInitializeSecurity tuvo éxito.
        LOG_INFO(L"COM ya inicializado, intentando conectar a WMI...");
        return ConnectToWMI();
    }

    // Inicializar COM para este hilo
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        LOG_ERROR(L"CoInitializeEx falló.", hr);
        return hr;
    }
    m_comInitialized = true;
    LOG_INFO(L"COM inicializado exitosamente (COINIT_MULTITHREADED).");

    // Establecer seguridad a nivel de proceso. Esto es crucial para servicios.
    // Permite al servicio realizar llamadas WMI que requieren ciertos niveles de autenticación/impersonación.
    // RPC_C_AUTHN_LEVEL_DEFAULT: Usa el nivel de autenticación predeterminado del servicio. (Para servicios, esto a menudo es Negotiate o Kerberos).
    // RPC_C_IMP_LEVEL_IMPERSONATE: Permite a WMI realizar tareas en nombre del cliente (nuestro servicio).
    hr = CoInitializeSecurity(
        NULL,
        -1,                          // COM elige qué servicios de autenticación registrar
        NULL,                        // Servicios de autenticación
        NULL,                        // Reservado
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, // Nivel de autenticación. PKT_PRIVACY es más seguro para servicios. DEFAULT podría ser suficiente.
        RPC_C_IMP_LEVEL_IMPERSONATE, // Nivel de impersonación predeterminado
        NULL,                        // Lista de autenticación
        EOAC_NONE,                   // Capacidades adicionales de autenticación (sin cloaking, sin llamadas a appartment)
        NULL                         // Reservado
    );

    if (FAILED(hr)) {
        LOG_ERROR(L"CoInitializeSecurity falló. WMI no funcionará correctamente.", hr);
        // No desinicializar COM aquí, pero WMI fallará. El destructor se encargará de CoUninitialize.
        return hr;
    }
    LOG_INFO(L"CoInitializeSecurity exitoso.");

    return ConnectToWMI();
}

HRESULT WindowsSecurityCenterIntegration::ConnectToWMI() {
    if(m_pServices) { // Ya conectado
        return S_OK;
    }

    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER, // Crear el localizador en el mismo proceso.
        IID_IWbemLocator, (LPVOID*)&m_pLocator);

    if (FAILED(hr)) {
        LOG_ERROR(L"No se pudo crear la instancia de IWbemLocator.", hr);
        return hr;
    }
    LOG_INFO(L"IWbemLocator creado exitosamente.");

    // Conectarse a WMI a través del namespace ROOT\SecurityCenter2
    CComBSTR ns = L"ROOT\\SecurityCenter2";
    hr = m_pLocator->ConnectServer(
        ns,      // Namespace WMI
        NULL,    // Usuario (NULL para usuario actual del proceso/hilo)
        NULL,    // Contraseña (NULL para usuario actual)
        0,       // Locale (0 para actual)
        NULL,    // Security flags (0 para default)
        0,       // Authority (0 para default)
        0,       // Context object (NULL)
        &m_pServices // Recibe el puntero a IWbemServices
    );

    if (FAILED(hr)) {
        LOG_ERROR(L"No se pudo conectar al namespace ROOT\\SecurityCenter2 de WMI.", hr);
        m_pLocator.Release(); // Liberar locator si la conexión falla
        return hr;
    }
    LOG_INFO(L"Conectado a WMI ROOT\\SecurityCenter2 exitosamente.");

    // Establecer seguridad en el proxy m_pServices.
    // Esto permite que WMI use la identidad del servicio para realizar operaciones.
    // Es necesario para que el servicio WMI pueda actuar en nombre de nuestro proceso de servicio.
    // RPC_C_AUTHN_LEVEL_CALL: Autenticación por llamada. Podría ser PKT_PRIVACY para mayor seguridad.
    hr = CoSetProxyBlanket(
        m_pServices,                 // El proxy a establecer (interfaz IWbemServices)
        RPC_C_AUTHN_WINNT,           // Servicio de autenticación (NTLM). Default es una buena opción también.
        RPC_C_AUTHZ_NONE,            // Servicio de autorización (ninguno)
        NULL,                        // Nombre principal del servidor (NULL)
        RPC_C_AUTHN_LEVEL_CALL,      // Nivel de autenticación (por llamada). PKT_PRIVACY si se necesita cifrado.
        RPC_C_IMP_LEVEL_IMPERSONATE, // Nivel de impersonación
        NULL,                        // Información de identidad del cliente (NULL para proceso actual)
        EOAC_NONE                    // Capacidades adicionales (sin cloaking)
    );

    if (FAILED(hr)) {
        LOG_ERROR(L"No se pudo establecer la seguridad del proxy (CoSetProxyBlanket).", hr);
        m_pServices.Release(); // Liberar servicios si falla CoSetProxyBlanket
        m_pLocator.Release();
        return hr;
    }
    LOG_INFO(L"CoSetProxyBlanket en m_pServices exitoso.");
    return S_OK;
}

std::wstring WindowsSecurityCenterIntegration::GetProductExePath() const {
    std::vector<wchar_t> pathBuf;
    DWORD pathLen = 0;

    // Empezar con un tamaño razonable y aumentar si es necesario.
    // MAX_PATH es a menudo 260, pero las rutas pueden ser más largas.
    DWORD bufferSize = MAX_PATH;
    pathBuf.resize(bufferSize);

    while (true) {
        pathLen = GetModuleFileNameW(NULL, pathBuf.data(), bufferSize);
        if (pathLen == 0) { // Falló GetModuleFileNameW
            LOG_ERROR(L"GetModuleFileNameW falló.", GetLastError());
            return L"";
        }
        if (pathLen < bufferSize) { // El buffer fue suficiente
            pathBuf.resize(pathLen); // Ajustar al tamaño real
            return std::wstring(pathBuf.begin(), pathBuf.end());
        }
        // El buffer era demasiado pequeño, duplicar el tamaño y reintentar.
        bufferSize *= 2;
        pathBuf.resize(bufferSize);
    }
}

HRESULT WindowsSecurityCenterIntegration::Register() {
    if (!m_pServices) {
        LOG_ERROR(L"Intento de registrar sin conexión WMI válida (m_pServices es nulo).", E_POINTER);
        return E_POINTER; // O intentar reconectar: InitializeCOM(); if (!m_pServices) return E_FAIL;
    }
    if (m_registered) {
        LOG_INFO(L"Producto ya marcado como registrado por esta instancia.");
        // Podríamos verificar si realmente existe en WSC y si no, proceder.
        // Por ahora, si m_registered es true, asumimos que está bien.
        return S_FALSE;
    }

    std::wstring productExePath = GetProductExePath();
    if (productExePath.empty()) {
        LOG_ERROR(L"No se pudo obtener la ruta del ejecutable del producto para el registro.", E_FAIL);
        return E_FAIL;
    }

    CComPtr<IWbemClassObject> pAntiVirusProductClass = nullptr;
    CComBSTR className = L"AntiVirusProduct";
    HRESULT hr = m_pServices->GetObject(className, 0, NULL, &pAntiVirusProductClass, NULL);
    if (FAILED(hr)) {
        LOG_ERROR(L"GetObject para la clase AntiVirusProduct falló.", hr);
        return hr;
    }
    LOG_INFO(L"Clase AntiVirusProduct obtenida.");

    CComPtr<IWbemClassObject> pNewInstance = nullptr;
    hr = pAntiVirusProductClass->SpawnInstance(0, &pNewInstance);
    if (FAILED(hr)) {
        LOG_ERROR(L"SpawnInstance para AntiVirusProduct falló.", hr);
        return hr;
    }
    LOG_INFO(L"Nueva instancia de AntiVirusProduct creada (spawned).");

    // Rellenar las propiedades de la instancia
    CComVariant varDisplayName(L"CryptoShield Anti-Ransomware");
    hr = pNewInstance->Put(L"displayName", 0, &varDisplayName, CIM_STRING);
    if (FAILED(hr)) { LOG_ERROR(L"Put para displayName falló.", hr); return hr; }

    CComVariant varInstanceGuid(m_instanceGuid.c_str());
    hr = pNewInstance->Put(L"instanceGuid", 0, &varInstanceGuid, CIM_STRING);
    if (FAILED(hr)) { LOG_ERROR(L"Put para instanceGuid falló.", hr); return hr; }

    CComVariant varPathToExe(productExePath.c_str());
    hr = pNewInstance->Put(L"pathToSignedProductExe", 0, &varPathToExe, CIM_STRING);
    if (FAILED(hr)) { LOG_ERROR(L"Put para pathToSignedProductExe falló.", hr); return hr; }

    // El estado inicial al registrar será "ON".
    // WSC_SECURITY_PRODUCT_STATE_ON (0) se mapea a 1 para WMI.
    CComVariant varProductState((ULONG)1); // 1 es ON para WMI productState
    hr = pNewInstance->Put(L"productState", 0, &varProductState, CIM_UINT32);
    if (FAILED(hr)) { LOG_ERROR(L"Put para productState inicial (ON) falló.", hr); return hr; }
    LOG_INFO(L"Propiedades de la nueva instancia establecidas.");

    // Guardar la nueva instancia en WMI
    hr = m_pServices->PutInstance(pNewInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    if (FAILED(hr)) {
        _com_error err(hr);
        LOG_ERROR(L"PutInstance para registrar AntiVirusProduct falló.", hr);
        LOG_ERROR(err.ErrorMessage(), hr);
        return hr;
    }

    LOG_INFO(L"CryptoShield registrado exitosamente en WSC.");
    m_registered = true;
    return S_OK;
}

HRESULT WindowsSecurityCenterIntegration::UpdateState(WSC_SECURITY_PRODUCT_STATE state) {
    if (!m_pServices) {
        LOG_ERROR(L"Intento de actualizar estado sin conexión WMI (m_pServices es nulo).", E_POINTER);
        return E_POINTER;
    }

    DWORD wmiProductStateValue;
    switch (state) {
        case WSC_SECURITY_PRODUCT_STATE_ON:
            wmiProductStateValue = 1; // WMI: ON
            break;
        case WSC_SECURITY_PRODUCT_STATE_OFF:
            wmiProductStateValue = 0; // WMI: OFF
            break;
        case WSC_SECURITY_PRODUCT_STATE_SNOOZED:
            wmiProductStateValue = 2; // WMI: SNOOZED
            break;
        case WSC_SECURITY_PRODUCT_STATE_EXPIRED:
            wmiProductStateValue = 3; // WMI: EXPIRED
            break;
        default:
            LOG_ERROR(L"Estado WSC_SECURITY_PRODUCT_STATE desconocido.", E_INVALIDARG);
            return E_INVALIDARG;
    }

    std::wstring wmiPath = L"AntiVirusProduct.instanceGuid='";
    wmiPath += m_instanceGuid;
    wmiPath += L"'";
    CComBSTR bstrWmiPath(wmiPath.c_str());

    CComPtr<IWbemClassObject> pInstance = nullptr;
    // Primero, obtener la instancia existente.
    // Usamos WBEM_FLAG_DIRECT_READ para obtener la instancia directamente del proveedor sin pasar por cachés.
    HRESULT hr = m_pServices->GetObject(bstrWmiPath, WBEM_FLAG_DIRECT_READ, NULL, &pInstance, NULL);
    if (FAILED(hr)) {
        LOG_ERROR(L"GetObject para la instancia específica de AntiVirusProduct falló al actualizar estado.", hr);
        _com_error err(hr);
        LOG_ERROR(err.ErrorMessage(), hr);
        // Si no se encuentra, no podemos actualizarlo. Podría significar que no está registrado.
        if (hr == WBEM_E_NOT_FOUND) m_registered = false;
        return hr;
    }
    LOG_INFO(L"Instancia existente de AntiVirusProduct obtenida para actualización.");

    CComVariant varWmiProductState(wmiProductStateValue);
    hr = pInstance->Put(L"productState", 0, &varWmiProductState, CIM_UINT32);
    if (FAILED(hr)) {
        LOG_ERROR(L"Put para productState en UpdateState falló.", hr);
        return hr;
    }

    // Guardar la instancia actualizada.
    // WBEM_FLAG_UPDATE_ONLY asegura que solo se actualice si existe.
    hr = m_pServices->PutInstance(pInstance, WBEM_FLAG_UPDATE_ONLY, NULL, NULL);
    if (FAILED(hr)) {
        LOG_ERROR(L"PutInstance para actualizar productState falló.", hr);
        _com_error err(hr);
        LOG_ERROR(err.ErrorMessage(), hr);
        return hr;
    }

    LOG_INFO(L"Estado de CryptoShield actualizado en WSC.");
    m_registered = true; // Asegurar que m_registered sea true si la actualización tuvo éxito.
    return S_OK;
}

HRESULT WindowsSecurityCenterIntegration::Unregister() {
    if (!m_pServices) {
        LOG_WARN(L"Intento de desregistrar sin conexión WMI (m_pServices es nulo).", E_POINTER);
        return E_POINTER;
    }

    std::wstring wmiPath = L"AntiVirusProduct.instanceGuid='";
    wmiPath += m_instanceGuid;
    wmiPath += L"'";
    CComBSTR bstrWmiPath(wmiPath.c_str());

    // Intentar eliminar la instancia.
    // No se necesitan flags especiales, pero se puede usar 0.
    HRESULT hr = m_pServices->DeleteInstance(bstrWmiPath, 0, NULL, NULL);
    if (FAILED(hr)) {
        if (hr == WBEM_E_NOT_FOUND) {
            LOG_INFO(L"Intento de desregistrar AntiVirusProduct, pero no se encontró (probablemente ya desregistrado).");
            m_registered = false; // Asegurar que esté marcado como no registrado.
            return S_OK; // No es un error si el objetivo es que no exista.
        } else {
            _com_error err(hr);
            LOG_ERROR(L"DeleteInstance para AntiVirusProduct falló.", hr);
            LOG_ERROR(err.ErrorMessage(), hr);
            return hr; // Devolver el error para otros fallos.
        }
    } else {
        LOG_INFO(L"CryptoShield desregistrado exitosamente de WSC.");
    }

    m_registered = false;
    return S_OK;
}
