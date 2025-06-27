#include "AMSIProvider.h"
#include <atomic> // Para std::atomic si se usa, o InterlockedIncrement/Decrement para m_refCount
#include <vector>
#include <string>
#include <Shlwapi.h> // Para StrCmpNIW si es necesario, aunque std::wstring::compare es más C++

// Variables globales para el servidor COM (simplificado)
extern long g_dll_lock_count_; // Contador de bloqueos de la DLL
extern HMODULE g_hModule;   // Handle del módulo DLL

// Implementación de CryptoShieldAMSIProvider
CryptoShieldAMSIProvider::CryptoShieldAMSIProvider() : m_ref_count_(1) { // Inicializar m_ref_count_
    InterlockedIncrement(&g_dll_lock_count_);
    // Inicialización, si es necesaria
}

CryptoShieldAMSIProvider::~CryptoShieldAMSIProvider() {
    InterlockedDecrement(&g_dll_lock_count_);
    // Limpieza, si es necesaria
}

// Métodos de IUnknown
STDMETHODIMP CryptoShieldAMSIProvider::QueryInterface(REFIID riid, void **ppvObject) {
    if (!ppvObject) {
        return E_POINTER;
    }
    *ppvObject = nullptr;

    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IAmsiProvider)) {
        *ppvObject = static_cast<IAmsiProvider *>(this);
        AddRef();
        return S_OK;
    }
    // Si se implementaran otras interfaces, se comprobarían aquí.

    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) CryptoShieldAMSIProvider::AddRef() {
    return InterlockedIncrement(&m_ref_count_);
}

STDMETHODIMP_(ULONG) CryptoShieldAMSIProvider::Release() {
    ULONG count = InterlockedDecrement(&m_ref_count_);
    if (count == 0) {
        delete this;
    }
    return count;
}

// Métodos de IAmsiProvider
STDMETHODIMP CryptoShieldAMSIProvider::Scan(IAmsiStream *stream, AMSI_RESULT *result) {
    if (!result) {
        return E_POINTER;
    }
    *result = AMSI_RESULT_NOT_DETECTED; // Valor predeterminado de seguridad

    if (!stream) {
        // Aunque AMSI podría no enviar un stream nulo, es buena práctica verificarlo.
        // Si el stream es nulo, no hay nada que escanear.
        return S_OK;
    }

    // Leer el contenido del IAmsiStream en un búfer.
    // El stream puede ser grande, así que léelo en fragmentos.
    std::vector<unsigned char> content_buffer;
    ULONG bytes_read = 0;
    HRESULT hr = S_OK;

    // Determinar el tamaño total del contenido si está disponible.
    // Esto puede ayudar a preasignar memoria, pero no es obligatorio por la interfaz.
    // ULONGLONG total_size = 0;
    // ULONG content_size_attr;
    // hr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(ULONGLONG), reinterpret_cast<PBYTE>(&total_size), &content_size_attr);
    // if (SUCCEEDED(hr) && content_size_attr == sizeof(ULONGLONG) && total_size > 0) {
    //    if (total_size > MAX_CONTENT_SIZE_THRESHOLD) { // Definir un umbral para evitar OOM
    //        *result = AMSI_RESULT_NOT_DETECTED; // O un error específico
    //        return E_ACCESSDENIED; // O algún código que indique contenido demasiado grande
    //    }
    //    content_buffer.reserve(static_cast<size_t>(total_size));
    // }


    // Búfer temporal para leer fragmentos
    const DWORD CHUNK_SIZE = 4096; // Leer en fragmentos de 4KB
    std::vector<unsigned char> chunk_buffer(CHUNK_SIZE);
    ULONGLONG current_address = 0;

    do {
        hr = stream->Read(current_address, CHUNK_SIZE, chunk_buffer.data(), &bytes_read);
        if (FAILED(hr)) {
            // Error al leer el stream, podría ser un problema con la aplicación que llama.
            // Devolver el error o manejarlo (ej. log). Aquí lo propagamos.
            // Es importante no dejar *result en DETECTED si no se pudo leer.
            *result = AMSI_RESULT_NOT_DETECTED; // O un error específico si AMSI lo define
            return hr;
        }

        if (bytes_read > 0) {
            content_buffer.insert(content_buffer.end(), chunk_buffer.begin(), chunk_buffer.begin() + bytes_read);
            current_address += bytes_read;
        }
        // Podríamos añadir un límite al tamaño total de content_buffer para evitar OOM con streams maliciosos.
        // if (content_buffer.size() > SOME_MAX_SIZE) { /* error o break */ }

    } while (bytes_read == CHUNK_SIZE); // Si Read devuelve menos que CHUNK_SIZE, es el final o un error (ya manejado).


    if (content_buffer.empty()) {
        *result = AMSI_RESULT_CLEAN; // Nada que escanear, se considera limpio.
        return S_OK;
    }

    // Análisis del Contenido (Lógica de Detección)
    // i. Análisis Básico de Cadenas:
    // Convertir el buffer a std::string o std::wstring para facilitar la búsqueda.
    // AMSI_ATTRIBUTE_CONTENT_ADDRESS indica si es UTF-16 o ASCII/UTF-8.
    // Por defecto, asumiremos que es una cadena de bytes que puede contener texto.
    // Para una detección robusta, se debería considerar el atributo AMSI_ATTRIBUTE_CONTENT_TYPE.

    std::string content_as_string(content_buffer.begin(), content_buffer.end());
    // Para PowerShell, es común que sea UTF-16. Si es así, se necesitaría una conversión o búsqueda diferente.
    // bool isUtf16 = false;
    // hr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_NAME, ...); // Para verificar el tipo de script
    // hr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS_IS_UTF16, ... &isUtf16);
    // if(isUtf16) { /* convertir a wstring o buscar patrones wide char */ }


    // Patrones maliciosos a buscar (ejemplos)
    // Estos deben ser gestionados de forma más sofisticada (ej. PatternDatabase) en una implementación real.
    const char* malicious_patterns[] = {
        "Invoke-Expression", "IEX", // Comandos de ejecución remota de PowerShell
        "Get-GPO", // Podría ser usado para enumerar políticas de grupo con fines maliciosos
        "vssadmin delete shadows", // Intento de eliminar copias de seguridad
        "Set-MpPreference -DisableRealtimeMonitoring $true", // Deshabilitar Windows Defender
        "powershell -ExecutionPolicy Bypass", // Bypass de políticas de ejecución
        "amsiutils", // Herramientas conocidas para evadir AMSI
        "Invoke-Mimikatz", // Herramienta de robo de credenciales
        // Añadir más patrones según sea necesario
    };

    bool found_malicious = false;
    for (const char* pattern : malicious_patterns) {
        // Usar std::search o string::find. std::search es más general para secuencias.
        // Para búsquedas insensibles a mayúsculas/minúsculas, se necesitaría transformar ambas cadenas
        // o usar un algoritmo de búsqueda que lo soporte (como boyer_moore_horspool con transformación).
        // Aquí, una búsqueda sensible a mayúsculas para simplificar.
        if (content_as_string.find(pattern) != std::string::npos) {
            found_malicious = true;
            break;
        }
    }

    if (found_malicious) {
        *result = AMSI_RESULT_DETECTED;
    } else {
        // Si no se encuentra nada explícitamente malicioso con las cadenas básicas,
        // se podría considerar limpio o no detectado.
        // Para este ejemplo, si no hay patrones, lo marcamos como limpio.
        // Una heurística más avanzada podría dejarlo como NOT_DETECTED.
        *result = AMSI_RESULT_CLEAN;
    }

    // ii. (Opcional - Futura Mejora) Comunicación con el Servicio:
    // Aquí iría la lógica para enviar 'content_buffer' al servicio CryptoShieldService.exe

    return S_OK;
}

STDMETHODIMP_(void) CryptoShieldAMSIProvider::CloseSession(ULONGLONG session) {
    // Esta función se llama cuando una sesión de AMSI termina.
    // En esta implementación simple, no mantenemos estado de sesión específico.
    // En escenarios más complejos, aquí se liberarían recursos asociados a la sesión.
    UNREFERENCED_PARAMETER(session);
}

STDMETHODIMP CryptoShieldAMSIProvider::DisplayName(LPWSTR *displayName) {
    if (!displayName) {
        return E_POINTER;
    }
    *displayName = nullptr;

    const wchar_t* productName = L"CryptoShield Anti-Ransomware";
    size_t productNameLength = wcslen(productName) + 1;

    *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(productNameLength * sizeof(wchar_t)));
    if (!*displayName) {
        return E_OUTOFMEMORY;
    }

    wcscpy_s(*displayName, productNameLength, productName);
    return S_OK;
}

// --- Implementación de IClassFactory (AMSIProviderFactory) ---
// Esto se moverá a su propia sección o archivo si es necesario, pero por ahora aquí para la Parte 3

class AMSIProviderFactory : public IClassFactory {
public:
    // Métodos de IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void **ppv) {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() {
        return InterlockedIncrement(&m_refCount);
    }

    STDMETHODIMP_(ULONG) Release() {
        ULONG count = InterlockedDecrement(&m_refCount);
        if (count == 0) {
            delete this;
        }
        return count;
    }

    // Métodos de IClassFactory
    STDMETHODIMP CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppvObject) {
        if (!ppvObject) return E_POINTER;
        *ppvObject = nullptr;

        // No soportamos agregación en este objeto.
        if (pUnkOuter != nullptr) {
            return CLASS_E_NOAGGREGATION;
        }

        CryptoShieldAMSIProvider* provider = new (std::nothrow) CryptoShieldAMSIProvider();
        if (!provider) {
            return E_OUTOFMEMORY;
        }

        HRESULT hr = provider->QueryInterface(riid, ppvObject);
        provider->Release(); // QueryInterface incrementó la referencia, CreateInstance no debe mantener una propia.
                            // El objeto se autoeliminará cuando su recuento de referencias llegue a 0.
        return hr;
    }

    STDMETHODIMP LockServer(BOOL fLock) {
        if (fLock) {
            InterlockedIncrement(&g_dll_lock_count_);
        } else {
            InterlockedDecrement(&g_dll_lock_count_);
        }
        return S_OK;
    }

    AMSIProviderFactory() : m_ref_count_(1) { // Adherencia a Naming Conventions
        InterlockedIncrement(&g_dll_lock_count_);
    }

    ~AMSIProviderFactory() {
        InterlockedDecrement(&g_dll_lock_count_);
    }

private:
    volatile long m_ref_count_; // Adherencia a Naming Conventions
};

// --- Funciones exportadas de la DLL ---
// Estas se definirán en dllmain.cpp o un archivo similar.
// Por ahora, las declaro aquí para avanzar y las moveré luego.

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (IsEqualCLSID(rclsid, CLSID_CryptoShieldAMSIProvider)) {
        AMSIProviderFactory *factory = new (std::nothrow) AMSIProviderFactory();
        if (!factory) {
            return E_OUTOFMEMORY;
        }
        HRESULT hr = factory->QueryInterface(riid, ppv);
        factory->Release(); // QueryInterface incrementó la referencia.
        return hr;
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

// DllRegisterServer y DllUnregisterServer se implementarán en la Parte 3.
// Por ahora, solo stubs básicos.
STDAPI DllRegisterServer() {
    // Implementación en Parte 3
    return S_OK;
}

STDAPI DllUnregisterServer() {
    // Implementación en Parte 3
    return S_OK;
}

// DllCanUnloadNow
STDAPI DllCanUnloadNow() {
    return (g_dll_lock_count_ == 0) ? S_OK : S_FALSE;
}

// Punto de entrada DllMain (opcional para COM puro, pero bueno tenerlo para g_hModule)
// Se moverá a dllmain.cpp
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule); // Optimización si no se necesita notificación de threads
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// Definiciones de variables globales
long g_dll_lock_count_ = 0; // Adherencia a Naming Conventions
HMODULE g_hModule = NULL;
