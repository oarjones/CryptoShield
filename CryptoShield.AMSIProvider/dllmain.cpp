#include <windows.h>
#include <olectl.h> // Para SELFREG_E_CLASS y otras definiciones OLE
#include "guid.h"     // Contiene CLSID_CryptoShieldAMSIProvider
#include "AMSIProvider.h" // Para la declaración de CryptoShieldAMSIProvider y la fábrica
#include <string>       // Para std::wstring
#include <vector>       // No directamente usado aquí, pero útil para manejo de cadenas a veces
#include <Shlwapi.h>    // Para RegDeleteTreeW

#pragma comment(lib, "Shlwapi.lib") // Para RegDeleteTreeW

// --- Variables Globales ---
long g_dll_lock_count_ = 0;    // Contador para DllCanUnloadNow | Adherencia a Naming Conventions
HMODULE g_hModule = NULL;   // Handle de este módulo DLL
const wchar_t* PROVIDER_NAME = L"CryptoShield AMSI Provider";
const wchar_t* THREADING_MODEL = L"Apartment";

// --- Declaración de la Fábrica de Clases ---
// (La implementación de AMSIProviderFactory sigue siendo la misma que antes,
//  asumiendo que m_refCount también se renombró a m_ref_count_ en su definición)
class AMSIProviderFactory : public IClassFactory {
public:
    STDMETHOD(QueryInterface)(REFIID riid, void **ppv) {
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
        return InterlockedIncrement(&m_ref_count_); // Usar m_ref_count_
    }

    STDMETHODIMP_(ULONG) Release() {
        ULONG count = InterlockedDecrement(&m_ref_count_); // Usar m_ref_count_
        if (count == 0) {
            delete this;
        }
        return count;
    }

    STDMETHODIMP CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppvObject) {
        if (!ppvObject) return E_POINTER;
        *ppvObject = nullptr;

        if (pUnkOuter != nullptr) {
            return CLASS_E_NOAGGREGATION;
        }

        CryptoShieldAMSIProvider* provider = new (std::nothrow) CryptoShieldAMSIProvider();
        if (!provider) {
            return E_OUTOFMEMORY;
        }

        HRESULT hr = provider->QueryInterface(riid, ppvObject);
        provider->Release();
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

    AMSIProviderFactory() : m_ref_count_(1) { // Usar m_ref_count_
        InterlockedIncrement(&g_dll_lock_count_);
    }
    ~AMSIProviderFactory() {
        InterlockedDecrement(&g_dll_lock_count_);
    }
private:
    volatile long m_ref_count_; // Nombre ya actualizado en AMSIProvider.cpp, aquí reflejado para consistencia
};


// --- DllMain ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            g_hModule = hModule;
            DisableThreadLibraryCalls(hModule); // Optimización
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

// --- DllGetClassObject ---
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    if (!ppv) {
        return E_POINTER;
    }
    *ppv = nullptr;

    if (IsEqualCLSID(rclsid, CLSID_CryptoShieldAMSIProvider)) {
        AMSIProviderFactory *factory = new (std::nothrow) AMSIProviderFactory();
        if (!factory) {
            return E_OUTOFMEMORY;
        }
        HRESULT hr = factory->QueryInterface(riid, ppv);
        if(FAILED(hr)) {
            delete factory;
        }
        return hr;
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

// --- DllCanUnloadNow ---
STDAPI DllCanUnloadNow(void) {
    return (g_dll_lock_count_ == 0) ? S_OK : S_FALSE;
}

// Helper function to set a registry key value
HRESULT SetRegistryKey(HKEY hKeyRoot, const std::wstring& subKeyPath, const std::wstring& valueName, const std::wstring& valueData) {
    HKEY hKey;
    LONG lResult = RegCreateKeyExW(hKeyRoot, subKeyPath.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    if (lResult != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(lResult);
    }

    lResult = RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(valueData.c_str()), static_cast<DWORD>((valueData.length() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    return (lResult == ERROR_SUCCESS) ? S_OK : HRESULT_FROM_WIN32(lResult);
}


// --- DllRegisterServer ---
STDAPI DllRegisterServer(void) {
    HRESULT hr = S_OK;
    wchar_t szModulePath[MAX_PATH];
    if (GetModuleFileNameW(g_hModule, szModulePath, MAX_PATH) == 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    LPOLESTR pszCLSID = nullptr;
    hr = StringFromCLSID(CLSID_CryptoShieldAMSIProvider, &pszCLSID);
    if (FAILED(hr)) {
        return hr;
    }
    std::wstring clsidString(pszCLSID);
    CoTaskMemFree(pszCLSID);

    // 1. Registrar el CLSID bajo HKCR\CLSID\{GUID}
    std::wstring clsidKeyPath = L"CLSID\\" + clsidString;
    hr = SetRegistryKey(HKEY_CLASSES_ROOT, clsidKeyPath, L"", PROVIDER_NAME); // Valor por defecto para CLSID
    if (FAILED(hr)) {
        return hr;
    }

    // 2. Registrar el servidor InprocServer32
    std::wstring inprocServerKeyPath = clsidKeyPath + L"\\InprocServer32";
    hr = SetRegistryKey(HKEY_CLASSES_ROOT, inprocServerKeyPath, L"", szModulePath); // Path de la DLL
    if (FAILED(hr)) {
        return hr;
    }
    hr = SetRegistryKey(HKEY_CLASSES_ROOT, inprocServerKeyPath, L"ThreadingModel", THREADING_MODEL);
    if (FAILED(hr)) {
        return hr;
    }

    // 3. Registrar el proveedor AMSI bajo HKLM\SOFTWARE\Microsoft\AMSI\Providers\{GUID}
    // NOTA: Esto requiere privilegios de administrador. regsvr32.exe debe ejecutarse como admin.
    std::wstring amsiProviderKeyPath = L"SOFTWARE\\Microsoft\\AMSI\\Providers\\" + clsidString;
    hr = SetRegistryKey(HKEY_LOCAL_MACHINE, amsiProviderKeyPath, L"", PROVIDER_NAME);
    if (FAILED(hr)) {
        // No necesariamente fallar toda la registración si esto falla,
        // pero el proveedor AMSI no funcionará.
        // Podríamos querer limpiar las claves de HKCR si esto falla.
        // Por simplicidad, retornamos el error.
        return hr;
    }

    return S_OK;
}

// --- DllUnregisterServer ---
STDAPI DllUnregisterServer(void) {
    HRESULT hr = S_OK;
    LPOLESTR pszCLSID = nullptr;
    hr = StringFromCLSID(CLSID_CryptoShieldAMSIProvider, &pszCLSID);
    if (FAILED(hr)) {
        return hr;
    }
    std::wstring clsidString(pszCLSID);
    CoTaskMemFree(pszCLSID);

    // 1. Eliminar la clave del proveedor AMSI de HKLM
    // NOTA: Esto requiere privilegios de administrador.
    std::wstring amsiProviderKeyPath = L"SOFTWARE\\Microsoft\\AMSI\\Providers\\" + clsidString;
    LONG lResult = RegDeleteKeyW(HKEY_LOCAL_MACHINE, amsiProviderKeyPath.c_str());
    // Ignorar si la clave no existe (ERROR_FILE_NOT_FOUND), pero fallar en otros errores.
    if (lResult != ERROR_SUCCESS && lResult != ERROR_FILE_NOT_FOUND) {
        // Podríamos acumular errores o registrar, pero por ahora retornamos el primer error.
        // Si la clave AMSI no se puede borrar, aún intentaremos borrar la de CLSID.
        // hr = HRESULT_FROM_WIN32(lResult);
    }

    // 2. Eliminar la clave CLSID de HKCR
    // RegDeleteTreeW es más robusto para eliminar la clave y todas sus subclaves.
    std::wstring clsidKeyPath = L"CLSID\\" + clsidString;
    lResult = RegDeleteTreeW(HKEY_CLASSES_ROOT, clsidKeyPath.c_str());
    if (lResult != ERROR_SUCCESS && lResult != ERROR_FILE_NOT_FOUND) {
        return HRESULT_FROM_WIN32(lResult);
    }

    return S_OK;
}
