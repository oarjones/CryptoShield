// Pre-declaración para evitar incluir todo Windows.h en el .h si es posible,
// aunque Wbemidl.h probablemente ya lo haga.
typedef unsigned long DWORD;
typedef long HRESULT;

// Forward declarations for COM interfaces if not using CComPtr directly in header for types
// struct IWbemLocator;
// struct IWbemServices;

// Para CComPtr
#include <atlbase.h> // Requerido para CComPtr y otras utilidades de ATL
#include <atlcomcli.h> // Para CComPtr

#include <string>
#include <Wbemidl.h> // Cabecera principal de WMI
#include <iwscapi.h> // Para WSC_SECURITY_PRODUCT_STATE

// Ya no se define WMI_PRODUCT_STATE aquí.
// UpdateState tomará WSC_SECURITY_PRODUCT_STATE y la clase mapeará
// internamente a los valores DWORD que WMI espera (0 para ON en WSC API -> 1 para ON en WMI, etc.)

class WindowsSecurityCenterIntegration {
public:
    WindowsSecurityCenterIntegration();
    ~WindowsSecurityCenterIntegration();

    /**
     * @brief Registra CryptoShield con el Centro de Seguridad de Windows.
     * @return HRESULT Resultado de la operación. S_OK si tiene éxito.
     */
    HRESULT Register();

    /**
     * @brief Actualiza el estado de CryptoShield en el Centro de Seguridad de Windows.
     * @param state El nuevo estado del producto, usando el enum WSC_SECURITY_PRODUCT_STATE de iwscapi.h.
     * @return HRESULT Resultado de la operación. S_OK si tiene éxito.
     */
    HRESULT UpdateState(WSC_SECURITY_PRODUCT_STATE state);

    /**
     * @brief Elimina el registro de CryptoShield del Centro de Seguridad de Windows.
     * @return HRESULT Resultado de la operación. S_OK si tiene éxito.
     */
    HRESULT Unregister();

private:
    /**
     * @brief Inicializa COM para el hilo actual y la seguridad del proceso.
     * @return HRESULT Resultado de la operación. S_OK si tiene éxito.
     */
    HRESULT InitializeCOM();

    /**
     * @brief Se conecta al servicio WMI y al namespace ROOT\\SecurityCenter2.
     * @return HRESULT Resultado de la operación. S_OK si tiene éxito.
     */
    HRESULT ConnectToWMI();

    /**
     * @brief Obtiene la ruta completa del ejecutable del producto.
     * @return std::wstring Ruta del ejecutable. Vacía si falla.
     */
    std::wstring GetProductExePath() const;

    bool m_comInitialized = false;
    bool m_registered = false; // Para rastrear si el producto está actualmente registrado por esta instancia

    // Punteros inteligentes ATL para la gestión automática de recursos COM.
    CComPtr<IWbemLocator> m_pLocator;
    CComPtr<IWbemServices> m_pServices;

    // GUID único para la instancia del producto CryptoShield.
    // Generado desde https://www.uuidgenerator.net/api/version4
    const std::wstring m_instanceGuid = L"{eb23bfb5-64d3-4829-ac2a-0f4e7d49914b}";
};
