#pragma once

#include <windows.h>
#include <amsi.h>
#include "guid.h" // Para CLSID_CryptoShieldAMSIProvider

// Declaración anticipada si es necesario para la fábrica de clases
class CryptoShieldAMSIProviderFactory;

class CryptoShieldAMSIProvider : public IAmsiProvider {
public:
    // Métodos de IUnknown
    STDMETHOD(QueryInterface)(REFIID riid, void **ppvObject) override;
    STDMETHOD_(ULONG, AddRef)() override;
    STDMETHOD_(ULONG, Release)() override;

    // Métodos de IAmsiProvider
    STDMETHOD(Scan)(IAmsiStream *stream, AMSI_RESULT *result) override;
    STDMETHOD_(void, CloseSession)(ULONGLONG session) override;
    STDMETHOD(DisplayName)(LPWSTR *displayName) override;

    CryptoShieldAMSIProvider();
    ~CryptoShieldAMSIProvider();

private:
    volatile long m_ref_count_; // Adherencia a Naming Conventions: snake_case con trailing underscore
    // Aquí podrías añadir una instancia del motor de detección o un cliente para comunicarte con el servicio
    // Por ahora, nos centraremos en la detección básica de cadenas.
};
