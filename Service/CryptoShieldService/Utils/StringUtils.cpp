#include "StringUtils.h"
#include <windows.h>
#include <locale>
#include <codecvt>

namespace CryptoShield::Utils {

    std::string to_string_utf8(const std::wstring& wstr)
    {
        if (wstr.empty()) {
            return std::string();
        }
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }

    //std::wstring to_wstring_utf8(const std::string& str)
    //{
    //    // std::wstring_convert está deprecado en C++17 pero es muy conveniente.
    //    // Si tu compilador lo soporta y no tienes restricciones, es una opción fácil.
    //    // Si no, se puede usar MultiByteToWideChar, que es la contraparte de la otra función.
    //    try {
    //        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    //        return converter.from_bytes(str);
    //    }
    //    catch (const std::range_error&) {
    //        // Manejar un posible error si la conversión falla.
    //        return L"";
    //    }
    //}

} // namespace CryptoShield::Utils