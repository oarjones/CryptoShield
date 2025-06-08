#pragma once

#include <string>

namespace CryptoShield::Utils {

    /**
     * @brief Converts a wide string (wstring) to a UTF-8 encoded string.
     * @param wstr The wide string to convert.
     * @return The UTF-8 encoded string.
     */
    std::string to_string_utf8(const std::wstring& wstr);

    ///**
    // * @brief Converts a UTF-8 encoded string to a wide string (wstring).
    // * @param str The UTF-8 encoded string to convert.
    // * @return The wide string.
    // */
    //std::wstring to_wstring_utf8(const std::string& str);

} // namespace CryptoShield::Utils