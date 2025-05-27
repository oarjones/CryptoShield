#include "Shared.h"
#include <sstream>
#include <iomanip>
#include <locale>
#include <codecvt>

//
// Implementación de funciones de utilidad
//

std::wstring GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::wstringstream wss;
    //wss << std::put_time(std::localtime(&time_t), L"%Y-%m-%d %H:%M:%S");

    //wss << std::put_time(std::localtime(&time_t), L"%Y-%m-%d %H:%M:%S");
    std::tm tm_info;
    if (localtime_s(&tm_info, &time_t) == 0) {
        wss << std::put_time(&tm_info, L"%Y-%m-%d %H:%M:%S");
    }
    else {
        // Handle error, perhaps log or set a default timestamp string
        wss << L"YYYY-MM-DD HH:MM:SS";
    }

    wss << L"." << std::setfill(L'0') << std::setw(3) << ms.count();
    
    return wss.str();
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) {
        return std::string();
    }
    
    // Use Windows API for conversion
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), 
                                         NULL, 0, NULL, NULL);
    std::string str_to(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), 
                       &str_to[0], size_needed, NULL, NULL);
    return str_to;
}

std::wstring StringToWString(const std::string& str) {
    if (str.empty()) {
        return std::wstring();
    }
    
    // Use Windows API for conversion
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), 
                                         NULL, 0);
    std::wstring wstr_to(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), 
                       &wstr_to[0], size_needed);
    return wstr_to;
}