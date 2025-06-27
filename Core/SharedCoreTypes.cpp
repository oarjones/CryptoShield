#include "SharedCoreTypes.h"
#include <sstream>
#include <iomanip>

namespace CryptoShield {

    std::wstring FileOperationInfo::GetOperationTypeString() const {
        switch (type) {
        case FileOperationType::Create: return L"Create";
        case FileOperationType::Write: return L"Write";
        case FileOperationType::Delete: return L"Delete";
        case FileOperationType::Rename: return L"Rename";
        case FileOperationType::SetInformation: return L"SetInfo";
        default: return L"Unknown";
        }
    }

    std::wstring FileOperationInfo::GetFormattedTimestamp() const {
        SYSTEMTIME st;
        FileTimeToSystemTime(&timestamp, &st);

        std::wostringstream oss;
        oss << std::setfill(L'0')
            << std::setw(4) << st.wYear << L"-"
            << std::setw(2) << st.wMonth << L"-"
            << std::setw(2) << st.wDay << L" "
            << std::setw(2) << st.wHour << L":"
            << std::setw(2) << st.wMinute << L":"
            << std::setw(2) << st.wSecond;

        return oss.str();
    }

} // namespace CryptoShield