#pragma once

#include <windows.h>
#include <string>

// Declared in Main.cpp, used for RegisterEventSourceW
extern const wchar_t SERVICE_NAME[];

/**
 * @brief Writes to Windows event log
 * @details Logs service events for monitoring
 *
 * @param event_type Type of event (error, warning, info). EVENTLOG_SUCCESS, EVENTLOG_ERROR_TYPE, EVENTLOG_WARNING_TYPE, EVENTLOG_INFORMATION_TYPE
 * @param message Message to log
 */
void WriteEventLog(WORD event_type, const std::wstring& message);
