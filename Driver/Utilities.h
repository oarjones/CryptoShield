#pragma once

#ifndef _UTILITIES_H_
#define _UTILITIES_H_

#include <fltKernel.h> // Para PFLT_FILE_NAME_INFORMATION y FLT_FILESYSTEM_TYPE

BOOLEAN IsFileSystemSupported(
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

BOOLEAN ShouldMonitorFileByPath(
    _In_ PFLT_FILE_NAME_INFORMATION FileNameInfo
);

NTSTATUS GetNormalizedFileNameInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _Outptr_ PFLT_FILE_NAME_INFORMATION* FileNameInfo
);

#endif // _UTILITIES_H_
