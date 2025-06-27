#pragma once

#ifndef _FILE_MONITOR_H_
#define _FILE_MONITOR_H_

#include <fltKernel.h> // Necesario para los tipos de datos del Filter Manager

//
// Prototipos para los Callbacks de Operaciones de I/O
// Estas son las funciones principales que el Filter Manager llama
// cuando ocurre una operación de fichero que estamos monitorizando.
//

FLT_PREOP_CALLBACK_STATUS
PreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

#endif // _FILE_MONITOR_H_