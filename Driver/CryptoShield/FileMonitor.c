/**
 * @file FileMonitor.c
 * @brief File operation monitoring and analysis implementation
 * @details Handles IRP pre/post operation callbacks and constructs messages for user mode.
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "CryptoShield.h" // Incluye Shared.h

 // ----- Forward Declarations (si es necesario para funciones en este archivo) -----
 // (No parece necesario por ahora)


 // ----- Helper function to send file operation notification -----
 // (Nombre seg�n documento t�cnico: SendFileOperationNotification)
 // Esta funci�n es interna a FileMonitor.c o declarada en CryptoShield.h si se usa en otros .c
 // El documento la tiene en FileMonitor.c, as� que la hacemos static si solo se usa aqu�.
 // Si SendMessageToUserService es la funci�n gen�rica de Communication.c, esta ser�a un wrapper.

static NTSTATUS SendFileOperationNotification(
    _In_ PFLT_CALLBACK_DATA Data,    // Para obtener PID/TID, Timestamp
    _In_ PCFLT_RELATED_OBJECTS FltObjects, // Para obtener info del archivo si es necesario
    _In_ PFLT_FILE_NAME_INFORMATION FileNameInfo, // Nombre del archivo ya obtenido
    _In_ ULONG OperationTypeShared   // FILE_OP_TYPE_* de Shared.h
)
{
    NTSTATUS status;
    CS_FILE_OPERATION_PAYLOAD payload = { 0 }; // De Shared.h
    USHORT filePathNameLengthChars = 0;        // Longitud en caracteres, sin NUL
    UNREFERENCED_PARAMETER(FltObjects); // <<< --- A�ADIR ESTA L�NEA AL INICIO DE LA FUNCI�N

    if (g_Context.IsUnloading || !g_Context.ClientConnected || g_Context.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED; // O STATUS_SHUTDOWN_IN_PROGRESS
    }

    // Rellenar el payload
    payload.Header.MessageType = MSG_TYPE_FILE_OPERATION; // De Shared.h
    // payload.Header.MessageId = ... ; // Opcional, para seguimiento
    payload.Header.PayloadSize = sizeof(CS_FILE_OPERATION_PAYLOAD); // Tama�o del payload fijo

    payload.ProcessId = FltGetRequestorProcessId(Data);
    payload.ThreadId = HandleToULong(PsGetCurrentThreadId()); // O FltGetRequestorThreadId(Data) si es aplicable y m�s f�cil
    KeQuerySystemTime(&payload.Timestamp);
    payload.OperationType = OperationTypeShared;

    // Copiar el nombre del archivo al payload
    if (FileNameInfo != NULL && FileNameInfo->Name.Length > 0) {
        // FileNameInfo->Name.Length es en bytes.
        // payload.FilePathLength es en caracteres.
        // payload.FilePath es WCHAR[MAX_FILE_PATH_CHARS]
        filePathNameLengthChars = FileNameInfo->Name.Length / sizeof(WCHAR);
        if (filePathNameLengthChars >= MAX_FILE_PATH_CHARS) { // Comprobar si cabe (incluyendo NUL impl�cito)
            filePathNameLengthChars = MAX_FILE_PATH_CHARS - 1; // Truncar para dejar espacio para NUL
        }
        RtlCopyMemory(payload.FilePath, FileNameInfo->Name.Buffer, filePathNameLengthChars * sizeof(WCHAR));
        payload.FilePath[filePathNameLengthChars] = L'\0'; // Asegurar terminaci�n NUL
        payload.FilePathLength = filePathNameLengthChars; // Longitud en caracteres sin NUL
    }
    else {
        // No hay nombre de archivo o es una operaci�n sin nombre (ej. sobre un handle abierto)
        // Podr�amos intentar obtenerlo del FltObjects->FileObject si FileNameInfo es NULL.
        // Por ahora, si no hay FileNameInfo, se deja vac�o.
        payload.FilePath[0] = L'\0';
        payload.FilePathLength = 0;
    }

    // Obtener otros datos opcionales si es necesario y eficiente:
    // payload.FileAttributes = ...;
    // payload.FileSize = ...;
    // Esto puede requerir consultas adicionales al sistema de archivos.

    // Enviar el mensaje al servicio de usuario
    // Asumimos que SendMessageToUserService se encarga de FILTER_MESSAGE_HEADER si espera respuesta.
    // Si es una notificaci�n pura sin esperar respuesta directa del servicio para esta operaci�n:
    status = SendMessageToUserService(
        (PCS_MESSAGE_PAYLOAD_HEADER)&payload,
        sizeof(CS_FILE_OPERATION_PAYLOAD),
        NULL,  // No se espera buffer de respuesta espec�fico para esta notificaci�n.
        NULL   // No se espera longitud de respuesta.
    );

    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_Context.MessagesSentToUserMode);
        CS_LOG_TRACE("Sent file op type %u for '%wZ' (PID: %u) successfully.",
            OperationTypeShared, &FileNameInfo->Name, payload.ProcessId);
    }
    else {
        CS_LOG_WARNING("Failed to send file op type %u for '%wZ' (PID: %u). Status: 0x%08X",
            OperationTypeShared, &FileNameInfo->Name, payload.ProcessId, status);
    }

    return status;
}


// ----- Minifilter Operation Callbacks -----

/**
 * @brief Pre-operation callback (nombre del doc. t�cnico: PreOperationCallback)
 * @details Called before an I/O operation is passed to the file system
 */
FLT_PREOP_CALLBACK_STATUS PreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS status;
    ULONG sharedFileOpType = 0; // FILE_OP_TYPE_* de Shared.h
    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK; // Por defecto, no llamar a post-op

    UNREFERENCED_PARAMETER(CompletionContext); // Inicialmente no se usa contexto para post-op
    *CompletionContext = NULL;

    // Comprobar si el driver se est� descargando o si el monitoreo est� deshabilitado.
    if (g_Context.IsUnloading || !g_Context.MonitoringEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // No hacer nada
    }

    // Omitir operaciones del sistema de paginaci�n para evitar recursi�n y sobrecarga.
    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    // Omitir operaciones en el volumen del sistema de logs (si se conoce).
    // if (FltObjects->Volume == g_SystemLogVolume) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Determinar el tipo de operaci�n seg�n IRP_MJ_*, y si es necesario, IRP_MN_*.
    // Esto debe mapear a los FILE_OP_TYPE_* de Shared.h.
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        sharedFileOpType = FILE_OP_TYPE_CREATE;
        callbackStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK; // Necesitamos post-op para Create
        break;
    case IRP_MJ_WRITE:
        sharedFileOpType = FILE_OP_TYPE_WRITE;
        // Para Write, post-op puede ser �til para ver el resultado.
        callbackStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
        break;
    case IRP_MJ_SET_INFORMATION:
        // Para IRP_MJ_SET_INFORMATION, el tipo de operaci�n depende de FileInformationClass.
        switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
        case FileRenameInformation:
        case FileRenameInformationEx:
            // Tambi�n FileRenameInformationBypassAccessCheck si se maneja
            sharedFileOpType = FILE_OP_TYPE_RENAME;
            break;
        case FileDispositionInformation:
        case FileDispositionInformationEx:
            // Tambi�n FileDispositionInformationBypassAccessCheck
            sharedFileOpType = FILE_OP_TYPE_DELETE;
            break;
        default:
            sharedFileOpType = FILE_OP_TYPE_SET_INFORMATION; // Gen�rico para otros SetInfo
            break;
        }
        // Post-op para SetInfo puede ser �til.
        callbackStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
        break;
    case IRP_MJ_CLEANUP:
        sharedFileOpType = FILE_OP_TYPE_CLEANUP;
        // No se necesita post-op para Cleanup seg�n el documento.
        callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
        break;
    default:
        // Operaci�n no monitorizada expl�citamente, no hacer nada.
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Si es una operaci�n que queremos notificar:
    if (sharedFileOpType != 0) {
        InterlockedIncrement64(&g_Context.FileOperationsMonitored);

        // Solo obtener nombre de archivo y enviar notificaci�n si hay un cliente conectado.
        if (g_Context.ClientConnected) {
            status = GetNormalizedFileNameInformation(Data, &fileNameInfo);
            if (NT_SUCCESS(status)) {
                // Opcional: Filtrar por nombre de archivo aqu� usando ShouldMonitorFileByPath(fileNameInfo)
                // if (ShouldMonitorFileByPath(fileNameInfo)) { ... }

                // Enviar notificaci�n al servicio de usuario.
                SendFileOperationNotification(Data, FltObjects, fileNameInfo, sharedFileOpType);
                // El llamador de SendFileOperationNotification es responsable de liberar fileNameInfo si es necesario.
                // Pero GetNormalizedFileNameInformation devuelve un puntero que debe ser liberado por el llamador de GetNormalizedFileNameInformation.
            }
            else {
                // No se pudo obtener el nombre, �enviar notificaci�n sin nombre?
                // O registrar error y continuar.
                CS_LOG_WARNING("Could not get file name for op type %u. Status: 0x%08X", sharedFileOpType, status);
                // Podr�a llamarse a SendFileOperationNotification con fileNameInfo = NULL.
                SendFileOperationNotification(Data, FltObjects, NULL, sharedFileOpType);
            }

            if (fileNameInfo != NULL) {
                FltReleaseFileNameInformation(fileNameInfo);
                fileNameInfo = NULL;
            }
        }
    }

    // Por ahora, el driver no bloquea ninguna operaci�n, solo observa.
    // Si se quisiera bloquear, se devolver�a FLT_PREOP_COMPLETE y se establecer�a Data->IoStatus.Status.
    // Ejemplo:
    // Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    // Data->IoStatus.Information = 0;
    // return FLT_PREOP_COMPLETE;

    return callbackStatus;
}

/**
 * @brief Post-operation callback (nombre del doc. t�cnico: PostOperationCallback)
 * @details Called after an I/O operation completes
 */
FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext, // Contexto pasado desde pre-operaci�n
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Comprobar si el driver se est� descargando.
    if (g_Context.IsUnloading || !g_Context.MonitoringEnabled) {
        return FLT_POSTOP_FINISHED_PROCESSING; // No hacer nada m�s
    }

    // FLT_POSTOP_DRAINING indica que el filtro se est� desconectando del volumen.
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Aqu� se podr�a analizar el resultado de la operaci�n (Data->IoStatus.Status)
    // y enviar una notificaci�n adicional si es necesario.
    // Por ejemplo, para IRP_MJ_CREATE, se podr�a verificar si el archivo se cre� o abri� con �xito.
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        if (NT_SUCCESS(Data->IoStatus.Status)) {
            CS_LOG_TRACE("PostCreate: File operation successful for %wZ, status 0x%08X, info 0x%p",
                &FltObjects->FileObject->FileName, Data->IoStatus.Status, Data->IoStatus.Information);
            // Data->IoStatus.Information para IRP_MJ_CREATE indica:
            // FILE_CREATED, FILE_OPENED, FILE_OVERWRITTEN, FILE_SUPERSEDED, FILE_EXISTS, FILE_DOES_NOT_EXIST
        }
        else {
            CS_LOG_TRACE("PostCreate: File operation failed for %wZ, status 0x%08X",
                &FltObjects->FileObject->FileName, Data->IoStatus.Status);
        }
        // Podr�a enviarse otra notificaci�n aqu� con el resultado.
    }
    // L�gica similar para otras operaciones si es necesario.

    return FLT_POSTOP_FINISHED_PROCESSING; // Indicar que hemos terminado con esta operaci�n.
}


// ----- Funciones de Ayuda para Monitoreo de Archivos -----

/**
 * @brief Gets normalized file name information for an I/O operation.
 * El llamador es responsable de liberar la estructura FileNameInfo con FltReleaseFileNameInformation.
 */
NTSTATUS GetNormalizedFileNameInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _Outptr_ PFLT_FILE_NAME_INFORMATION* FileNameInfo // Puntero para devolver la estructura asignada
)
{
    NTSTATUS status;

    PAGED_CODE(); // Las funciones de nombre de archivo suelen ser paginables.

    if (FileNameInfo == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }
    *FileNameInfo = NULL; // Inicializar el puntero de salida

    // Obtener el nombre de archivo normalizado.
    // FLT_FILE_NAME_QUERY_DEFAULT: El manejador de filtros elige el mejor m�todo.
    // FLT_FILE_NAME_NORMALIZED: Intenta obtener el nombre can�nico.
    // Tambi�n se puede especificar FLT_FILE_NAME_OPENED (para nombres ya abiertos) o
    // FLT_FILE_NAME_SHORT (para nombres cortos 8.3, menos �til).
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        FileNameInfo // Recibe el puntero a la estructura asignada
    );

    if (!NT_SUCCESS(status)) {
        CS_LOG_TRACE("FltGetFileNameInformation failed with status 0x%08X", status);
        // Puede fallar si no hay nombre (ej. operaciones en handles abiertos sin nombre asociado)
        // o si el sistema de archivos no soporta la consulta en este momento.
        return status;
    }

    // (Opcional) Parsear el nombre para tener acceso a componentes como Volumen, Directorio, Stream.
    // Esto es �til si se necesita analizar partes espec�ficas del nombre.
    // status = FltParseFileNameInformation(*FileNameInfo);
    // if (!NT_SUCCESS(status)) {
    //     CS_LOG_WARNING("FltParseFileNameInformation failed with status 0x%08X for '%wZ'",
    //         status, &(*FileNameInfo)->Name);
    //     FltReleaseFileNameInformation(*FileNameInfo);
    //     *FileNameInfo = NULL;
    //     return status;
    // }
    // CS_LOG_TRACE("Normalized file name: '%wZ'", &(*FileNameInfo)->Name);
    // CS_LOG_TRACE("Volume: '%wZ', Share: '%wZ', ParentDir: '%wZ', FinalComponent: '%wZ', Extension: '%wZ', Stream: '%wZ'",
    //    &(*FileNameInfo)->Volume, &(*FileNameInfo)->Share, &(*FileNameInfo)->ParentDir,
    //    &(*FileNameInfo)->FinalComponent, &(*FileNameInfo)->Extension, &(*FileNameInfo)->Stream);


    return STATUS_SUCCESS;
}