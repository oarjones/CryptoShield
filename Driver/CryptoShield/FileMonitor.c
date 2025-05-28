#include "CryptoShield.h" // For g_CryptoShieldContext, FILTER_MESSAGE, MSG_FILE_OPERATION, CRYPTOSHIELD_TAG
#include <fltKernel.h>    // For FLT_CALLBACK_DATA, FltGetFileNameInformation, FltSendMessage, etc.
#include <ntstrsafe.h>    // For RtlStringCchCopyUnicodeString, RtlStringCchLengthW (if needed)

// Definition for SendFileOperationNotification, as it's used by PostOperationCallback
NTSTATUS SendFileOperationNotification(
    _In_ PCRYPTOSHIELD_CONTEXT Context,
    _In_ PFLT_CALLBACK_DATA Data, // Pass Data to get ProcessId and potentially other info
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects, // May not be strictly needed here if not accessing FltObjects->FileObject
    _In_ ULONG OperationType,
    _In_ PUNICODE_STRING FilePath // Pass the actual file path
);


FLT_PREOP_CALLBACK_STATUS PreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
    NTSTATUS status;
    UNICODE_STRING defaultName;

    PAGED_CODE(); // File name operations are typically paged.

    if (g_CryptoShieldContext == NULL || !g_CryptoShieldContext->MonitoringEnabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Default file path if actual name cannot be obtained
    RtlInitUnicodeString(&defaultName, L"[Unknown File]");

    // Get file name information
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_NORMALIZED_RESPONSE, 
        &fileNameInfo
    );

    PUNICODE_STRING pNameToLog = &defaultName;
    if (NT_SUCCESS(status) && fileNameInfo != NULL && fileNameInfo->Name.Buffer != NULL) {
        pNameToLog = &fileNameInfo->Name;
    }

    UCHAR majorFunction = Data->Iopb->MajorFunction;
    KdPrint(("CryptoShield: PreOperation - IRP_MJ_0x%X, File: %wZ, ProcessId: %lu\n",
        majorFunction,
        pNameToLog,
        (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data) 
        ));

    if (fileNameInfo != NULL) {
        FltReleaseFileNameInformation(fileNameInfo);
    }

    // If a PostOp is registered (as it is for all our monitored IRPs), 
    // we must return FLT_PREOP_SUCCESS_WITH_CALLBACK or an alternate status that bypasses PostOp.
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags); 
    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
    NTSTATUS status;
    UNICODE_STRING defaultName;

    PAGED_CODE();

    if (g_CryptoShieldContext == NULL || !g_CryptoShieldContext->MonitoringEnabled || FltObjects->FileObject == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    
    RtlInitUnicodeString(&defaultName, L"[Unknown File PostOp]");

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_NORMALIZED_RESPONSE,
        &fileNameInfo
    );

    PUNICODE_STRING pNameToLog = &defaultName;
    if (NT_SUCCESS(status) && fileNameInfo != NULL && fileNameInfo->Name.Buffer != NULL) {
        pNameToLog = &fileNameInfo->Name;
    }
    
    KdPrint(("CryptoShield: PostOperation - IRP_MJ_0x%X, File: %wZ, Status: 0x%08X, ProcessId: %lu\n",
        Data->Iopb->MajorFunction,
        pNameToLog,
        Data->IoStatus.Status,
        (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data)
        ));

    if (g_CryptoShieldContext->ClientPort != NULL && NT_SUCCESS(Data->IoStatus.Status)) { 
        SendFileOperationNotification(g_CryptoShieldContext, Data, FltObjects, Data->Iopb->MajorFunction, pNameToLog);
    }

    if (fileNameInfo != NULL) {
        FltReleaseFileNameInformation(fileNameInfo);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}


NTSTATUS SendFileOperationNotification(
    _In_ PCRYPTOSHIELD_CONTEXT Context, 
    _In_ PFLT_CALLBACK_DATA Data,       
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects, 
    _In_ ULONG OperationType,           
    _In_ PUNICODE_STRING FilePath       
) {
    UNREFERENCED_PARAMETER(FltObjects);
    PFILTER_MESSAGE message = NULL;
    NTSTATUS status;
    ULONG messageSize;
    LARGE_INTEGER currentTime;

    PAGED_CODE(); 

    if (Context == NULL || Context->ClientPort == NULL || FilePath == NULL) {
        KdPrint(("CryptoShield: SendFileOperationNotification - Invalid parameters (Context: %p, ClientPort: %p, FilePath: %p)\n", Context, Context ? Context->ClientPort : NULL, FilePath));
        return STATUS_INVALID_PARAMETER;
    }
    
    messageSize = sizeof(FILTER_MESSAGE); 

    message = (PFILTER_MESSAGE)ExAllocatePoolZero(NonPagedPool, messageSize, CRYPTOSHIELD_TAG);
    if (message == NULL) {
        KdPrint(("CryptoShield: SendFileOperationNotification - Failed to allocate message buffer.\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    message->MessageType = MSG_FILE_OPERATION;
    message->ProcessId = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data); 
    message->ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId(); 
    KeQuerySystemTimePrecise(&currentTime); 
    message->Timestamp = currentTime;
    message->OperationType = OperationType;

    if (FilePath->Buffer != NULL && FilePath->Length > 0) {
        ULONG lengthToCopyChars = FilePath->Length / sizeof(WCHAR);
        if (lengthToCopyChars >= RTL_NUMBER_OF(message->FilePath)) {
            lengthToCopyChars = RTL_NUMBER_OF(message->FilePath) - 1; 
        }
        
        RtlCopyMemory(message->FilePath, FilePath->Buffer, lengthToCopyChars * sizeof(WCHAR));
        message->FilePath[lengthToCopyChars] = L'\0'; 
        message->FilePathLength = lengthToCopyChars; 
    } else {
        message->FilePath[0] = L'\0';
        message->FilePathLength = 0;
         KdPrint(("CryptoShield: SendFileOperationNotification - FilePath buffer was NULL or Length was 0.\n"));
    }
    
    LARGE_INTEGER timeout;
    timeout.QuadPart = -1000 * 1000; // 100ms 

    ULONG replyLength = 0; 

    status = FltSendMessage(
        Context->FilterHandle,
        &Context->ClientPort, 
        message,              
        messageSize,          
        NULL,                 
        &replyLength,         
        &timeout              
    );

    if (NT_SUCCESS(status)) {
        KdPrint(("CryptoShield: SendFileOperationNotification - Message sent for %wZ.\n", FilePath));
        InterlockedIncrement((PLONG)&Context->MessagesSent); // Cast to PLONG for InterlockedIncrement
    } else {
        KdPrint(("CryptoShield: SendFileOperationNotification - FltSendMessage failed (0x%08X) for %wZ.\n", status, FilePath));
        if (status == STATUS_PORT_DISCONNECTED) {
            // Consider clearing Context->ClientPort = NULL here, perhaps under a lock,
            // if DisconnectNotifyCallback might not have run.
            // However, FltSendMessage is expected to handle this.
            KdPrint(("CryptoShield: SendFileOperationNotification - Port disconnected.\n"));
        }
    }

    ExFreePoolWithTag(message, CRYPTOSHIELD_TAG);
    return status;
}
