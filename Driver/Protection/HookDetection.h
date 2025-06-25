/**
 * @file HookDetection.h
 * @brief Hook detection and prevention system interface (Monitor & Alert Model)
 * @details Detects various types of kernel hooks and prepares alert data.
 *
 * @author CryptoShield Team
 * @date 2025
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include <fltKernel.h>
#include "SelfProtection.h"

#pragma pack(push, 1)
typedef struct _IDT_DESCRIPTOR {
    UINT16 Limit;
    UINT64 Base;
} IDT_DESCRIPTOR, * PIDT_DESCRIPTOR;

typedef struct _IDT_ENTRY {
    UINT16 OffsetLow;
    UINT16 Selector;
    UINT8  IST;
    UINT8  TypeAttr;
    UINT16 OffsetMid;
    UINT32 OffsetHigh;
    UINT32 Reserved;
} IDT_ENTRY, * PIDT_ENTRY;
#pragma pack(pop)

typedef struct _SYSTEM_SERVICE_TABLE {
    PVOID* ServiceTableBase;
    PVOID  ServiceCounterTableBase;
    UINT64 NumberOfServices;
    PVOID  ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

typedef enum _HOOK_TYPE {
    HOOK_TYPE_NONE = 0,
    HOOK_TYPE_SSDT = 1,
    HOOK_TYPE_IDT = 2,
    HOOK_TYPE_IRP_HANDLER = 4,
    HOOK_TYPE_FILTER_CALLBACK = 8,
    HOOK_TYPE_INLINE = 16,
} HOOK_TYPE;

#define MAX_HOOK_DETECTIONS 100
#define MAX_INSTRUCTION_BYTES 32
#define MAX_PATTERN_SIZE 64

typedef struct _HOOK_DETECTION_RESULT {
    HOOK_TYPE HookType;
    PVOID HookedAddress;
    PVOID HookHandler;
    BOOLEAN IsMalicious; // Basado en heurísticas (ej. puntero fuera de módulos firmados)
    ULONG ConfidenceLevel;
    WCHAR Description[256];
    ULONG IndexOrVector; // Para el índice de la SSDT o el vector de la IDT
} HOOK_DETECTION_RESULT, * PHOOK_DETECTION_RESULT;

typedef struct _HOOK_DETECTION_CONTEXT {
    PSYSTEM_SERVICE_TABLE SsdtBase;
    ULONG SsdtEntries;
    PVOID* OriginalSsdtTable; // Backup para comparación

    PIDT_ENTRY IdtBase;
    USHORT IdtEntries;

    ULONG TotalScans;
    ULONG HooksDetected;

    KSPIN_LOCK DetectionLock;
    ERESOURCE ScanResource;
} HOOK_DETECTION_CONTEXT, * PHOOK_DETECTION_CONTEXT;

// --- Declaraciones de Funciones (API Pública del Módulo) ---

NTSTATUS InitializeHookDetection(_In_ PPROTECTION_CONTEXT Context);
VOID CleanupHookDetection(_In_ PHOOK_DETECTION_CONTEXT DetectionContext);
NTSTATUS DetectSSDTHooks(_In_ PHOOK_DETECTION_CONTEXT Context, _Out_writes_to_(MaxResults, *pDetectedCount) PHOOK_DETECTION_RESULT Results, _In_ ULONG MaxResults, _Out_ PULONG pDetectedCount);
NTSTATUS DetectIDTHooks(_In_ PHOOK_DETECTION_CONTEXT Context, _Out_writes_to_(MaxResults, *pDetectedCount) PHOOK_DETECTION_RESULT Results, _In_ ULONG MaxResults, _Out_ PULONG pDetectedCount);
BOOLEAN AnalyzeFunctionPrologue(_In_ PVOID FunctionAddress, _Out_ PVOID* pJumpTarget);
BOOLEAN IsValidKernelAddress(_In_ PVOID Address);
VOID GetHookDetectionStatistics(_In_ PHOOK_DETECTION_CONTEXT Context, _Out_opt_ PULONG TotalScans, _Out_opt_ PULONG HooksDetected);