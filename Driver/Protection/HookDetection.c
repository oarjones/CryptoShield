/**
 * @file HookDetection.c
 * @brief Implements SSDT and other hook detection mechanisms for CryptoShield.
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "HookDetection.h"
#include "../CryptoShield.h" // For CS_LOG_*, CS_ASSERT_IRQL_PASSIVE, CRYPTOSHIELD_POOL_TAG

// Global variable to store ntoskrnl.exe information
KERNEL_MODULE_INFO g_NtoskrnlInfo = { NULL, 0 };

// Structure for Service Descriptor Table Entry
typedef struct _SYSTEM_SERVICE_TABLE {
    PULONG ServiceTableBase; // Pointer to the table of service function addresses (KiServiceTable)
    PULONG ServiceCounterTableBase; // Optional: Used for counting service calls
    ULONG NumberOfServices; // Number of services in the table
    PUCHAR ParamTableBase; // Optional: Table of argument byte counts for services
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

// KeServiceDescriptorTable is not always exported.
// For 64-bit systems, it has a specific structure.
// We are interested in the primary table (ntoskrnl.exe's services).
#ifdef _WIN64
// On x64, KeServiceDescriptorTable is an array of SSDT_ENTRY_64.
// Each entry describes a service table. The first one is for ntoskrnl.
// However, the structure itself is complex to define without internal headers.
// We typically care about the ServiceTableBase from the first entry.
// Let's define a simplified view for what we need.
typedef struct _KSERVICE_DESCRIPTOR_TABLE_ENTRY {
    PULONG ServiceTableBase;
    PULONG ServiceCounterTableBase; // unused
    ULONG_PTR NumberOfServices; // Should be ULONG_PTR for x64
    PUCHAR ParamTableBase;    // unused
} KSERVICE_DESCRIPTOR_TABLE_ENTRY, *PKSERVICE_DESCRIPTOR_TABLE_ENTRY;

#else // _WIN32
// On x86, KeServiceDescriptorTable is an array of SYSTEM_SERVICE_TABLE.
typedef SYSTEM_SERVICE_TABLE KSERVICE_DESCRIPTOR_TABLE_ENTRY;
typedef PKSERVICE_DESCRIPTOR_TABLE_ENTRY PKSERVICE_DESCRIPTOR_TABLE_ENTRY;
#endif

// Global pointer to the resolved KeServiceDescriptorTable (or its main entry)
// This should be initialized at PASSIVE_LEVEL during DriverEntry.
PKSERVICE_DESCRIPTOR_TABLE_ENTRY g_KeServiceDescriptorTable = NULL;


// Function prototype for ZwQuerySystemInformation
NTSTATUS ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

/**
 * @brief Retrieves the base address and size of ntoskrnl.exe.
 * @details Uses ZwQuerySystemInformation to find ntoskrnl.exe in the list of loaded modules.
 *
 * @param ModuleInfo Pointer to KERNEL_MODULE_INFO structure to be filled.
 * @return NTSTATUS Status of the operation. STATUS_SUCCESS on success.
 * @note This function should be called at PASSIVE_LEVEL.
 */
NTSTATUS GetNtoskrnlBoundaries(
    _Out_ PKERNEL_MODULE_INFO ModuleInfo
);

/**
 * @brief Initializes SSDT related structures.
 * @details Attempts to find KeServiceDescriptorTable. This should be called at PASSIVE_LEVEL.
 * @return NTSTATUS STATUS_SUCCESS if successful, otherwise an error code.
 */
NTSTATUS InitializeSdtTable(VOID)
{
    UNICODE_STRING routineName;

    PAGED_CODE();
    CS_ASSERT_IRQL_PASSIVE();

    RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
    g_KeServiceDescriptorTable = (PKSERVICE_DESCRIPTOR_TABLE_ENTRY)MmGetSystemRoutineAddress(&routineName);

    if (g_KeServiceDescriptorTable == NULL) {
        CS_LOG_ERROR("KeServiceDescriptorTable not found via MmGetSystemRoutineAddress. SSDT hook detection will not be available.");
        // This is a critical scenario for this feature.
        // Depending on policy, could return error or allow driver to load with this feature disabled.
        return STATUS_NOT_FOUND;
    }

    CS_LOG_INFO("KeServiceDescriptorTable found at %p.", g_KeServiceDescriptorTable);
    // Further validation of the table can be done here if necessary
    if (g_KeServiceDescriptorTable->ServiceTableBase == NULL || g_KeServiceDescriptorTable->NumberOfServices == 0) {
        CS_LOG_ERROR("KeServiceDescriptorTable appears invalid (NULL ServiceTableBase or Zero services).");
        g_KeServiceDescriptorTable = NULL; // Mark as invalid
        return STATUS_UNSUCCESSFUL;
    }

    CS_LOG_INFO("SSDT (KiServiceTable) found at %p with %lu services.",
        g_KeServiceDescriptorTable->ServiceTableBase,
        (ULONG)g_KeServiceDescriptorTable->NumberOfServices); // Cast NumberOfServices for logging consistency

    return STATUS_SUCCESS;
}


/**
 * @brief Retrieves the base address and size of ntoskrnl.exe.
 * @details Uses ZwQuerySystemInformation to find ntoskrnl.exe in the list of loaded modules.
 *
 * @param ModuleInfo Pointer to KERNEL_MODULE_INFO structure to be filled.
 * @return NTSTATUS Status of the operation. STATUS_SUCCESS on success.
 * @note This function should be called at PASSIVE_LEVEL.
 */
NTSTATUS GetNtoskrnlBoundaries(
    _Out_ PKERNEL_MODULE_INFO ModuleInfo
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PRTL_PROCESS_MODULES pModules = NULL;
    ULONG ulModulesSize = 0;
    ULONG ulReturnLength = 0;
    ANSI_STRING ntoskrnlNameAnsi;
    UNICODE_STRING ntoskrnlNameUnicode;

    PAGED_CODE(); // Ensure running at PASSIVE_LEVEL
    CS_ASSERT_IRQL_PASSIVE();

    if (ModuleInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ModuleInfo->BaseAddress = NULL;
    ModuleInfo->Size = 0;

    // Initialize the target module name
    RtlInitAnsiString(&ntoskrnlNameAnsi, "ntoskrnl.exe"); // Case-insensitive comparison will be done

    // First call to get the required buffer size
    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &ulReturnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        CS_LOG_ERROR("ZwQuerySystemInformation failed to get buffer size. Status: 0x%X", status);
        return status;
    }

    if (ulReturnLength == 0) {
        CS_LOG_ERROR("ZwQuerySystemInformation returned zero length for module info.");
        return STATUS_UNSUCCESSFUL;
    }

    ulModulesSize = ulReturnLength; // Use the returned length
    pModules = (PRTL_PROCESS_MODULES)CS_ALLOCATE_POOL(PagedPool, ulModulesSize); // PagedPool is appropriate here
    if (pModules == NULL) {
        CS_LOG_ERROR("Failed to allocate memory for module information. Size: %lu", ulModulesSize);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Second call to get the actual module information
    status = ZwQuerySystemInformation(SystemModuleInformation, pModules, ulModulesSize, &ulReturnLength);
    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("ZwQuerySystemInformation failed to get module list. Status: 0x%X", status);
        CS_FREE_POOL(pModules);
        return status;
    }

    // Iterate through the modules to find ntoskrnl.exe
    for (ULONG i = 0; i < pModules->NumberOfModules; i++) {
        // The FullPathName is a CHAR array. We need to compare it with "ntoskrnl.exe".
        // The OffsetToFileName gives the offset into FullPathName where the actual file name starts.
        ANSI_STRING currentModuleNameAnsi;
        RtlInitAnsiString(&currentModuleNameAnsi, (PCSZ)(pModules->Modules[i].FullPathName + pModules->Modules[i].OffsetToFileName));

        // For robust comparison, convert both to Unicode and compare, or use RtlEqualString with case insensitivity if sure about ANSI.
        // Here, we'll do a case-insensitive ANSI comparison for simplicity, assuming standard module names.
        // A more robust way would be to convert currentModuleNameAnsi to Unicode first.
        if (RtlCompareString(&currentModuleNameAnsi, &ntoskrnlNameAnsi, TRUE) == 0) { // TRUE for CaseInsensitive
            ModuleInfo->BaseAddress = pModules->Modules[i].ImageBase;
            ModuleInfo->Size = pModules->Modules[i].ImageSize;
            CS_LOG_INFO("Found ntoskrnl.exe. Base: %p, Size: 0x%lX", ModuleInfo->BaseAddress, ModuleInfo->Size);
            status = STATUS_SUCCESS;
            break;
        }
    }

    CS_FREE_POOL(pModules);

    if (!NT_SUCCESS(status) || ModuleInfo->BaseAddress == NULL) {
        CS_LOG_ERROR("ntoskrnl.exe module not found in the list.");
        status = STATUS_NOT_FOUND; // More specific error
    }

    // Store globally if successful
    if(NT_SUCCESS(status)) {
        g_NtoskrnlInfo.BaseAddress = ModuleInfo->BaseAddress;
        g_NtoskrnlInfo.Size = ModuleInfo->Size;
    }

    return status;
}

/**
 * @brief Checks if the SSDT has been hooked.
 * @details Iterates through SSDT entries and checks if any service points outside ntoskrnl.exe.
 * @return BOOLEAN TRUE if a hook is detected, FALSE otherwise.
 * @warning This function should be called carefully, considering IRQL and SSDT access specifics.
 *          Accessing SSDT directly is highly version-dependent and can be unstable.
 *          This is a placeholder and needs a robust way to find SSDT.
 */
BOOLEAN IsSdtHooked(VOID)
{
    // CS_ASSERT_IRQL_DISPATCH_LEVEL_OR_BELOW(); // Or specific IRQL if known

    // Placeholder: SSDT detection is complex and architecture-dependent.
    // A robust implementation requires finding KeServiceDescriptorTable,
    // which is not directly exported on all Windows versions.
    // This often involves pattern scanning or using known offsets (unreliable).

    if (g_NtoskrnlInfo.BaseAddress == NULL || g_NtoskrnlInfo.Size == 0) {
        CS_LOG_WARNING("Ntoskrnl.exe boundaries not initialized. Cannot perform SSDT check.");
        // Attempt to initialize them now. This might be problematic if called at high IRQL.
        // For now, assume it's called where GetNtoskrnlBoundaries can run or has already run.
        // A better design would ensure GetNtoskrnlBoundaries is called during driver init.
        NTSTATUS init_status = GetNtoskrnlBoundaries(&g_NtoskrnlInfo); // This call might fail if not at PASSIVE_LEVEL
        if (!NT_SUCCESS(init_status) || g_NtoskrnlInfo.BaseAddress == NULL) {
             CS_LOG_ERROR("Failed to get ntoskrnl boundaries for SSDT check. Status: 0x%X", init_status);
             return FALSE; // Cannot proceed
        }
    }

    PVOID pSdtServiceAddress = NULL;
    ULONG_PTR ulNtoskrnlStart = (ULONG_PTR)g_NtoskrnlInfo.BaseAddress;
    ULONG_PTR ulNtoskrnlEnd = ulNtoskrnlStart + g_NtoskrnlInfo.Size;
    PULONG pServiceTable = NULL;
    ULONG_PTR ulNumberOfServices = 0;

    // This function might be called at DISPATCH_LEVEL by the DPC timer.
    // Ensure g_NtoskrnlInfo and g_KeServiceDescriptorTable are initialized.
    if (g_NtoskrnlInfo.BaseAddress == NULL || g_NtoskrnlInfo.Size == 0) {
        CS_LOG_WARNING("Ntoskrnl.exe boundaries not initialized. Cannot perform SSDT check.");
        // It's too late/dangerous to call GetNtoskrnlBoundaries here if at DISPATCH_LEVEL
        return FALSE;
    }

    if (g_KeServiceDescriptorTable == NULL || g_KeServiceDescriptorTable->ServiceTableBase == NULL) {
        CS_LOG_WARNING("KeServiceDescriptorTable not initialized or invalid. Cannot perform SSDT check.");
        return FALSE; // SSDT not found or invalid.
    }

    pServiceTable = g_KeServiceDescriptorTable->ServiceTableBase;
    ulNumberOfServices = g_KeServiceDescriptorTable->NumberOfServices;

    // Iterate through the SSDT entries
    for (ULONG_PTR i = 0; i < ulNumberOfServices; i++) {
        // On x64, SSDT entries are relative offsets from ServiceTableBase.
        // Each entry is a 32-bit signed offset, shifted right by 4 bits.
        // ServiceAddress = ServiceTableBase + (SSDTEntry >> 4)
        // On x86, SSDT entries are direct pointers.
#ifdef _WIN64
        // SSDT entries are relative offsets from ServiceTableBase.
        // The value in the table is an offset relative to KiServiceTable.
        // Each entry is a LONG (signed 32-bit integer).
        // The actual address is KiServiceTable + (KiServiceTable[i] >> 4).
        // This is a simplification; direct access is complex due to PatchGuard.
        // For demonstration, let's assume a more direct model or that this is a shadow SSDT if accessible.
        // A common way to get the address:
        // LONG relativeOffset = ((PLONG)pServiceTable)[i];
        // pSdtServiceAddress = (PVOID)((ULONG_PTR)pServiceTable + (relativeOffset >> 4));
        // However, direct reading of SSDT on x64 can be tricky and might lead to BSOD if not handled carefully
        // due to PatchGuard. This example assumes we *can* read it.
        // A more common method for user-mode hooks is to check the first few bytes of the function for JMPs.
        // For kernel hooks, if another driver has hooked, it has modified this table.

        // For simplicity and focusing on the boundary check:
        // Let's assume pServiceTable[i] gives us something usable to derive an address.
        // THIS IS A MAJOR SIMPLIFICATION FOR x64 and likely incorrect for live protected systems.
        // Proper SSDT parsing on x64 is significantly more complex.
        // If ServiceTableBase directly contains pointers (e.g. shadow SSDT or older/unprotected systems):
        // pSdtServiceAddress = (PVOID)((PULONG_PTR)pServiceTable)[i];

        // Given the structure definition KSERVICE_DESCRIPTOR_TABLE_ENTRY where ServiceTableBase is PULONG,
        // it implies that ServiceTableBase itself is the array of function pointers (or offsets for x64).
        // For x64, the values in ServiceTableBase[i] are offsets.
        // Address = (char*)ServiceTableBase + ServiceTableBase[i]
        // This is a common interpretation for KiServiceTable.
        // Let's take the entry as a relative offset from the table base itself.
        // This is one of the ways SSDT entries are structured on x64.
        // ServiceAddress = KeServiceDescriptorTable->ServiceTableBase + KeServiceDescriptorTable->ServiceTableBase[i]
        // No, that's not right. It's:
        // TargetAddress = (PBYTE)ServiceTableBase + (ServiceTableBase[i] >> 4) (for some versions)
        // Or:
        // TargetAddress = (PVOID) ServiceTableBase[i] (if it's an array of pointers, less common for main SSDT on x64)

        // Let's assume ServiceTableBase is an array of pointers for simplicity, though this is often not the case for the primary SSDT on x64.
        // If it were an array of direct pointers:
        // pSdtServiceAddress = (PVOID)((PULONG_PTR)pServiceTable)[i];
        // If it's an array of relative offsets (from ServiceTableBase):
        // This part is highly architecture and version specific.
        // A truly robust solution needs careful research for target Windows versions.
        // For now, we will assume a model where pServiceTable[i] is an offset from ServiceTableBase.
        // This is a common pattern for the primary SSDT (KiServiceTable).
        // Each entry is a signed 32-bit value. The actual offset is this value >> 4.
        // So, address = (PBYTE)pServiceTable + (((PLONG)pServiceTable)[i] >> 4);

        // Let's use a simplified access model for demonstration, assuming ServiceTableBase holds direct pointers or easily calculable ones.
        // This is often true for Shadow SSDTs or specific system configurations.
        // If KeServiceDescriptorTable->ServiceTableBase points to an array of ULONG_PTRs (function pointers):
        pSdtServiceAddress = (PVOID)((PULONG_PTR)pServiceTable)[i];


#else // _WIN32
        // On x86, SSDT entries are direct pointers.
        pSdtServiceAddress = (PVOID)(pServiceTable[i]);
#endif

        if (pSdtServiceAddress == NULL) continue; // Skip NULL entries if any

        // Check if the service address is outside ntoskrnl.exe module boundaries
        if ((ULONG_PTR)pSdtServiceAddress < ulNtoskrnlStart ||
            (ULONG_PTR)pSdtServiceAddress >= ulNtoskrnlEnd) {

            // To avoid false positives from legitimate hooks by other trusted kernel modules (e.g., other AVs, system components),
            // one might need a whitelist or further checks (e.g., is the hooked address in another known, signed module?).
            // For this exercise, any address outside ntoskrnl.exe is considered a hook.
            CS_LOG_ERROR("SSDT Hook Detected! Service index %lu (Address: %p) points outside ntoskrnl.exe (%p - %p).",
                         (ULONG)i, pSdtServiceAddress, (PVOID)ulNtoskrnlStart, (PVOID)ulNtoskrnlEnd);
            return TRUE; // Hook detected
        }
    }

    CS_LOG_TRACE("IsSdtHooked: No SSDT hooks detected pointing outside ntoskrnl.exe.");
    return FALSE; // No hooks detected
}
