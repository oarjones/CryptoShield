/**
 * @file MemoryIntegrity.c
 * @brief Implements driver memory integrity checking mechanisms for CryptoShield.
 * @details This file contains functions to calculate and verify a checksum of the
 *          driver's own code in memory to detect tampering.
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "MemoryIntegrity.h"
#include "../CryptoShield.h" // Access to g_Context, CS_LOG_*, CS_ASSERT_IRQL_PASSIVE
#include <ntstatus.h> // Added for STATUS_OBJECT_NOT_INITIALIZED

/**
 * @brief Calculates a checksum of the specified memory region.
 * @details This function computes a simple checksum (e.g., XOR sum) for the given data.
 *          A more robust algorithm like CRC32 could be used in a production system.
 *
 * @param ImageBase Pointer to the base of the memory region.
 * @param ImageSize Size of the memory region in bytes.
 * @param pChecksum Pointer to a ULONG64 to store the calculated checksum.
 * @return NTSTATUS Status of the operation. STATUS_SUCCESS on success.
 *
 * @note This function must be careful about page boundaries and memory accessibility
 *       if the region is large or its state is uncertain. For a driver's own image,
 *       it's generally safe if called at appropriate times.
 *       It should be callable at various IRQLs if necessary, but for initialization,
 *       PASSIVE_LEVEL is fine. If called from DPC (DISPATCH_LEVEL), ImageBase must be non-paged.
 *       The .text section of a driver is non-paged.
 */
static NTSTATUS XorSumChecksum(
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize,
    _Out_ PULONG64 pChecksum
)
{
    ULONG64 checksum = 0;
    PUCHAR  bytePtr = (PUCHAR)ImageBase;
    ULONG   i;

    // Parameter validation is expected to be done by the caller (CalculateDriverChecksum)
    // or implicitly by this function's usage context.
    // However, basic check for pChecksum is good.
    if (pChecksum == NULL) return STATUS_INVALID_PARAMETER; // ImageBase/ImageSize checked by caller

    *pChecksum = 0; // Initialize output

    // Simple checksum: sum of bytes XORed with an evolving value.
    // This is not cryptographically strong but serves as a basic integrity check.
    // Ensure this code is safe if ImageBase points to paged memory and this is called > PASSIVE_LEVEL
    // However, driver's .text section is non-paged.
    __try {
        for (i = 0; i < ImageSize; i++) {
            checksum = (checksum << 1) | (checksum >> 63); // Rotate left
            checksum ^= bytePtr[i];
        }
        *pChecksum = checksum;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS status = GetExceptionCode();
        CS_LOG_ERROR("Exception 0x%X while calculating XorSum checksum for memory at %p, size %lu.",
                     status, ImageBase, ImageSize);
        return status; // Or STATUS_ACCESS_VIOLATION
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Calculates a checksum of the specified memory region using a provided hash function.
 * @details This function acts as a wrapper to call the specified checksum algorithm.
 *
 * @param ImageBase Pointer to the base of the memory region.
 * @param ImageSize Size of the memory region in bytes.
 * @param pChecksum Pointer to a ULONG64 to store the calculated checksum.
 * @param HashFunction Pointer to the checksum function to use.
 * @return NTSTATUS Status of the operation. STATUS_SUCCESS on success.
 */
NTSTATUS CalculateDriverChecksum(
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize,
    _Out_ PULONG64 pChecksum,
    _In_ PCHECKSUM_FUNCTION HashFunction
)
{
    if (ImageBase == NULL || ImageSize == 0 || pChecksum == NULL || HashFunction == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Call the provided hash function
    return HashFunction(ImageBase, ImageSize, pChecksum);
}

/**
 * @brief Initializes the driver memory integrity protection.
 * @details Calculates and stores an initial checksum of the driver's code section.
 *          This function is called from DriverEntry.
 *
 * @param DriverObject Pointer to the driver object for this driver.
 * @return NTSTATUS Status of the operation.
 */
NTSTATUS InitializeMemoryIntegrity(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS status;

    PAGED_CODE(); // Should be called at PASSIVE_LEVEL
    CS_ASSERT_IRQL_PASSIVE();

    if (DriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Store driver image base and size in global context
    // DriverObject->DriverStart and DriverObject->DriverSize are valid after DriverEntry's main work.
    g_Context.DriverImageBase = DriverObject->DriverStart;
    g_Context.DriverImageSize = DriverObject->DriverSize;

    if (g_Context.DriverImageBase == NULL || g_Context.DriverImageSize == 0) {
        CS_LOG_ERROR("Driver image base or size is invalid. Base: %p, Size: %lu",
                     g_Context.DriverImageBase, g_Context.DriverImageSize);
        return STATUS_UNSUCCESSFUL; // Or a more specific error
    }

    CS_LOG_INFO("Initializing memory integrity. Driver Base: %p, Size: %lu bytes.",
                g_Context.DriverImageBase, g_Context.DriverImageSize);

    // Calculate and store the initial checksum
    status = CalculateDriverChecksum(
        g_Context.DriverImageBase,
        g_Context.DriverImageSize,
        &g_Context.InitialDriverChecksum,
        XorSumChecksum // Pass the XorSumChecksum function
    );

    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("Failed to calculate initial driver checksum. Status: 0x%X", status);
        // Clear stored values if checksum calculation failed
        g_Context.DriverImageBase = NULL;
        g_Context.DriverImageSize = 0;
        g_Context.InitialDriverChecksum = 0;
        return status;
    }

    CS_LOG_INFO("Initial driver checksum calculated: 0x%llX", g_Context.InitialDriverChecksum);
    return STATUS_SUCCESS;
}

/**
 * @brief Checks if the driver's memory integrity is intact.
 * @details Recalculates the checksum of the driver's code and compares it
 *          with the initially stored checksum.
 *
 * @param IsIntact Pointer to a BOOLEAN that will receive TRUE if memory is intact, FALSE otherwise.
 *                 This value is only valid if the function returns STATUS_SUCCESS.
 * @return NTSTATUS Status of the operation. STATUS_SUCCESS if the check was performed,
 *         or an error code if checksum calculation failed.
 *
 * @note This function can be called from a DPC routine (DISPATCH_LEVEL).
 *       It relies on g_Context.DriverImageBase and g_Context.DriverImageSize
 *       being valid and pointing to non-paged memory (driver's code section).
 */
NTSTATUS IsDriverMemoryIntact(
    _Out_ PBOOLEAN IsIntact
)
{
    ULONG64 currentChecksum = 0;
    NTSTATUS status;

    // CS_ASSERT_IRQL_DISPATCH_LEVEL_OR_BELOW(); // Or the specific IRQL it's designed for

    if (IsIntact == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *IsIntact = FALSE; // Default to not intact or error state

    if (g_Context.DriverImageBase == NULL || g_Context.DriverImageSize == 0) {
        CS_LOG_WARNING("Driver image base or size not initialized. Cannot verify memory integrity.");
        // Consider if this case should return an error or STATUS_SUCCESS with IsIntact = TRUE (fail-safe).
        // For this refactoring, let's treat it as a setup issue that prevents checking.
        // However, the original logic returned TRUE (fail-safe).
        // To maintain similar behavior for the "unable to check" scenario, we could return success and IsIntact = TRUE.
        // But the request implies differentiating errors from tampering.
        // Let's return an error indicating configuration issue.
        return STATUS_OBJECT_NOT_INITIALIZED; // Or a custom status
    }

    status = CalculateDriverChecksum(
        g_Context.DriverImageBase,
        g_Context.DriverImageSize,
        &currentChecksum,
        XorSumChecksum // Pass the XorSumChecksum function
    );

    if (!NT_SUCCESS(status)) {
        CS_LOG_ERROR("Failed to calculate current driver checksum during integrity check. Status: 0x%X", status);
        // IsIntact remains FALSE by default or previous assignment
        return status; // Return the error from CalculateDriverChecksum
    }

    if (currentChecksum != g_Context.InitialDriverChecksum) {
        CS_LOG_WARNING("Current driver checksum 0x%llX does not match initial checksum 0x%llX. Memory may be tampered.",
                       currentChecksum, g_Context.InitialDriverChecksum);
        *IsIntact = FALSE; // Checksums do not match, memory may have been tampered with.
    } else {
        *IsIntact = TRUE; // Checksums match.
        CS_LOG_TRACE("Driver memory integrity check passed. Checksum: 0x%llX", currentChecksum);
    }

    return STATUS_SUCCESS; // Check was performed successfully
}

/**
 * @brief Cleans up resources used by memory integrity protection.
 * @details Currently, this function mainly serves to clear context variables if needed.
 *          Called from FilterUnloadCallback.
 */
VOID CleanupMemoryIntegrity(VOID)
{
    PAGED_CODE();
    CS_ASSERT_IRQL_PASSIVE();

    CS_LOG_INFO("Cleaning up memory integrity protection.");

    // Clear the stored values in the global context
    // This is mostly for completeness, as they are simple types.
    g_Context.DriverImageBase = NULL;
    g_Context.DriverImageSize = 0;
    g_Context.InitialDriverChecksum = 0;

    CS_LOG_TRACE("Memory integrity context cleared.");
}
