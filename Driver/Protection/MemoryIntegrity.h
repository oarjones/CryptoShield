/**
 * @file MemoryIntegrity.h
 * @brief Header file for driver memory integrity checking mechanisms.
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#include <ntifs.h> // For PDRIVER_OBJECT, PVOID, ULONG, ULONG64, BOOLEAN, NTSTATUS
#include <wdm.h>   // General WDM definitions

/**
 * @brief Initializes the driver memory integrity protection.
 * @details Calculates and stores an initial checksum of the driver's code section.
 *          This function is called from DriverEntry at PASSIVE_LEVEL.
 *
 * @param DriverObject Pointer to the driver object for this driver.
 * @return NTSTATUS Status of the operation.
 */
NTSTATUS InitializeMemoryIntegrity(
    _In_ PDRIVER_OBJECT DriverObject
);

/**
 * @brief Checks if the driver's memory integrity is intact.
 * @details Recalculates the checksum of the driver's code and compares it
 *          with the initially stored checksum. This can be called periodically,
 *          potentially from a DPC routine.
 *
 * @return BOOLEAN TRUE if the checksums match (memory is intact), FALSE otherwise.
 */
BOOLEAN IsDriverMemoryIntact(VOID);

/**
 * @brief Cleans up resources or context related to memory integrity protection.
 * @details Called from FilterUnloadCallback at PASSIVE_LEVEL.
 */
VOID CleanupMemoryIntegrity(VOID);

// Note: CalculateDriverChecksum is not exposed in this header as it's considered
// an internal helper function to MemoryIntegrity.c. If it were needed elsewhere,
// it would be declared here.

// Ensure this file can be included multiple times without error
#ifndef MEMORY_INTEGRITY_H
#define MEMORY_INTEGRITY_H

// Content of the header is already above, this is just a common guard pattern.
// However, #pragma once achieves the same for MSVC and compatible compilers.
// For maximum portability, both can be used, but #pragma once is idiomatic here.

#endif // MEMORY_INTEGRITY_H
