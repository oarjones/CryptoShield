/**
 * @file CallbackProtection.h
 * @brief Function declarations for callback table protection mechanisms.
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

#ifndef _CALLBACK_PROTECTION_H_
#define _CALLBACK_PROTECTION_H_

#include <fltKernel.h> // For PFLT_FILTER type

// ----- Function Declarations -----

/**
 * @brief Initializes the callback protection mechanism.
 * @details Backs up the filter callback table and sets up a periodic integrity check.
 * @param filterHandle Handle to the filter object.
 * @return NTSTATUS Status of the operation.
 * @remarks Must be called at PASSIVE_LEVEL.
 */
NTSTATUS InitializeCallbackProtection(
    _In_ PFLT_FILTER filterHandle
);

/**
 * @brief Cleans up resources used by the callback protection mechanism.
 * @details Stops the integrity check timer and frees the backup table memory.
 * @remarks Must be called at PASSIVE_LEVEL.
 */
VOID CleanupCallbackProtection(VOID);

// Note: IntegrityCheckDpcRoutine is not declared here as it's typically not called directly
// from outside CallbackProtection.c. It's registered as a DPC routine.

#endif // _CALLBACK_PROTECTION_H_
