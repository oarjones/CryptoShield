/**
 * @file MemoryIntegrity.h
 * @brief Memory integrity verification and protection interface
 * @details Provides mechanisms to protect and verify critical memory regions
 *
 * @author CryptoShield Team
 * @date 2025
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#pragma once

//#include <ntddk.h>
#include <fltKernel.h>
#include "SelfProtection.h"

 // Memory protection flags
#define MEMORY_PROTECT_READ_ONLY        0x00000001
#define MEMORY_PROTECT_NO_EXECUTE       0x00000002
#define MEMORY_PROTECT_GUARD_PAGE       0x00000004
#define MEMORY_PROTECT_HASH_VERIFY      0x00000008
#define MEMORY_PROTECT_ENCRYPT          0x00000010
#define MEMORY_PROTECT_CRITICAL         0x00000020

// Integrity check methods
#define INTEGRITY_CHECK_CRC32           0x00000001
#define INTEGRITY_CHECK_SHA256          0x00000002
#define INTEGRITY_CHECK_CUSTOM          0x00000004
#define INTEGRITY_CHECK_PATTERN         0x00000008
#define INTEGRITY_CHECK_ALL             0x0000000F

// Maximum values
#define MAX_MEMORY_REGIONS              32
#define MAX_BACKUP_COPIES               3
#define MAX_HASH_SIZE                   32  // SHA256 size
#define INTEGRITY_PATTERN_SIZE          16

// Memory region structure
typedef struct _MEMORY_REGION {
    PVOID BaseAddress;
    SIZE_T Size;
    ULONG ProtectionFlags;
    ULONG CheckMethod;

    // Integrity verification data
    union {
        ULONG Crc32;
        UCHAR Sha256[MAX_HASH_SIZE];
        ULONG CustomChecksum;
    } Hash;

    // Backup information
    PVOID BackupAddresses[MAX_BACKUP_COPIES];
    ULONG BackupCount;
    ULONG CurrentBackupIndex;

    // Metadata
    BOOLEAN IsProtected;
    BOOLEAN IsLocked;
    LARGE_INTEGER LastVerified;
    LARGE_INTEGER LastModified;
    ULONG VerificationCount;
    ULONG CorruptionCount;

    // Memory descriptor
    PMDL RegionMdl;
    PVOID MappedAddress;

    // Pattern for quick validation
    UCHAR ValidationPattern[INTEGRITY_PATTERN_SIZE];

} MEMORY_REGION, * PMEMORY_REGION;

// Integrity context structure
typedef struct _INTEGRITY_CONTEXT {
    // Region management
    MEMORY_REGION Regions[MAX_MEMORY_REGIONS];
    ULONG RegionCount;
    ULONG ActiveRegions;

    // Synchronization
    KSPIN_LOCK IntegrityLock;
    ERESOURCE RegionResource;

    // Configuration
    ULONG VerificationInterval;     // in milliseconds
    ULONG DefaultCheckMethod;
    BOOLEAN AutoRepairEnabled;
    BOOLEAN EncryptionEnabled;

    // Statistics
    ULONG TotalVerifications;
    ULONG TotalCorruptions;
    ULONG SuccessfulRepairs;
    ULONG FailedRepairs;

    // Encryption key (if enabled)
    UCHAR EncryptionKey[32];
    BOOLEAN KeyInitialized;

} INTEGRITY_CONTEXT, * PINTEGRITY_CONTEXT;

// Corruption event structure
typedef struct _CORRUPTION_EVENT {
    PVOID Address;
    SIZE_T Size;
    ULONG RegionIndex;
    LARGE_INTEGER Timestamp;
    ULONG CorruptionType;
    ULONG ProcessId;
    ULONG ThreadId;
    BOOLEAN RepairAttempted;
    BOOLEAN RepairSuccessful;
} CORRUPTION_EVENT, * PCORRUPTION_EVENT;

// Function declarations

/**
 * @brief Initialize memory integrity system
 * @param Context Protection context
 * @return Allocated integrity context or NULL
 */
PINTEGRITY_CONTEXT InitializeMemoryIntegrity(
    _In_ PPROTECTION_CONTEXT Context
);

/**
 * @brief Cleanup memory integrity system
 * @param IntegrityContext Integrity context to cleanup
 */
VOID CleanupMemoryIntegrity(
    _In_ PINTEGRITY_CONTEXT IntegrityContext
);

// Region management functions

/**
 * @brief Add protected memory region
 * @param Context Integrity context
 * @param BaseAddress Start address of region
 * @param Size Size of region
 * @param ProtectionFlags Protection flags
 * @param CheckMethod Integrity check method
 * @return STATUS_SUCCESS on success
 */
NTSTATUS AddProtectedMemoryRegion(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _In_ ULONG ProtectionFlags,
    _In_ ULONG CheckMethod
);

/**
 * @brief Remove protected memory region
 * @param Context Integrity context
 * @param BaseAddress Start address of region
 * @return STATUS_SUCCESS on success
 */
NTSTATUS RemoveProtectedMemoryRegion(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PVOID BaseAddress
);

/**
 * @brief Find memory region by address
 * @param Context Integrity context
 * @param Address Address to search
 * @return Region pointer or NULL
 */
PMEMORY_REGION FindMemoryRegion(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PVOID Address
);

// Protection functions

/**
 * @brief Apply memory protection to region
 * @param Region Memory region
 * @param NewProtection New protection flags
 * @return STATUS_SUCCESS on success
 */
NTSTATUS ApplyMemoryProtection(
    _In_ PMEMORY_REGION Region,
    _In_ ULONG NewProtection
);

/**
 * @brief Lock memory region pages
 * @param Region Memory region
 * @return STATUS_SUCCESS on success
 */
NTSTATUS LockMemoryRegion(
    _In_ PMEMORY_REGION Region
);

/**
 * @brief Unlock memory region pages
 * @param Region Memory region
 * @return STATUS_SUCCESS on success
 */
NTSTATUS UnlockMemoryRegion(
    _In_ PMEMORY_REGION Region
);

// Verification functions

/**
 * @brief Verify single region integrity
 * @param Context Integrity context
 * @param Region Memory region to verify
 * @return TRUE if integrity valid
 */
BOOLEAN VerifyRegionIntegrity(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region
);

/**
 * @brief Verify all protected regions
 * @param Context Integrity context
 * @return Number of corrupted regions
 */
ULONG VerifyAllRegions(
    _In_ PINTEGRITY_CONTEXT Context
);

/**
 * @brief Calculate region hash
 * @param Region Memory region
 * @param Method Check method to use
 * @param HashBuffer Output hash buffer
 * @param HashSize Size of hash buffer
 * @return STATUS_SUCCESS on success
 */
NTSTATUS CalculateRegionHash(
    _In_ PMEMORY_REGION Region,
    _In_ ULONG Method,
    _Out_writes_bytes_(HashSize) PVOID HashBuffer,
    _In_ ULONG HashSize
);

// Backup and repair functions

/**
 * @brief Create backup of memory region
 * @param Context Integrity context
 * @param Region Memory region to backup
 * @return STATUS_SUCCESS on success
 */
NTSTATUS CreateRegionBackup(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region
);

/**
 * @brief Restore region from backup
 * @param Context Integrity context
 * @param Region Memory region to restore
 * @param BackupIndex Backup index to use (-1 for latest)
 * @return STATUS_SUCCESS on success
 */
NTSTATUS RestoreRegionFromBackup(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region,
    _In_ LONG BackupIndex
);

/**
 * @brief Rotate region backups
 * @param Region Memory region
 */
VOID RotateRegionBackups(
    _In_ PMEMORY_REGION Region
);

/**
 * @brief Auto-repair corrupted region
 * @param Context Integrity context
 * @param Region Corrupted region
 * @param Event Corruption event details
 * @return STATUS_SUCCESS if repaired
 */
NTSTATUS AutoRepairRegion(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region,
    _In_ PCORRUPTION_EVENT Event
);

// Advanced features

/**
 * @brief Enable memory encryption for region
 * @param Context Integrity context
 * @param Region Memory region
 * @return STATUS_SUCCESS on success
 */
NTSTATUS EnableRegionEncryption(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region
);

/**
 * @brief Disable memory encryption for region
 * @param Context Integrity context
 * @param Region Memory region
 * @return STATUS_SUCCESS on success
 */
NTSTATUS DisableRegionEncryption(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region
);

/**
 * @brief Set guard pages around region
 * @param Region Memory region
 * @return STATUS_SUCCESS on success
 */
NTSTATUS SetRegionGuardPages(
    _In_ PMEMORY_REGION Region
);

/**
 * @brief Handle page fault in protected region
 * @param Context Integrity context
 * @param FaultAddress Fault address
 * @param FaultType Type of fault
 * @return TRUE if handled
 */
BOOLEAN HandleProtectedPageFault(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PVOID FaultAddress,
    _In_ ULONG FaultType
);

// Utility functions

/**
 * @brief Calculate CRC32 checksum
 * @param Buffer Data buffer
 * @param Length Buffer length
 * @return CRC32 value
 */
ULONG CalculateCrc32(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
);

/**
 * @brief Calculate SHA256 hash
 * @param Buffer Data buffer
 * @param Length Buffer length
 * @param Hash Output hash buffer (32 bytes)
 * @return STATUS_SUCCESS on success
 */
NTSTATUS CalculateSha256(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(32) PUCHAR Hash
);

/**
 * @brief Generate validation pattern
 * @param Pattern Output pattern buffer
 * @param Size Pattern size
 */
VOID GenerateValidationPattern(
    _Out_writes_bytes_(Size) PUCHAR Pattern,
    _In_ ULONG Size
);

/**
 * @brief Compare memory safely
 * @param Buffer1 First buffer
 * @param Buffer2 Second buffer
 * @param Length Length to compare
 * @return TRUE if equal
 */
BOOLEAN SafeCompareMemory(
    _In_reads_bytes_(Length) PVOID Buffer1,
    _In_reads_bytes_(Length) PVOID Buffer2,
    _In_ SIZE_T Length
);

// Logging and statistics

/**
 * @brief Log corruption event
 * @param Context Integrity context
 * @param Event Corruption event
 */
VOID LogCorruptionEvent(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PCORRUPTION_EVENT Event
);

/**
 * @brief Get integrity statistics
 * @param Context Integrity context
 * @param TotalRegions Output total regions
 * @param CorruptedRegions Output corrupted count
 * @param RepairSuccess Output repair success rate
 */
VOID GetIntegrityStatistics(
    _In_ PINTEGRITY_CONTEXT Context,
    _Out_opt_ PULONG TotalRegions,
    _Out_opt_ PULONG CorruptedRegions,
    _Out_opt_ PULONG RepairSuccess
);

/**
 * @brief Dump region information
 * @param Region Memory region
 */
VOID DumpRegionInfo(
    _In_ PMEMORY_REGION Region
);
