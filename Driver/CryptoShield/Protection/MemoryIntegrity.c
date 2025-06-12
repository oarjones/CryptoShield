/**
 * @file MemoryIntegrity.c
 * @brief Implementation of memory integrity verification system
 * @details Provides protection and verification of critical memory regions
 *
 * @author CryptoShield Team
 * @date 2025
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "MemoryIntegrity.h"
#include <ntstrsafe.h>

 // Memory allocation tag
#define INTEGRITY_TAG 'tgnI'  // 'Intg' in little-endian

// CRC32 lookup table
static ULONG g_Crc32Table[256];
static BOOLEAN g_Crc32TableInitialized = FALSE;

// Forward declarations
static VOID InitializeCrc32Table(VOID);
static NTSTATUS AllocateRegionBackups(PMEMORY_REGION Region);
static VOID FreeRegionBackups(PMEMORY_REGION Region);

/**
 * @brief Initialize memory integrity system
 */
PINTEGRITY_CONTEXT InitializeMemoryIntegrity(
    _In_ PPROTECTION_CONTEXT Context)
{
    PINTEGRITY_CONTEXT integrityContext;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);

    DbgPrint("[CryptoShield] Initializing memory integrity system\n");

    // Allocate integrity context
    /*integrityContext = (PINTEGRITY_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(INTEGRITY_CONTEXT),
        INTEGRITY_TAG
    );*/
    integrityContext = (PINTEGRITY_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(INTEGRITY_CONTEXT),
        INTEGRITY_TAG
    );

    if (!integrityContext) {
        DbgPrint("[CryptoShield] Failed to allocate integrity context\n");
        return NULL;
    }

    RtlZeroMemory(integrityContext, sizeof(INTEGRITY_CONTEXT));

    // Initialize synchronization
    KeInitializeSpinLock(&integrityContext->IntegrityLock);
    status = ExInitializeResourceLite(&integrityContext->RegionResource);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[CryptoShield] Failed to initialize resource: 0x%08X\n", status);
        ExFreePoolWithTag(integrityContext, INTEGRITY_TAG);
        return NULL;
    }

    // Set default configuration
    integrityContext->VerificationInterval = 10000;  // 10 seconds
    integrityContext->DefaultCheckMethod = INTEGRITY_CHECK_CRC32;
    integrityContext->AutoRepairEnabled = TRUE;
    integrityContext->EncryptionEnabled = FALSE;

    // Initialize CRC32 table if needed
    if (!g_Crc32TableInitialized) {
        InitializeCrc32Table();
    }

    DbgPrint("[CryptoShield] Memory integrity system initialized\n");

    return integrityContext;
}

/**
 * @brief Cleanup memory integrity system
 */
VOID CleanupMemoryIntegrity(
    _In_ PINTEGRITY_CONTEXT IntegrityContext)
{
    ULONG i;

    if (!IntegrityContext) {
        return;
    }

    DbgPrint("[CryptoShield] Cleaning up memory integrity system\n");

    // Acquire exclusive access
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&IntegrityContext->RegionResource, TRUE);

    // Clean up all regions
    for (i = 0; i < IntegrityContext->RegionCount; i++) {
        PMEMORY_REGION region = &IntegrityContext->Regions[i];

        if (region->IsProtected) {
            // Unlock if locked
            if (region->IsLocked) {
                UnlockMemoryRegion(region);
            }

            // Free backups
            FreeRegionBackups(region);

            // Clear region
            region->IsProtected = FALSE;
        }
    }

    ExReleaseResourceLite(&IntegrityContext->RegionResource);
    KeLeaveCriticalRegion();

    // Delete resource
    ExDeleteResourceLite(&IntegrityContext->RegionResource);

    // Log final statistics
    DbgPrint("[CryptoShield] Integrity Statistics:\n");
    DbgPrint("  - Total verifications: %lu\n", IntegrityContext->TotalVerifications);
    DbgPrint("  - Total corruptions: %lu\n", IntegrityContext->TotalCorruptions);
    DbgPrint("  - Successful repairs: %lu\n", IntegrityContext->SuccessfulRepairs);
    DbgPrint("  - Failed repairs: %lu\n", IntegrityContext->FailedRepairs);

    // Free context
    ExFreePoolWithTag(IntegrityContext, INTEGRITY_TAG);
}

/**
 * @brief Add protected memory region
 */
NTSTATUS AddProtectedMemoryRegion(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size,
    _In_ ULONG ProtectionFlags,
    _In_ ULONG CheckMethod)
{
    PMEMORY_REGION region = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
    KIRQL oldIrql;

    if (!Context || !BaseAddress || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Validate check method
    if (!(CheckMethod & INTEGRITY_CHECK_ALL)) {
        CheckMethod = Context->DefaultCheckMethod;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Context->RegionResource, TRUE);

    __try {
        // Find free slot
        for (i = 0; i < MAX_MEMORY_REGIONS; i++) {
            if (!Context->Regions[i].IsProtected) {
                region = &Context->Regions[i];
                break;
            }
        }

        if (!region) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // Initialize region
        RtlZeroMemory(region, sizeof(MEMORY_REGION));
        region->BaseAddress = BaseAddress;
        region->Size = Size;
        region->ProtectionFlags = ProtectionFlags;
        region->CheckMethod = CheckMethod;

        // Generate validation pattern
        GenerateValidationPattern(region->ValidationPattern, INTEGRITY_PATTERN_SIZE);

        // Calculate initial hash
        status = CalculateRegionHash(region, CheckMethod, &region->Hash, sizeof(region->Hash));
        if (!NT_SUCCESS(status)) {
            DbgPrint("[CryptoShield] Failed to calculate initial hash: 0x%08X\n", status);
            __leave;
        }

        // Create backups if requested
        if (ProtectionFlags & MEMORY_PROTECT_CRITICAL) {
            status = AllocateRegionBackups(region);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[CryptoShield] Failed to allocate backups: 0x%08X\n", status);
                __leave;
            }

            // Create initial backup
            status = CreateRegionBackup(Context, region);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[CryptoShield] Failed to create initial backup: 0x%08X\n", status);
                FreeRegionBackups(region);
                __leave;
            }
        }

        // Lock memory if requested
        if (ProtectionFlags & MEMORY_PROTECT_READ_ONLY) {
            status = LockMemoryRegion(region);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[CryptoShield] Failed to lock region: 0x%08X\n", status);
                // Continue anyway
            }
        }

        // Mark as protected
        region->IsProtected = TRUE;
        KeQuerySystemTime(&region->LastVerified);
        region->LastModified = region->LastVerified;

        // Update context
        KeAcquireSpinLock(&Context->IntegrityLock, &oldIrql);
        Context->ActiveRegions++;
        if (i >= Context->RegionCount) {
            Context->RegionCount = i + 1;
        }
        KeReleaseSpinLock(&Context->IntegrityLock, oldIrql);

        DbgPrint("[CryptoShield] Protected region added: %p, Size: %zu, Method: 0x%X\n",
            BaseAddress, Size, CheckMethod);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception adding protected region: 0x%08X\n",
            GetExceptionCode());
        status = STATUS_UNHANDLED_EXCEPTION;
    }

    ExReleaseResourceLite(&Context->RegionResource);
    KeLeaveCriticalRegion();

    return status;
}

/**
 * @brief Verify single region integrity
 */
BOOLEAN VerifyRegionIntegrity(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region)
{
    BOOLEAN isValid = FALSE;
    union {
        ULONG Crc32;
        UCHAR Sha256[MAX_HASH_SIZE];
        ULONG CustomChecksum;
    } currentHash;
    NTSTATUS status;
    CORRUPTION_EVENT event = { 0 };

    if (!Context || !Region || !Region->IsProtected) {
        return FALSE;
    }

    Region->VerificationCount++;

    __try {
        // Calculate current hash
        RtlZeroMemory(&currentHash, sizeof(currentHash));
        status = CalculateRegionHash(Region, Region->CheckMethod,
            &currentHash, sizeof(currentHash));

        if (!NT_SUCCESS(status)) {
            DbgPrint("[CryptoShield] Failed to calculate hash for verification\n");
            return FALSE;
        }

        // Compare based on method
        if (Region->CheckMethod & INTEGRITY_CHECK_CRC32) {
            isValid = (currentHash.Crc32 == Region->Hash.Crc32);
        }
        else if (Region->CheckMethod & INTEGRITY_CHECK_SHA256) {
            isValid = RtlCompareMemory(currentHash.Sha256, Region->Hash.Sha256,
                MAX_HASH_SIZE) == MAX_HASH_SIZE;
        }
        else if (Region->CheckMethod & INTEGRITY_CHECK_CUSTOM) {
            isValid = (currentHash.CustomChecksum == Region->Hash.CustomChecksum);
        }

        // Update timestamp
        KeQuerySystemTime(&Region->LastVerified);

        if (!isValid) {
            Region->CorruptionCount++;
            Context->TotalCorruptions++;

            // Prepare corruption event
            event.Address = Region->BaseAddress;
            event.Size = Region->Size;
            event.RegionIndex = (ULONG)(Region - Context->Regions);
            KeQuerySystemTime(&event.Timestamp);
            event.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            event.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();

            LogCorruptionEvent(Context, &event);

            // Attempt auto-repair if enabled
            if (Context->AutoRepairEnabled && Region->BackupCount > 0) {
                status = AutoRepairRegion(Context, Region, &event);
                if (NT_SUCCESS(status)) {
                    DbgPrint("[CryptoShield] Region auto-repaired successfully\n");
                    isValid = TRUE;
                }
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception verifying region integrity\n");
        isValid = FALSE;
    }

    return isValid;
}

/**
 * @brief Verify all protected regions
 */
ULONG VerifyAllRegions(
    _In_ PINTEGRITY_CONTEXT Context)
{
    ULONG corruptedCount = 0;
    ULONG i;

    if (!Context) {
        return 0;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->RegionResource, TRUE);

    Context->TotalVerifications++;

    for (i = 0; i < Context->RegionCount; i++) {
        PMEMORY_REGION region = &Context->Regions[i];

        if (region->IsProtected) {
            if (!VerifyRegionIntegrity(Context, region)) {
                corruptedCount++;
            }
        }
    }

    ExReleaseResourceLite(&Context->RegionResource);
    KeLeaveCriticalRegion();

    return corruptedCount;
}

/**
 * @brief Calculate region hash
 */
NTSTATUS CalculateRegionHash(
    _In_ PMEMORY_REGION Region,
    _In_ ULONG Method,
    _Out_writes_bytes_(HashSize) PVOID HashBuffer,
    _In_ ULONG HashSize)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!Region || !HashBuffer || HashSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        if (Method & INTEGRITY_CHECK_CRC32) {
            if (HashSize < sizeof(ULONG)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            *(PULONG)HashBuffer = CalculateCrc32(Region->BaseAddress, (ULONG)Region->Size);
        }
        else if (Method & INTEGRITY_CHECK_SHA256) {
            if (HashSize < MAX_HASH_SIZE) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            status = CalculateSha256(Region->BaseAddress, (ULONG)Region->Size,
                (PUCHAR)HashBuffer);
        }
        else if (Method & INTEGRITY_CHECK_CUSTOM) {
            if (HashSize < sizeof(ULONG)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            // Simple custom checksum
            *(PULONG)HashBuffer = CalculateChecksum(Region->BaseAddress, (ULONG)Region->Size);
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception calculating hash\n");
        status = STATUS_UNHANDLED_EXCEPTION;
    }

    return status;
}

/**
 * @brief Create backup of memory region
 */
NTSTATUS CreateRegionBackup(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region)
{
    PVOID backupBuffer;
    ULONG backupIndex;

    UNREFERENCED_PARAMETER(Context);

    if (!Region || !Region->IsProtected || Region->Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Rotate backups if all slots are full
    if (Region->BackupCount >= MAX_BACKUP_COPIES) {
        RotateRegionBackups(Region);
        backupIndex = MAX_BACKUP_COPIES - 1;
    }
    else {
        backupIndex = Region->BackupCount;
    }

    // Allocate backup buffer if not already allocated
    if (!Region->BackupAddresses[backupIndex]) {
        /*backupBuffer = ExAllocatePoolWithTag(NonPagedPool, Region->Size, INTEGRITY_TAG);*/
        backupBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Region->Size, INTEGRITY_TAG);

        if (!backupBuffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Region->BackupAddresses[backupIndex] = backupBuffer;
    }

    __try {
        // Copy region to backup
        RtlCopyMemory(Region->BackupAddresses[backupIndex],
            Region->BaseAddress,
            Region->Size);

        // Update backup info
        Region->CurrentBackupIndex = backupIndex;
        if (Region->BackupCount < MAX_BACKUP_COPIES) {
            Region->BackupCount++;
        }

        DbgPrint("[CryptoShield] Created backup %lu for region %p\n",
            backupIndex, Region->BaseAddress);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception creating backup\n");
        return STATUS_UNHANDLED_EXCEPTION;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Restore region from backup
 */
NTSTATUS RestoreRegionFromBackup(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region,
    _In_ LONG BackupIndex)
{
    ULONG useIndex;

    UNREFERENCED_PARAMETER(Context);

    if (!Region || !Region->IsProtected || Region->BackupCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Determine which backup to use
    if (BackupIndex < 0) {
        useIndex = Region->CurrentBackupIndex;
    }
    else if ((ULONG)BackupIndex >= Region->BackupCount) {
        return STATUS_INVALID_PARAMETER;
    }
    else {
        useIndex = (ULONG)BackupIndex;
    }

    if (!Region->BackupAddresses[useIndex]) {
        return STATUS_NOT_FOUND;
    }

    __try {
        // Restore from backup
        RtlCopyMemory(Region->BaseAddress,
            Region->BackupAddresses[useIndex],
            Region->Size);

        // Recalculate hash
        CalculateRegionHash(Region, Region->CheckMethod, &Region->Hash, sizeof(Region->Hash));

        // Update timestamp
        KeQuerySystemTime(&Region->LastModified);

        DbgPrint("[CryptoShield] Restored region %p from backup %lu\n",
            Region->BaseAddress, useIndex);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception restoring from backup\n");
        return STATUS_UNHANDLED_EXCEPTION;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Auto-repair corrupted region
 */
NTSTATUS AutoRepairRegion(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region,
    _In_ PCORRUPTION_EVENT Event)
{
    NTSTATUS status;

    if (!Context || !Region || !Event) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[CryptoShield] Attempting auto-repair for region %p\n", Region->BaseAddress);

    Event->RepairAttempted = TRUE;

    // Try to restore from latest backup
    status = RestoreRegionFromBackup(Context, Region, -1);

    if (NT_SUCCESS(status)) {
        Context->SuccessfulRepairs++;
        Event->RepairSuccessful = TRUE;

        // Verify the repair
        if (VerifyRegionIntegrity(Context, Region)) {
            DbgPrint("[CryptoShield] Auto-repair successful\n");
        }
        else {
            DbgPrint("[CryptoShield] Auto-repair verification failed\n");
            status = STATUS_DATA_ERROR;
        }
    }
    else {
        Context->FailedRepairs++;
        Event->RepairSuccessful = FALSE;
        DbgPrint("[CryptoShield] Auto-repair failed: 0x%08X\n", status);
    }

    return status;
}

/**
 * @brief Lock memory region pages
 */
NTSTATUS LockMemoryRegion(
    _In_ PMEMORY_REGION Region)
{
    PMDL mdl;

    if (!Region || Region->IsLocked) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        // Create MDL
        mdl = IoAllocateMdl(Region->BaseAddress, (ULONG)Region->Size,
            FALSE, FALSE, NULL);

        if (!mdl) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Lock pages
        MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

        // Map to system space
        Region->MappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode,
            MmCached, NULL, FALSE,
            NormalPagePriority);

        if (!Region->MappedAddress) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Region->RegionMdl = mdl;
        Region->IsLocked = TRUE;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (mdl) {
            IoFreeMdl(mdl);
        }
        return STATUS_UNHANDLED_EXCEPTION;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Calculate CRC32 checksum
 */
ULONG CalculateCrc32(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length)
{
    PUCHAR data = (PUCHAR)Buffer;
    ULONG crc = 0xFFFFFFFF;
    ULONG i;

    if (!Buffer || Length == 0) {
        return 0;
    }

    for (i = 0; i < Length; i++) {
        crc = (crc >> 8) ^ g_Crc32Table[(crc ^ data[i]) & 0xFF];
    }

    return ~crc;
}

/**
 * @brief Calculate SHA256 hash (simplified version)
 */
NTSTATUS CalculateSha256(
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_writes_bytes_(32) PUCHAR Hash)
{
    // This is a simplified implementation
    // In production, use BCrypt APIs or a proper SHA256 implementation
    ULONG i;
    PUCHAR data = (PUCHAR)Buffer;

    if (!Buffer || !Hash || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Simple hash for demonstration
    RtlZeroMemory(Hash, 32);

    for (i = 0; i < Length && i < 32; i++) {
        Hash[i % 32] ^= data[i];
        Hash[(i + 1) % 32] ^= _rotl8(data[i], 3);
        Hash[(i + 2) % 32] ^= _rotl8(data[i], 5);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Initialize CRC32 lookup table
 */
static VOID InitializeCrc32Table(VOID)
{
    ULONG i, j;
    ULONG crc;

    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            }
            else {
                crc >>= 1;
            }
        }
        g_Crc32Table[i] = crc;
    }

    g_Crc32TableInitialized = TRUE;
}

/**
 * @brief Allocate region backups
 */
static NTSTATUS AllocateRegionBackups(PMEMORY_REGION Region)
{
    ULONG i;

    for (i = 0; i < MAX_BACKUP_COPIES; i++) {
        /*Region->BackupAddresses[i] = ExAllocatePoolWithTag(
            NonPagedPool,
            Region->Size,
            INTEGRITY_TAG
        );*/
        Region->BackupAddresses[i] = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            Region->Size,
            INTEGRITY_TAG
        );

        if (!Region->BackupAddresses[i]) {
            // Free already allocated
            FreeRegionBackups(Region);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Free region backups
 */
static VOID FreeRegionBackups(PMEMORY_REGION Region)
{
    ULONG i;

    for (i = 0; i < MAX_BACKUP_COPIES; i++) {
        if (Region->BackupAddresses[i]) {
            ExFreePoolWithTag(Region->BackupAddresses[i], INTEGRITY_TAG);
            Region->BackupAddresses[i] = NULL;
        }
    }

    Region->BackupCount = 0;
}

/**
 * @brief Rotate region backups
 */
VOID RotateRegionBackups(
    _In_ PMEMORY_REGION Region)
{
    PVOID oldest;
    ULONG i;

    if (!Region || Region->BackupCount == 0) {
        return;
    }

    // Save oldest backup pointer
    oldest = Region->BackupAddresses[0];

    // Shift backups
    for (i = 0; i < MAX_BACKUP_COPIES - 1; i++) {
        Region->BackupAddresses[i] = Region->BackupAddresses[i + 1];
    }

    // Move oldest to newest position
    Region->BackupAddresses[MAX_BACKUP_COPIES - 1] = oldest;
}

/**
 * @brief Generate validation pattern
 */
VOID GenerateValidationPattern(
    _Out_writes_bytes_(Size) PUCHAR Pattern,
    _In_ ULONG Size)
{
    ULONG i;
    LARGE_INTEGER time;

    KeQuerySystemTime(&time);

    for (i = 0; i < Size; i++) {
        Pattern[i] = (UCHAR)((time.LowPart >> i) ^ (time.HighPart >> (i + 8)));
    }
}

/**
 * @brief Log corruption event
 */
VOID LogCorruptionEvent(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PCORRUPTION_EVENT Event)
{
    UNREFERENCED_PARAMETER(Context);

    DbgPrint("[CryptoShield] MEMORY CORRUPTION DETECTED:\n");
    DbgPrint("  - Address: %p\n", Event->Address);
    DbgPrint("  - Size: %zu\n", Event->Size);
    DbgPrint("  - Region: %lu\n", Event->RegionIndex);
    DbgPrint("  - Process: %lu\n", Event->ProcessId);
    DbgPrint("  - Thread: %lu\n", Event->ThreadId);
    DbgPrint("  - Repair Attempted: %s\n", Event->RepairAttempted ? "Yes" : "No");
    DbgPrint("  - Repair Successful: %s\n", Event->RepairSuccessful ? "Yes" : "No");
}

 /**
  * @brief Unlock memory region pages
  */
NTSTATUS UnlockMemoryRegion(
    _In_ PMEMORY_REGION Region)
{
    if (!Region || !Region->IsLocked || !Region->RegionMdl) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        // Unmap pages if mapped
        if (Region->MappedAddress) {
            MmUnmapLockedPages(Region->MappedAddress, Region->RegionMdl);
            Region->MappedAddress = NULL;
        }

        // Unlock pages
        MmUnlockPages(Region->RegionMdl);

        // Free MDL
        IoFreeMdl(Region->RegionMdl);
        Region->RegionMdl = NULL;

        Region->IsLocked = FALSE;

        DbgPrint("[CryptoShield] Memory region unlocked: %p\n", Region->BaseAddress);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception unlocking memory region: 0x%08X\n",
            GetExceptionCode());
        return STATUS_UNHANDLED_EXCEPTION;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Remove protected memory region
 */
NTSTATUS RemoveProtectedMemoryRegion(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PVOID BaseAddress)
{
    ULONG i;
    PMEMORY_REGION region = NULL;
    KIRQL oldIrql;

    if (!Context || !BaseAddress) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Context->RegionResource, TRUE);

    __try {
        // Find region
        for (i = 0; i < Context->RegionCount; i++) {
            if (Context->Regions[i].IsProtected &&
                Context->Regions[i].BaseAddress == BaseAddress) {
                region = &Context->Regions[i];
                break;
            }
        }

        if (!region) {
            ExReleaseResourceLite(&Context->RegionResource);
            KeLeaveCriticalRegion();
            return STATUS_NOT_FOUND;
        }

        // Unlock if locked
        if (region->IsLocked) {
            UnlockMemoryRegion(region);
        }

        // Free backups
        FreeRegionBackups(region);

        // Clear region
        RtlZeroMemory(region, sizeof(MEMORY_REGION));

        // Update context
        KeAcquireSpinLock(&Context->IntegrityLock, &oldIrql);
        Context->ActiveRegions--;
        KeReleaseSpinLock(&Context->IntegrityLock, oldIrql);

        DbgPrint("[CryptoShield] Removed protected region: %p\n", BaseAddress);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception removing protected region: 0x%08X\n",
            GetExceptionCode());
        ExReleaseResourceLite(&Context->RegionResource);
        KeLeaveCriticalRegion();
        return STATUS_UNHANDLED_EXCEPTION;
    }

    ExReleaseResourceLite(&Context->RegionResource);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @brief Find memory region by address
 */
PMEMORY_REGION FindMemoryRegion(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PVOID Address)
{
    ULONG i;
    PMEMORY_REGION region = NULL;

    if (!Context || !Address) {
        return NULL;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->RegionResource, TRUE);

    for (i = 0; i < Context->RegionCount; i++) {
        if (Context->Regions[i].IsProtected) {
            PUCHAR regionStart = (PUCHAR)Context->Regions[i].BaseAddress;
            PUCHAR regionEnd = regionStart + Context->Regions[i].Size;

            if ((PUCHAR)Address >= regionStart && (PUCHAR)Address < regionEnd) {
                region = &Context->Regions[i];
                break;
            }
        }
    }

    ExReleaseResourceLite(&Context->RegionResource);
    KeLeaveCriticalRegion();

    return region;
}

/**
 * @brief Apply memory protection to region
 */
NTSTATUS ApplyMemoryProtection(
    _In_ PMEMORY_REGION Region,
    _In_ ULONG NewProtection)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMDL mdl = NULL;

    if (!Region || !Region->IsProtected) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        // Create MDL for protection change
        mdl = IoAllocateMdl(Region->BaseAddress, (ULONG)Region->Size,
            FALSE, FALSE, NULL);

        if (!mdl) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Lock pages
        MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

        // Apply new protection
        // Note: In kernel mode, we typically use MDLs and page descriptors
        // Direct page protection changes require careful handling

        if (NewProtection & MEMORY_PROTECT_READ_ONLY) {
            // Mark pages as read-only
            // This would require manipulating PTEs which is complex
            DbgPrint("[CryptoShield] Read-only protection requested for region %p\n",
                Region->BaseAddress);
        }

        if (NewProtection & MEMORY_PROTECT_NO_EXECUTE) {
            // Set NX bit on pages
            DbgPrint("[CryptoShield] No-execute protection requested for region %p\n",
                Region->BaseAddress);
        }

        // Update region protection flags
        Region->ProtectionFlags = NewProtection;

        // Unlock pages
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (mdl) {
            IoFreeMdl(mdl);
        }
        DbgPrint("[CryptoShield] Exception applying memory protection: 0x%08X\n",
            GetExceptionCode());
        return STATUS_UNHANDLED_EXCEPTION;
    }

    return status;
}

/**
 * @brief Enable memory encryption for region
 */
NTSTATUS EnableRegionEncryption(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region)
{
    if (!Context || !Region || !Context->EncryptionEnabled) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Context->KeyInitialized) {
        DbgPrint("[CryptoShield] Encryption key not initialized\n");
        return STATUS_ENCRYPTION_FAILED;
    }

    // Simple XOR encryption for demonstration
    // In production, use proper encryption APIs
    __try {
        PUCHAR data = (PUCHAR)Region->BaseAddress;
        SIZE_T i, keyIndex = 0;

        for (i = 0; i < Region->Size; i++) {
            data[i] ^= Context->EncryptionKey[keyIndex];
            keyIndex = (keyIndex + 1) % 32;
        }

        Region->ProtectionFlags |= MEMORY_PROTECT_ENCRYPT;

        DbgPrint("[CryptoShield] Region encrypted: %p\n", Region->BaseAddress);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception encrypting region: 0x%08X\n",
            GetExceptionCode());
        return STATUS_ENCRYPTION_FAILED;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Disable memory encryption for region
 */
NTSTATUS DisableRegionEncryption(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PMEMORY_REGION Region)
{
    if (!Context || !Region) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!(Region->ProtectionFlags & MEMORY_PROTECT_ENCRYPT)) {
        return STATUS_SUCCESS; // Already unencrypted
    }

    // Decrypt using same XOR method
    NTSTATUS status = EnableRegionEncryption(Context, Region);

    if (NT_SUCCESS(status)) {
        Region->ProtectionFlags &= ~MEMORY_PROTECT_ENCRYPT;
        DbgPrint("[CryptoShield] Region decrypted: %p\n", Region->BaseAddress);
    }

    return status;
}

/**
 * @brief Set guard pages around region
 */
NTSTATUS SetRegionGuardPages(
    _In_ PMEMORY_REGION Region)
{
    if (!Region || !Region->IsProtected) {
        return STATUS_INVALID_PARAMETER;
    }

    // Guard pages would be set before and after the protected region
    // This requires allocating additional pages and marking them as guard pages

    DbgPrint("[CryptoShield] Guard pages requested for region %p\n",
        Region->BaseAddress);

    // In production, this would:
    // 1. Allocate pages before and after the region
    // 2. Mark them with PAGE_GUARD flag
    // 3. Set up exception handling for guard page violations

    Region->ProtectionFlags |= MEMORY_PROTECT_GUARD_PAGE;

    return STATUS_SUCCESS;
}

/**
 * @brief Handle page fault in protected region
 */
BOOLEAN HandleProtectedPageFault(
    _In_ PINTEGRITY_CONTEXT Context,
    _In_ PVOID FaultAddress,
    _In_ ULONG FaultType)
{
    PMEMORY_REGION region;
    CORRUPTION_EVENT event = { 0 };

    if (!Context || !FaultAddress) {
        return FALSE;
    }

    // Find the region containing the fault address
    region = FindMemoryRegion(Context, FaultAddress);
    if (!region) {
        return FALSE;
    }

    DbgPrint("[CryptoShield] Page fault in protected region: %p, Type: 0x%X\n",
        FaultAddress, FaultType);

    // Log the event
    event.Address = FaultAddress;
    event.Size = region->Size;
    event.RegionIndex = (ULONG)(region - Context->Regions);
    KeQuerySystemTime(&event.Timestamp);
    event.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    event.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();

    LogCorruptionEvent(Context, &event);

    // Handle based on fault type
    if (FaultType & 0x2) { // Write fault
        if (region->ProtectionFlags & MEMORY_PROTECT_READ_ONLY) {
            DbgPrint("[CryptoShield] Write attempt to read-only region blocked\n");
            return TRUE; // Handled
        }
    }

    // Attempt auto-repair if corruption detected
    if (Context->AutoRepairEnabled && region->BackupCount > 0) {
        AutoRepairRegion(Context, region, &event);
    }

    return TRUE;
}

/**
 * @brief Safe memory comparison
 */
BOOLEAN SafeCompareMemory(
    _In_reads_bytes_(Length) PVOID Buffer1,
    _In_reads_bytes_(Length) PVOID Buffer2,
    _In_ SIZE_T Length)
{
    BOOLEAN equal = TRUE;

    if (!Buffer1 || !Buffer2 || Length == 0) {
        return FALSE;
    }

    __try {
        SIZE_T i;
        PUCHAR p1 = (PUCHAR)Buffer1;
        PUCHAR p2 = (PUCHAR)Buffer2;

        // Constant-time comparison to prevent timing attacks
        for (i = 0; i < Length; i++) {
            if (p1[i] != p2[i]) {
                equal = FALSE;
                // Don't break early - complete the comparison
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CryptoShield] Exception in safe memory comparison\n");
        return FALSE;
    }

    return equal;
}

/**
 * @brief Get integrity statistics
 */
VOID GetIntegrityStatistics(
    _In_ PINTEGRITY_CONTEXT Context,
    _Out_opt_ PULONG TotalRegions,
    _Out_opt_ PULONG CorruptedRegions,
    _Out_opt_ PULONG RepairSuccess)
{
    ULONG i, corrupted = 0;

    if (!Context) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&Context->RegionResource, TRUE);

    // Count corrupted regions
    for (i = 0; i < Context->RegionCount; i++) {
        if (Context->Regions[i].IsProtected &&
            Context->Regions[i].CorruptionCount > 0) {
            corrupted++;
        }
    }

    ExReleaseResourceLite(&Context->RegionResource);
    KeLeaveCriticalRegion();

    // Return statistics
    if (TotalRegions) {
        *TotalRegions = Context->ActiveRegions;
    }

    if (CorruptedRegions) {
        *CorruptedRegions = corrupted;
    }

    if (RepairSuccess) {
        ULONG total = Context->SuccessfulRepairs + Context->FailedRepairs;
        if (total > 0) {
            *RepairSuccess = (Context->SuccessfulRepairs * 100) / total;
        }
        else {
            *RepairSuccess = 0;
        }
    }
}

/**
 * @brief Dump region information for debugging
 */
VOID DumpRegionInfo(
    _In_ PMEMORY_REGION Region)
{
    if (!Region) {
        return;
    }

    DbgPrint("[CryptoShield] Memory Region Information:\n");
    DbgPrint("  - Base Address: %p\n", Region->BaseAddress);
    DbgPrint("  - Size: %zu bytes\n", Region->Size);
    DbgPrint("  - Protection Flags: 0x%08X\n", Region->ProtectionFlags);
    DbgPrint("  - Check Method: 0x%08X\n", Region->CheckMethod);
    DbgPrint("  - Is Protected: %s\n", Region->IsProtected ? "Yes" : "No");
    DbgPrint("  - Is Locked: %s\n", Region->IsLocked ? "Yes" : "No");
    DbgPrint("  - Verification Count: %lu\n", Region->VerificationCount);
    DbgPrint("  - Corruption Count: %lu\n", Region->CorruptionCount);
    DbgPrint("  - Backup Count: %lu\n", Region->BackupCount);
    DbgPrint("  - Current Checksum: 0x%08X\n", Region->Hash.Crc32);
}

// Note: This completes the MemoryIntegrity.c implementation