#include "../pch.h"
#include "SyntheticDataGenerator.h"
#include <fstream>
#include <random>
#include <iostream>

namespace CryptoShield::Testing {

    // --- Implementación de Métodos Públicos ---

    void SyntheticDataGenerator::GenerateFileEncryptorBehavior(const std::wstring& target_directory, std::vector<CryptoShield::FileOperationInfo>& ops_log) {
        std::wcout << L"INFO: Generating synthetic file encryptor behavior in " << target_directory << std::endl;

        uint32_t ransomware_pid = 1337;

        // 1. Crear un conjunto de archivos víctima
        std::vector<std::wstring> extensions_to_create = { L".txt", L".docx", L".jpg", L".pdf" };
        auto files_to_encrypt = CreateTestFiles(target_directory, extensions_to_create, 5);

        // 2. Simular el cifrado y renombrado de los archivos
        EncryptTestFiles(files_to_encrypt, ransomware_pid, ops_log);

        // 3. Crear una nota de rescate
        std::wstring ransom_note_path = target_directory + L"\\DECRYPT_YOUR_FILES.txt";
        CreateDummyFile(ransom_note_path, 256);
        ops_log.push_back(CreateOperation(ransomware_pid, ransom_note_path, CryptoShield::FileOperationType::Create));
        ops_log.push_back(CreateOperation(ransomware_pid, ransom_note_path, CryptoShield::FileOperationType::Write));
    }

    void SyntheticDataGenerator::GenerateShadowDeletionBehavior(std::vector<std::wstring>& command_log) {
        std::wcout << L"INFO: Generating synthetic shadow copy deletion commands." << std::endl;
        command_log.push_back(L"vssadmin.exe delete shadows /all /quiet");
        command_log.push_back(L"wmic.exe shadowcopy delete");
        command_log.push_back(L"bcdedit.exe /set {default} recoveryenabled no");
    }

    void SyntheticDataGenerator::GenerateBackupSoftwareBehavior(const std::wstring& source_directory, const std::wstring& backup_file, std::vector<CryptoShield::FileOperationInfo>& ops_log) {
        std::wcout << L"INFO: Generating legitimate backup software behavior." << std::endl;
        uint32_t backup_pid = 8008;

        // 1. Crear archivos fuente
        auto source_files = CreateTestFiles(source_directory, { L".dat", L".log", L".config" }, 10);

        // 2. Simular la lectura de muchos archivos fuente
        for (const auto& file : source_files) {
            ops_log.push_back(CreateOperation(backup_pid, file, CryptoShield::FileOperationType::Create)); // Usamos Create como análogo de Read para el test
        }

        // 3. Simular la escritura al archivo de backup
        CreateDummyFile(backup_file, 1024 * 1024); // Crear un archivo de backup de 1MB
        for (int i = 0; i < 10; ++i) { // Múltiples escrituras
            ops_log.push_back(CreateOperation(backup_pid, backup_file, CryptoShield::FileOperationType::Write));
        }
    }

    void SyntheticDataGenerator::GenerateCompilerBehavior(const std::wstring& project_directory, std::vector<CryptoShield::FileOperationInfo>& ops_log) {
        std::wcout << L"INFO: Generating legitimate compiler behavior." << std::endl;
        uint32_t compiler_pid = 7070;

        // 1. Crear archivos fuente (.h, .cpp)
        auto source_files = CreateTestFiles(project_directory, { L".h", L".cpp" }, 5);
        for (const auto& file : source_files) {
            ops_log.push_back(CreateOperation(compiler_pid, file, CryptoShield::FileOperationType::Create)); // Simula lectura
        }

        // 2. Simular creación de archivos objeto (.obj)
        for (int i = 0; i < 5; ++i) {
            std::wstring obj_path = project_directory + L"\\file" + std::to_wstring(i) + L".obj";
            ops_log.push_back(CreateOperation(compiler_pid, obj_path, CryptoShield::FileOperationType::Create));
            ops_log.push_back(CreateOperation(compiler_pid, obj_path, CryptoShield::FileOperationType::Write));
        }

        // 3. Simular linkado y creación de ejecutable (.exe)
        std::wstring exe_path = project_directory + L"\\program.exe";
        ops_log.push_back(CreateOperation(compiler_pid, exe_path, CryptoShield::FileOperationType::Create));
        ops_log.push_back(CreateOperation(compiler_pid, exe_path, CryptoShield::FileOperationType::Write));
    }


    // --- Implementación de Métodos Privados ---

    std::vector<std::wstring> SyntheticDataGenerator::CreateTestFiles(const std::wstring& directory, const std::vector<std::wstring>& extensions, size_t files_per_extension) {
        std::vector<std::wstring> created_files;
        if (!std::filesystem::exists(directory)) {
            std::filesystem::create_directories(directory);
        }

        for (const auto& ext : extensions) {
            for (size_t i = 0; i < files_per_extension; ++i) {
                std::wstring file_path = directory + L"\\testfile_" + std::to_wstring(i) + ext;
                CreateDummyFile(file_path, 1024 + (i * 100)); // Tamaños variados
                created_files.push_back(file_path);
            }
        }
        return created_files;
    }

    void SyntheticDataGenerator::EncryptTestFiles(const std::vector<std::wstring>& files, uint32_t pid, std::vector<CryptoShield::FileOperationInfo>& ops_log) {
        for (const auto& file_path : files) {
            ops_log.push_back(CreateOperation(pid, file_path, CryptoShield::FileOperationType::Create)); // Lectura
            ops_log.push_back(CreateOperation(pid, file_path, CryptoShield::FileOperationType::Write));  // Escritura (cifrado)

            std::wstring new_path = file_path + L".locked";
            ops_log.push_back(CreateOperation(pid, new_path, CryptoShield::FileOperationType::Rename)); // Renombrado
        }
    }

    CryptoShield::FileOperationInfo SyntheticDataGenerator::CreateOperation(uint32_t pid, const std::wstring& path, CryptoShield::FileOperationType type) {
        CryptoShield::FileOperationInfo op;
        op.process_id = pid;
        op.file_path = path;
        op.type = type;
        op.thread_id = GetCurrentThreadId();
        GetSystemTimeAsFileTime(&op.timestamp);
        return op;
    }

    void SyntheticDataGenerator::CreateDummyFile(const std::wstring& path, size_t size) {
        std::ofstream ofs(path, std::ios::binary | std::ios::out);
        if (ofs) {
            std::vector<char> buffer(size, 'T'); // 'T' for Test
            ofs.write(buffer.data(), size);
        }
    }

} // namespace CryptoShield::Testing