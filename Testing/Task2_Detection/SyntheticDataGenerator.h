#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include "../../Core/CommunicationManager.h" // Para FileOperationInfo

namespace CryptoShield::Testing {

    /**
     * @class SyntheticDataGenerator
     * @brief Genera comportamientos sint�ticos para probar el motor de detecci�n.
     *
     * Esta clase crea escenarios realistas de ataques de ransomware y de
     * comportamiento de software leg�timo para validar la eficacia y la
     * precisi�n de los diferentes m�dulos de detecci�n.
     */
    class SyntheticDataGenerator {
    public:
        SyntheticDataGenerator() = default;

        // --- Generaci�n de Comportamiento de Ransomware ---

        /**
         * @brief Simula un ataque de ransomware que cifra archivos en un directorio.
         * @param target_directory Directorio donde se crear�n y cifrar�n los archivos.
         * @param ops_log Vector para registrar las operaciones de archivo generadas.
         */
        void GenerateFileEncryptorBehavior(const std::wstring& target_directory, std::vector<CryptoShield::FileOperationInfo>& ops_log);

        /**
         * @brief Simula los comandos usados para eliminar Shadow Copies.
         * @param command_log Vector para registrar los comandos simulados.
         */
        void GenerateShadowDeletionBehavior(std::vector<std::wstring>& command_log);

        // --- Generaci�n de Comportamiento Leg�timo (Falsos Positivos) ---

        /**
         * @brief Simula el comportamiento de un software de backup.
         * @param source_directory Directorio del que se har� "backup".
         * @param backup_file Archivo de backup de destino.
         * @param ops_log Vector para registrar las operaciones de archivo generadas.
         */
        void GenerateBackupSoftwareBehavior(const std::wstring& source_directory, const std::wstring& backup_file, std::vector<CryptoShield::FileOperationInfo>& ops_log);

        /**
         * @brief Simula el comportamiento de un compilador de software.
         * @param project_directory Directorio del proyecto que se va a "compilar".
         * @param ops_log Vector para registrar las operaciones de archivo generadas.
         */
        void GenerateCompilerBehavior(const std::wstring& project_directory, std::vector<CryptoShield::FileOperationInfo>& ops_log);


    private:
        /**
         * @brief Crea un conjunto de archivos de prueba en un directorio.
         * @param directory Directorio de destino.
         * @param extensions Extensiones de los archivos a crear.
         * @param files_per_extension N�mero de archivos a crear por cada extensi�n.
         * @return Lista de rutas de los archivos creados.
         */
        std::vector<std::wstring> CreateTestFiles(const std::wstring& directory, const std::vector<std::wstring>& extensions, size_t files_per_extension);

        /**
         * @brief Simula el cifrado de archivos (lectura, modificaci�n, escritura y renombrado).
         * @param files Vector de archivos a "cifrar".
         * @param pid ID del proceso que realiza la acci�n.
         * @param ops_log Vector para registrar las operaciones.
         */
        void EncryptTestFiles(const std::vector<std::wstring>& files, uint32_t pid, std::vector<CryptoShield::FileOperationInfo>& ops_log);

        // --- Funciones de Utilidad ---
        CryptoShield::FileOperationInfo CreateOperation(uint32_t pid, const std::wstring& path, CryptoShield::FileOperationType type);
        void CreateDummyFile(const std::wstring& path, size_t size);
    };

} // namespace CryptoShield::Testing#pragma once
