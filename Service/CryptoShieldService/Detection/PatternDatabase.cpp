/**
 * @file PatternDatabase.cpp
 * @brief Pattern database implementation (Part 1)
 * @details Implements pattern storage, initialization and basic management
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#define NOMINMAX
#include "PatternDatabase.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <random>
#include <nlohmann/json.hpp>

namespace CryptoShield::Detection {

    /**
     * @brief Constructor
     */
    PatternDatabase::PatternDatabase()
        : pattern_id_counter_(1)
        , statistics_{}
    {
        statistics_.last_update = std::chrono::system_clock::now();
    }

    /**
     * @brief Destructor
     */
    PatternDatabase::~PatternDatabase() = default;

    /**
     * @brief Initialize database with default patterns
     */
    bool PatternDatabase::Initialize()
    {
        try {
            std::lock_guard<std::mutex> lock(patterns_mutex_);

            // Clear existing patterns
            patterns_.clear();
            patterns_by_type_.clear();
            patterns_by_family_.clear();

            // Initialize all pattern categories
            InitializeFileExtensions();
            InitializeRansomNotePatterns();
            InitializeProcessPatterns();
            InitializeCommandLinePatterns();
            InitializeBehaviorSequences();

            // Update statistics
            statistics_.total_patterns = patterns_.size();
            statistics_.active_patterns = patterns_.size();
            statistics_.last_update = std::chrono::system_clock::now();

            std::wcout << L"[PatternDatabase] Initialized with "
                << patterns_.size() << L" patterns" << std::endl;

            return true;
        }
        catch (const std::exception& e) {
            std::wcerr << L"[PatternDatabase] Initialization failed: "
                << e.what() << std::endl;
            return false;
        }
    }

    /**
     * @brief Initialize known file extensions
     */
    void PatternDatabase::InitializeFileExtensions()
    {
        struct ExtensionPattern {
            const wchar_t* extension;
            const wchar_t* family;
            const wchar_t* variant;
            PatternConfidence confidence;
        };

        const ExtensionPattern extensions[] = {
            // WannaCry variants
            {L".wncry", L"WannaCry", L"Original", PatternConfidence::CRITICAL},
            {L".wcry", L"WannaCry", L"Variant", PatternConfidence::CRITICAL},
            {L".wncrypt", L"WannaCry", L"Variant", PatternConfidence::CRITICAL},
            {L".wncryt", L"WannaCry", L"Variant", PatternConfidence::CRITICAL},

            // Locky variants
            {L".locky", L"Locky", L"Original", PatternConfidence::CRITICAL},
            {L".odin", L"Locky", L"Odin", PatternConfidence::CRITICAL},
            {L".shit", L"Locky", L"SHIT", PatternConfidence::CRITICAL},
            {L".thor", L"Locky", L"Thor", PatternConfidence::CRITICAL},
            {L".aesir", L"Locky", L"Aesir", PatternConfidence::CRITICAL},
            {L".zzzzz", L"Locky", L"ZZZZZ", PatternConfidence::CRITICAL},

            // Cerber variants
            {L".cerber", L"Cerber", L"Original", PatternConfidence::CRITICAL},
            {L".cerber2", L"Cerber", L"v2", PatternConfidence::CRITICAL},
            {L".cerber3", L"Cerber", L"v3", PatternConfidence::CRITICAL},

            // CryptoLocker variants
            {L".encrypted", L"CryptoLocker", L"Generic", PatternConfidence::HIGH},
            {L".cryptolocker", L"CryptoLocker", L"Original", PatternConfidence::CRITICAL},
            {L".enc", L"CryptoLocker", L"Short", PatternConfidence::MEDIUM},
            {L".crypted", L"CryptoLocker", L"Variant", PatternConfidence::HIGH},

            // Ryuk
            {L".ryk", L"Ryuk", L"Original", PatternConfidence::CRITICAL},
            {L".RYK", L"Ryuk", L"Uppercase", PatternConfidence::CRITICAL},

            // Sodinokibi/REvil
            {L".sodinokibi", L"Sodinokibi", L"Original", PatternConfidence::CRITICAL},
            {L".revil", L"REvil", L"Rebranded", PatternConfidence::CRITICAL},

            // Dharma variants
            {L".dharma", L"Dharma", L"Original", PatternConfidence::CRITICAL},
            {L".wallet", L"Dharma", L"Wallet", PatternConfidence::HIGH},
            {L".onion", L"Dharma", L"Onion", PatternConfidence::HIGH},

            // Maze
            {L".maze", L"Maze", L"Original", PatternConfidence::CRITICAL},

            // Conti
            {L".conti", L"Conti", L"Original", PatternConfidence::CRITICAL},

            // LockBit
            {L".lockbit", L"LockBit", L"Original", PatternConfidence::CRITICAL},
            {L".abcd", L"LockBit", L"ABCD", PatternConfidence::HIGH},

            // Generic suspicious extensions
            {L".locked", L"Generic", L"Locked", PatternConfidence::MEDIUM},
            {L".crypto", L"Generic", L"Crypto", PatternConfidence::MEDIUM},
            {L".enc", L"Generic", L"Encrypted", PatternConfidence::LOW},
            {L".aaa", L"Generic", L"Triple-A", PatternConfidence::MEDIUM},
            {L".xyz", L"Generic", L"XYZ", PatternConfidence::LOW},
            {L".zzz", L"Generic", L"Triple-Z", PatternConfidence::MEDIUM},
            {L".abc", L"Generic", L"ABC", PatternConfidence::LOW},
            {L".omega", L"Generic", L"Omega", PatternConfidence::MEDIUM},
            {L".alpha", L"Generic", L"Alpha", PatternConfidence::MEDIUM},
            {L".virus", L"Generic", L"Virus", PatternConfidence::HIGH},
            {L".kraken", L"Generic", L"Kraken", PatternConfidence::MEDIUM},
            {L".darkness", L"Generic", L"Darkness", PatternConfidence::MEDIUM},
            {L".nochance", L"Generic", L"NoChance", PatternConfidence::MEDIUM},
            {L".ecc", L"Generic", L"ECC", PatternConfidence::MEDIUM},
            {L".exx", L"Generic", L"EXX", PatternConfidence::MEDIUM},
            {L".ezz", L"Generic", L"EZZ", PatternConfidence::MEDIUM},
            {L".damaged", L"Generic", L"Damaged", PatternConfidence::MEDIUM},
            {L".fucked", L"Generic", L"Offensive", PatternConfidence::HIGH}
        };

        for (const auto& ext : extensions) {
            RansomwarePattern pattern;
            pattern.pattern_id = GeneratePatternId();
            pattern.type = PatternType::FILE_EXTENSION;
            pattern.pattern_value = ext.extension;
            pattern.match_mode = MatchMode::EXACT;
            pattern.confidence = ext.confidence;
            pattern.family_name = ext.family;
            pattern.variant_name = ext.variant;
            pattern.description = L"Known ransomware file extension";
            pattern.first_seen = std::chrono::system_clock::now();
            pattern.last_updated = pattern.first_seen;
            pattern.hit_count = 0;
            pattern.is_active = true;
            pattern.false_positive_rate = 0.0;

            patterns_[pattern.pattern_id] = pattern;
            patterns_by_type_.emplace(pattern.type, pattern.pattern_id);
            patterns_by_family_.emplace(pattern.family_name, pattern.pattern_id);
        }
    }

    /**
     * @brief Initialize ransom note patterns
     */
    void PatternDatabase::InitializeRansomNotePatterns()
    {
        struct NotePattern {
            const wchar_t* filename;
            const wchar_t* family;
            MatchMode mode;
            PatternConfidence confidence;
        };

        const NotePattern notes[] = {
            // WannaCry
            {L"@Please_Read_Me@.txt", L"WannaCry", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"@WanaDecryptor@.txt", L"WannaCry", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"!Please Read Me!.txt", L"WannaCry", MatchMode::EXACT, PatternConfidence::CRITICAL},

            // Locky
            {L"_HELP_instructions.txt", L"Locky", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"_HELP_instructions.html", L"Locky", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"_HELP_instructions.bmp", L"Locky", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"HELP_instructions.txt", L"Locky", MatchMode::EXACT, PatternConfidence::HIGH},

            // Cerber
            {L"# DECRYPT MY FILES #.txt", L"Cerber", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"# DECRYPT MY FILES #.html", L"Cerber", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"# DECRYPT MY FILES #.url", L"Cerber", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"_READ_THIS_FILE_*", L"Cerber", MatchMode::WILDCARD, PatternConfidence::HIGH},

            // CryptoLocker
            {L"DECRYPT_INSTRUCTION.txt", L"CryptoLocker", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"DECRYPT_INSTRUCTION.html", L"CryptoLocker", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"HOW_TO_DECRYPT.txt", L"CryptoLocker", MatchMode::EXACT, PatternConfidence::HIGH},

            // Ryuk
            {L"RyukReadMe.txt", L"Ryuk", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"RyukReadMe.html", L"Ryuk", MatchMode::EXACT, PatternConfidence::CRITICAL},

            // Sodinokibi/REvil
            {L"*-readme.txt", L"Sodinokibi", MatchMode::WILDCARD, PatternConfidence::HIGH},
            {L"*-HOW-TO-DECRYPT.txt", L"REvil", MatchMode::WILDCARD, PatternConfidence::HIGH},

            // Dharma
            {L"FILES ENCRYPTED.txt", L"Dharma", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"Info.hta", L"Dharma", MatchMode::EXACT, PatternConfidence::HIGH},
            {L"README.txt", L"Dharma", MatchMode::EXACT, PatternConfidence::MEDIUM},

            // Maze
            {L"DECRYPT-FILES.txt", L"Maze", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"DECRYPT-FILES.html", L"Maze", MatchMode::EXACT, PatternConfidence::CRITICAL},

            // Conti
            {L"readme.txt", L"Conti", MatchMode::EXACT, PatternConfidence::MEDIUM},
            {L"CONTI_README.txt", L"Conti", MatchMode::EXACT, PatternConfidence::CRITICAL},

            // LockBit
            {L"Restore-My-Files.txt", L"LockBit", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"LockBit_README.txt", L"LockBit", MatchMode::EXACT, PatternConfidence::CRITICAL},

            // Generic patterns
            {L"*READ*ME*", L"Generic", MatchMode::WILDCARD, PatternConfidence::LOW},
            {L"*DECRYPT*", L"Generic", MatchMode::WILDCARD, PatternConfidence::LOW},
            {L"*RECOVER*", L"Generic", MatchMode::WILDCARD, PatternConfidence::LOW},
            {L"*RESTORE*", L"Generic", MatchMode::WILDCARD, PatternConfidence::LOW},
            {L"HOW_TO_*", L"Generic", MatchMode::WILDCARD, PatternConfidence::LOW},
            {L"YOUR_FILES_*", L"Generic", MatchMode::WILDCARD, PatternConfidence::LOW}
        };

        for (const auto& note : notes) {
            RansomwarePattern pattern;
            pattern.pattern_id = GeneratePatternId();
            pattern.type = PatternType::FILE_NAME;
            pattern.pattern_value = note.filename;
            pattern.match_mode = note.mode;
            pattern.confidence = note.confidence;
            pattern.family_name = note.family;
            pattern.variant_name = L"";
            pattern.description = L"Ransom note filename pattern";
            pattern.first_seen = std::chrono::system_clock::now();
            pattern.last_updated = pattern.first_seen;
            pattern.hit_count = 0;
            pattern.is_active = true;
            pattern.false_positive_rate = 0.0;

            patterns_[pattern.pattern_id] = pattern;
            patterns_by_type_.emplace(pattern.type, pattern.pattern_id);
            patterns_by_family_.emplace(pattern.family_name, pattern.pattern_id);
        }
    }

    /**
     * @brief Initialize process name patterns
     */
    void PatternDatabase::InitializeProcessPatterns()
    {
        struct ProcessPattern {
            const wchar_t* process_name;
            const wchar_t* family;
            MatchMode mode;
            PatternConfidence confidence;
        };

        const ProcessPattern processes[] = {
            // WannaCry
            {L"tasksche.exe", L"WannaCry", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"@WanaDecryptor@.exe", L"WannaCry", MatchMode::EXACT, PatternConfidence::CRITICAL},
            {L"wncry.exe", L"WannaCry", MatchMode::EXACT, PatternConfidence::CRITICAL},

            // Locky
            {L"svchost.exe", L"Locky", MatchMode::EXACT, PatternConfidence::LOW}, // False positive prone

            // Cerber
            {L"cerber.exe", L"Cerber", MatchMode::SUBSTRING, PatternConfidence::HIGH},

            // Ryuk
            {L"ryuk.exe", L"Ryuk", MatchMode::SUBSTRING, PatternConfidence::CRITICAL},

            // Sodinokibi
            {L"sodinokibi.exe", L"Sodinokibi", MatchMode::SUBSTRING, PatternConfidence::CRITICAL},

            // Dharma
            {L"dharma*.exe", L"Dharma", MatchMode::WILDCARD, PatternConfidence::HIGH},

            // Maze
            {L"maze*.exe", L"Maze", MatchMode::WILDCARD, PatternConfidence::HIGH},

            // Conti
            {L"conti*.exe", L"Conti", MatchMode::WILDCARD, PatternConfidence::HIGH},

            // LockBit
            {L"lockbit*.exe", L"LockBit", MatchMode::WILDCARD, PatternConfidence::HIGH},

            // Generic suspicious
            {L"*crypt*.exe", L"Generic", MatchMode::WILDCARD, PatternConfidence::LOW},
            {L"*ransom*.exe", L"Generic", MatchMode::WILDCARD, PatternConfidence::MEDIUM},
            {L"*locker*.exe", L"Generic", MatchMode::WILDCARD, PatternConfidence::LOW},
            {L"*decrypt*.exe", L"Generic", MatchMode::WILDCARD, PatternConfidence::LOW}
        };

        for (const auto& proc : processes) {
            RansomwarePattern pattern;
            pattern.pattern_id = GeneratePatternId();
            pattern.type = PatternType::PROCESS_NAME;
            pattern.pattern_value = proc.process_name;
            pattern.match_mode = proc.mode;
            pattern.confidence = proc.confidence;
            pattern.family_name = proc.family;
            pattern.variant_name = L"";
            pattern.description = L"Known ransomware process name";
            pattern.first_seen = std::chrono::system_clock::now();
            pattern.last_updated = pattern.first_seen;
            pattern.hit_count = 0;
            pattern.is_active = true;
            pattern.false_positive_rate = proc.process_name == L"svchost.exe" ? 0.8 : 0.0;

            patterns_[pattern.pattern_id] = pattern;
            patterns_by_type_.emplace(pattern.type, pattern.pattern_id);
            patterns_by_family_.emplace(pattern.family_name, pattern.pattern_id);
        }
    }

    /**
     * @brief Initialize command line patterns
     */
    void PatternDatabase::InitializeCommandLinePatterns()
    {
        struct CommandPattern {
            const wchar_t* pattern;
            const wchar_t* family;
            MatchMode mode;
            PatternConfidence confidence;
            const wchar_t* description;
        };

        const CommandPattern commands[] = {
            // Shadow copy deletion
            {L"vssadmin.exe delete shadows", L"Generic", MatchMode::SUBSTRING,
             PatternConfidence::CRITICAL, L"Shadow copy deletion"},
            {L"vssadmin delete shadows /all /quiet", L"Generic", MatchMode::SUBSTRING,
             PatternConfidence::CRITICAL, L"Silent shadow copy deletion"},
            {L"wmic shadowcopy delete", L"Generic", MatchMode::SUBSTRING,
             PatternConfidence::CRITICAL, L"WMI shadow copy deletion"},
            {L"bcdedit /set {default} bootstatuspolicy ignoreallfailures", L"Generic",
             MatchMode::SUBSTRING, PatternConfidence::HIGH, L"Boot recovery disable"},
            {L"bcdedit /set {default} recoveryenabled no", L"Generic",
             MatchMode::SUBSTRING, PatternConfidence::HIGH, L"Recovery disable"},
            {L"wbadmin delete catalog -quiet", L"Generic", MatchMode::SUBSTRING,
             PatternConfidence::HIGH, L"Backup catalog deletion"},

             // Specific ransomware commands
             {L"cmd.exe /c vssadmin.exe", L"WannaCry", MatchMode::SUBSTRING,
              PatternConfidence::MEDIUM, L"WannaCry shadow deletion"},
             {L"icacls . /grant Everyone:F /T /C /Q", L"Ryuk", MatchMode::SUBSTRING,
              PatternConfidence::HIGH, L"Ryuk permission change"},
             {L"net stop *sql*", L"Generic", MatchMode::WILDCARD,
              PatternConfidence::MEDIUM, L"SQL service stop"},
             {L"net stop *backup*", L"Generic", MatchMode::WILDCARD,
              PatternConfidence::MEDIUM, L"Backup service stop"},

              // Encryption indicators
              {L"cipher /w:", L"Generic", MatchMode::SUBSTRING,
               PatternConfidence::LOW, L"Cipher command usage"},
              {L"gpg --encrypt", L"Generic", MatchMode::SUBSTRING,
               PatternConfidence::LOW, L"GPG encryption"},
              {L"openssl enc", L"Generic", MatchMode::SUBSTRING,
               PatternConfidence::LOW, L"OpenSSL encryption"}
        };

        for (const auto& cmd : commands) {
            RansomwarePattern pattern;
            pattern.pattern_id = GeneratePatternId();
            pattern.type = PatternType::COMMAND_LINE;
            pattern.pattern_value = cmd.pattern;
            pattern.match_mode = cmd.mode;
            pattern.confidence = cmd.confidence;
            pattern.family_name = cmd.family;
            pattern.variant_name = L"";
            pattern.description = cmd.description;
            pattern.first_seen = std::chrono::system_clock::now();
            pattern.last_updated = pattern.first_seen;
            pattern.hit_count = 0;
            pattern.is_active = true;
            pattern.false_positive_rate = 0.0;

            patterns_[pattern.pattern_id] = pattern;
            patterns_by_type_.emplace(pattern.type, pattern.pattern_id);
            patterns_by_family_.emplace(pattern.family_name, pattern.pattern_id);
        }
    }

    /**
     * @brief Initialize behavior sequences
     */
    void PatternDatabase::InitializeBehaviorSequences()
    {
        std::lock_guard<std::mutex> lock(sequences_mutex_);

        // WannaCry behavior sequence
        {
            BehaviorSequence seq;
            seq.sequence_id = L"SEQ_WANNACRY_001";
            seq.family_name = L"WannaCry";
            seq.required_behaviors = {
                L"MASS_FILE_ENCRYPTION",
                L"SHADOW_COPY_DELETION",
                L"RANSOM_NOTE_CREATION",
                L"WALLPAPER_CHANGE"
            };
            seq.optional_behaviors = {
                L"NETWORK_SCAN",
                L"SMB_EXPLOIT"
            };
            seq.max_time_window = std::chrono::milliseconds(300000); // 5 minutes
            seq.min_behaviors_required = 3;
            seq.confidence = PatternConfidence::HIGH;
            seq.description = L"WannaCry typical behavior sequence";

            behavior_sequences_[seq.sequence_id] = seq;
        }

        // Ryuk behavior sequence
        {
            BehaviorSequence seq;
            seq.sequence_id = L"SEQ_RYUK_001";
            seq.family_name = L"Ryuk";
            seq.required_behaviors = {
                L"PROCESS_INJECTION",
                L"PRIVILEGE_ESCALATION",
                L"SHADOW_COPY_DELETION",
                L"MASS_FILE_ENCRYPTION",
                L"NETWORK_SHARE_ENCRYPTION"
            };
            seq.optional_behaviors = {
                L"PERSISTENCE_CREATION",
                L"LOG_DELETION"
            };
            seq.max_time_window = std::chrono::milliseconds(600000); // 10 minutes
            seq.min_behaviors_required = 4;
            seq.confidence = PatternConfidence::HIGH;
            seq.description = L"Ryuk typical behavior sequence";

            behavior_sequences_[seq.sequence_id] = seq;
        }

        // Generic ransomware sequence
        {
            BehaviorSequence seq;
            seq.sequence_id = L"SEQ_GENERIC_001";
            seq.family_name = L"Generic";
            seq.required_behaviors = {
                L"MASS_FILE_MODIFICATION",
                L"FILE_EXTENSION_CHANGE",
                L"RANSOM_NOTE_CREATION"
            };
            seq.optional_behaviors = {
                L"SHADOW_COPY_DELETION",
                L"REGISTRY_MODIFICATION",
                L"BOOT_CONFIG_CHANGE"
            };
            seq.max_time_window = std::chrono::milliseconds(900000); // 15 minutes
            seq.min_behaviors_required = 2;
            seq.confidence = PatternConfidence::MEDIUM;
            seq.description = L"Generic ransomware behavior sequence";

            behavior_sequences_[seq.sequence_id] = seq;
        }
    }

    /**
     * @brief Load patterns from file
     */
    bool PatternDatabase::LoadPatterns(const std::wstring& database_file)
    {
        try {
            std::ifstream file(database_file);
            if (!file.is_open()) {
                std::wcerr << L"[PatternDatabase] Failed to open database file: "
                    << database_file << std::endl;
                return false;
            }

            nlohmann::json j;
            file >> j;

            std::lock_guard<std::mutex> lock(patterns_mutex_);

            // Clear existing patterns
            patterns_.clear();
            patterns_by_type_.clear();
            patterns_by_family_.clear();

            // Load patterns
            for (const auto& jp : j["patterns"]) {
                RansomwarePattern pattern;
                pattern.pattern_id = std::wstring(jp["id"].get<std::string>().begin(),
                    jp["id"].get<std::string>().end());
                pattern.type = static_cast<PatternType>(jp["type"].get<int>());
                pattern.pattern_value = std::wstring(jp["value"].get<std::string>().begin(),
                    jp["value"].get<std::string>().end());
                pattern.match_mode = static_cast<MatchMode>(jp["match_mode"].get<int>());
                pattern.confidence = static_cast<PatternConfidence>(jp["confidence"].get<int>());
                pattern.family_name = std::wstring(jp["family"].get<std::string>().begin(),
                    jp["family"].get<std::string>().end());
                pattern.variant_name = std::wstring(jp["variant"].get<std::string>().begin(),
                    jp["variant"].get<std::string>().end());
                pattern.description = std::wstring(jp["description"].get<std::string>().begin(),
                    jp["description"].get<std::string>().end());
                pattern.hit_count = jp["hit_count"].get<size_t>();
                pattern.is_active = jp["is_active"].get<bool>();
                pattern.false_positive_rate = jp["false_positive_rate"].get<double>();

                patterns_[pattern.pattern_id] = pattern;
                patterns_by_type_.emplace(pattern.type, pattern.pattern_id);
                patterns_by_family_.emplace(pattern.family_name, pattern.pattern_id);
            }

            // Update statistics
            statistics_.total_patterns = patterns_.size();
            statistics_.active_patterns = std::count_if(patterns_.begin(), patterns_.end(),
                [](const auto& p) { return p.second.is_active; });

            std::wcout << L"[PatternDatabase] Loaded " << patterns_.size()
                << L" patterns from " << database_file << std::endl;

            return true;
        }
        catch (const std::exception& e) {
            std::wcerr << L"[PatternDatabase] Error loading patterns: "
                << e.what() << std::endl;
            return false;
        }
    }

    /**
     * @brief Save patterns to file
     */
    bool PatternDatabase::SavePatterns(const std::wstring& database_file) const
    {
        try {
            nlohmann::json j;

            {
                std::lock_guard<std::mutex> lock(patterns_mutex_);

                // Convert patterns to JSON
                j["version"] = "1.0";
                j["timestamp"] = std::chrono::system_clock::now().time_since_epoch().count();
                j["pattern_count"] = patterns_.size();

                auto& patterns_array = j["patterns"];
                for (const auto& [id, pattern] : patterns_) {
                    nlohmann::json jp;
                    jp["id"] = std::string(pattern.pattern_id.begin(), pattern.pattern_id.end());
                    jp["type"] = static_cast<int>(pattern.type);
                    jp["value"] = std::string(pattern.pattern_value.begin(), pattern.pattern_value.end());
                    jp["match_mode"] = static_cast<int>(pattern.match_mode);
                    jp["confidence"] = static_cast<int>(pattern.confidence);
                    jp["family"] = std::string(pattern.family_name.begin(), pattern.family_name.end());
                    jp["variant"] = std::string(pattern.variant_name.begin(), pattern.variant_name.end());
                    jp["description"] = std::string(pattern.description.begin(), pattern.description.end());
                    jp["hit_count"] = pattern.hit_count;
                    jp["is_active"] = pattern.is_active;
                    jp["false_positive_rate"] = pattern.false_positive_rate;

                    patterns_array.push_back(jp);
                }
            }

            // Write to file
            std::ofstream file(database_file);
            if (!file.is_open()) {
                std::wcerr << L"[PatternDatabase] Failed to create database file: "
                    << database_file << std::endl;
                return false;
            }

            file << j.dump(4);

            std::wcout << L"[PatternDatabase] Saved " << patterns_.size()
                << L" patterns to " << database_file << std::endl;

            return true;
        }
        catch (const std::exception& e) {
            std::wcerr << L"[PatternDatabase] Error saving patterns: "
                << e.what() << std::endl;
            return false;
        }
    }

    /**
     * @brief Add new pattern to database
     */
    std::optional<std::wstring> PatternDatabase::AddPattern(const RansomwarePattern& pattern)
    {
        if (!ValidatePattern(pattern)) {
            return std::nullopt;
        }

        std::lock_guard<std::mutex> lock(patterns_mutex_);

        std::wstring pattern_id = pattern.pattern_id.empty() ?
            GeneratePatternId() : pattern.pattern_id;

        RansomwarePattern new_pattern = pattern;
        new_pattern.pattern_id = pattern_id;
        new_pattern.first_seen = std::chrono::system_clock::now();
        new_pattern.last_updated = new_pattern.first_seen;

        patterns_[pattern_id] = new_pattern;
        patterns_by_type_.emplace(new_pattern.type, pattern_id);
        patterns_by_family_.emplace(new_pattern.family_name, pattern_id);

        // Update statistics
        statistics_.total_patterns++;
        if (new_pattern.is_active) {
            statistics_.active_patterns++;
        }
        statistics_.patterns_by_type[new_pattern.type]++;
        statistics_.patterns_by_family[new_pattern.family_name]++;

        return pattern_id;
    }

    /**
     * @brief Remove pattern from database
     */
    bool PatternDatabase::RemovePattern(const std::wstring& pattern_id)
    {
        std::lock_guard<std::mutex> lock(patterns_mutex_);

        auto it = patterns_.find(pattern_id);
        if (it == patterns_.end()) {
            return false;
        }

        // Update statistics
        const auto& pattern = it->second;
        statistics_.total_patterns--;
        if (pattern.is_active) {
            statistics_.active_patterns--;
        }
        statistics_.patterns_by_type[pattern.type]--;
        statistics_.patterns_by_family[pattern.family_name]--;

        // Remove from indices
        auto type_range = patterns_by_type_.equal_range(pattern.type);
        for (auto it2 = type_range.first; it2 != type_range.second; ++it2) {
            if (it2->second == pattern_id) {
                patterns_by_type_.erase(it2);
                break;
            }
        }

        auto family_range = patterns_by_family_.equal_range(pattern.family_name);
        for (auto it2 = family_range.first; it2 != family_range.second; ++it2) {
            if (it2->second == pattern_id) {
                patterns_by_family_.erase(it2);
                break;
            }
        }

        // Remove pattern
        patterns_.erase(it);

        return true;
    }

    /**
     * @brief Update existing pattern
     */
    bool PatternDatabase::UpdatePattern(const RansomwarePattern& pattern)
    {
        if (!ValidatePattern(pattern)) {
            return false;
        }

        std::lock_guard<std::mutex> lock(patterns_mutex_);

        auto it = patterns_.find(pattern.pattern_id);
        if (it == patterns_.end()) {
            return false;
        }

        // Update pattern
        RansomwarePattern& existing = it->second;
        existing.pattern_value = pattern.pattern_value;
        existing.match_mode = pattern.match_mode;
        existing.confidence = pattern.confidence;
        existing.family_name = pattern.family_name;
        existing.variant_name = pattern.variant_name;
        existing.description = pattern.description;
        existing.is_active = pattern.is_active;
        existing.false_positive_rate = pattern.false_positive_rate;
        existing.last_updated = std::chrono::system_clock::now();

        return true;
    }

    /**
     * @brief Generate unique pattern ID
     */
    std::wstring PatternDatabase::GeneratePatternId() const
    {
        uint64_t id = pattern_id_counter_.fetch_add(1);

        std::wstringstream ss;
        ss << L"PTN_" << std::setfill(L'0') << std::setw(10) << id;

        return ss.str();
    }

    /**
     * @brief Validate pattern
     */
    bool PatternDatabase::ValidatePattern(const RansomwarePattern& pattern) const
    {
        // Check pattern value length
        if (pattern.pattern_value.empty() ||
            pattern.pattern_value.length() > MAX_PATTERN_LENGTH) {
            return false;
        }

        // Check family name
        if (pattern.family_name.empty()) {
            return false;
        }

        // Validate regex patterns
        if (pattern.match_mode == MatchMode::REGEX) {
            try {
                std::wregex test(pattern.pattern_value);
            }
            catch (const std::regex_error&) {
                return false;
            }
        }

        // Check false positive rate
        if (pattern.false_positive_rate < 0.0 ||
            pattern.false_positive_rate > 1.0) {
            return false;
        }

        return true;
    }

    /**
     * @brief Clear all patterns
     */
    void PatternDatabase::Clear()
    {
        std::lock_guard<std::mutex> lock(patterns_mutex_);

        patterns_.clear();
        patterns_by_type_.clear();
        patterns_by_family_.clear();

        // Reset statistics
        statistics_ = DatabaseStatistics{};
        statistics_.last_update = std::chrono::system_clock::now();

        pattern_id_counter_ = 1;
    }

    /**
     * @brief Get all known ransomware families
     */
    std::set<std::wstring> PatternDatabase::GetKnownFamilies() const
    {
        std::lock_guard<std::mutex> lock(patterns_mutex_);

        std::set<std::wstring> families;
        for (const auto& [family, id] : patterns_by_family_) {
            families.insert(family);
        }

        return families;
    }

    /**
     * @brief Get database statistics
     */
    DatabaseStatistics PatternDatabase::GetStatistics() const
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        return statistics_;
    }
        

     /**
      * @brief Match value against patterns
      */
    std::vector<PatternMatch> PatternDatabase::MatchPattern(
        const std::wstring& value,
        PatternType type) const
    {
        auto start_time = std::chrono::steady_clock::now();
        std::vector<PatternMatch> matches;

        if (value.empty()) {
            return matches;
        }

        std::lock_guard<std::mutex> lock(patterns_mutex_);

        // Get patterns of specified type
        auto range = patterns_by_type_.equal_range(type);

        for (auto it = range.first; it != range.second; ++it) {
            auto pattern_it = patterns_.find(it->second);
            if (pattern_it == patterns_.end() || !pattern_it->second.is_active) {
                continue;
            }

            const auto& pattern = pattern_it->second;
            double match_score = 0.0;

            // Perform matching based on mode
            switch (pattern.match_mode) {
            case MatchMode::EXACT:
                match_score = PerformExactMatch(value, pattern.pattern_value);
                break;

            case MatchMode::SUBSTRING:
                match_score = PerformSubstringMatch(value, pattern.pattern_value);
                break;

            case MatchMode::REGEX:
                match_score = PerformRegexMatch(value, pattern.pattern_value);
                break;

            case MatchMode::WILDCARD:
                match_score = PerformWildcardMatch(value, pattern.pattern_value);
                break;

            case MatchMode::FUZZY:
                match_score = PerformFuzzyMatch(value, pattern.pattern_value);
                break;
            }

            // Create match result if matched
            if (match_score > 0.0) {
                PatternMatch match;
                match.pattern_id = pattern.pattern_id;
                match.matched_value = value;
                match.pattern_type = pattern.type;
                match.match_score = match_score;
                match.confidence = pattern.confidence;
                match.family_name = pattern.family_name;
                match.variant_name = pattern.variant_name;
                match.match_time = std::chrono::steady_clock::now();
                match.context = L"Direct pattern match";

                matches.push_back(match);

                // Update hit count
                const_cast<PatternDatabase*>(this)->UpdateHitCount(pattern.pattern_id);
            }
        }

        // Update statistics
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
            end_time - start_time
        );
        const_cast<PatternDatabase*>(this)->UpdateMatchStatistics(duration);

        return matches;
    }

    /**
     * @brief Match multiple values against patterns
     */
    std::vector<PatternMatch> PatternDatabase::MatchPatterns(
        const std::vector<std::wstring>& values,
        PatternType type) const
    {
        std::vector<PatternMatch> all_matches;

        for (const auto& value : values) {
            auto matches = MatchPattern(value, type);
            all_matches.insert(all_matches.end(), matches.begin(), matches.end());
        }

        return all_matches;
    }

    /**
     * @brief Match against all pattern types
     */
    std::vector<PatternMatch> PatternDatabase::MatchAllTypes(const std::wstring& value) const
    {
        std::vector<PatternMatch> all_matches;

        // Check against all pattern types
        for (int type = static_cast<int>(PatternType::FILE_EXTENSION);
            type <= static_cast<int>(PatternType::BEHAVIOR_SEQUENCE);
            ++type) {
            auto matches = MatchPattern(value, static_cast<PatternType>(type));
            all_matches.insert(all_matches.end(), matches.begin(), matches.end());
        }

        return all_matches;
    }

    /**
     * @brief Match behavioral sequence
     */
    std::vector<std::wstring> PatternDatabase::MatchBehaviorSequence(
        const std::vector<std::wstring>& behaviors,
        std::chrono::milliseconds time_window) const
    {
        std::vector<std::wstring> matched_families;

        std::lock_guard<std::mutex> lock(sequences_mutex_);

        for (const auto& [seq_id, sequence] : behavior_sequences_) {
            // Check time window
            if (time_window > sequence.max_time_window) {
                continue;
            }

            // Count matching required behaviors
            size_t required_matches = 0;
            for (const auto& required : sequence.required_behaviors) {
                if (std::find(behaviors.begin(), behaviors.end(), required) != behaviors.end()) {
                    required_matches++;
                }
            }

            // Count optional behaviors
            size_t optional_matches = 0;
            for (const auto& optional : sequence.optional_behaviors) {
                if (std::find(behaviors.begin(), behaviors.end(), optional) != behaviors.end()) {
                    optional_matches++;
                }
            }

            // Check if minimum requirements met
            if (required_matches >= sequence.min_behaviors_required ||
                (required_matches + optional_matches) >= sequence.min_behaviors_required) {
                matched_families.push_back(sequence.family_name);
            }
        }

        // Remove duplicates
        std::sort(matched_families.begin(), matched_families.end());
        matched_families.erase(
            std::unique(matched_families.begin(), matched_families.end()),
            matched_families.end()
        );

        return matched_families;
    }

    /**
     * @brief Perform exact match
     */
    double PatternDatabase::PerformExactMatch(
        const std::wstring& value,
        const std::wstring& pattern) const
    {
        // Case-insensitive comparison
        std::wstring lower_value = value;
        std::wstring lower_pattern = pattern;

        std::transform(lower_value.begin(), lower_value.end(),
            lower_value.begin(), ::towlower);
        std::transform(lower_pattern.begin(), lower_pattern.end(),
            lower_pattern.begin(), ::towlower);

        return (lower_value == lower_pattern) ? 1.0 : 0.0;
    }

    /**
     * @brief Perform substring match
     */
    double PatternDatabase::PerformSubstringMatch(
        const std::wstring& value,
        const std::wstring& pattern) const
    {
        // Case-insensitive substring search
        std::wstring lower_value = value;
        std::wstring lower_pattern = pattern;

        std::transform(lower_value.begin(), lower_value.end(),
            lower_value.begin(), ::towlower);
        std::transform(lower_pattern.begin(), lower_pattern.end(),
            lower_pattern.begin(), ::towlower);

        return (lower_value.find(lower_pattern) != std::wstring::npos) ? 1.0 : 0.0;
    }

    /**
     * @brief Perform regex match
     */
    double PatternDatabase::PerformRegexMatch(
        const std::wstring& value,
        const std::wstring& pattern) const
    {
        try {
            // Check regex cache
            std::lock_guard<std::mutex> lock(regex_cache_mutex_);

            auto cache_it = regex_cache_.find(pattern);
            if (cache_it == regex_cache_.end()) {
                // Compile and cache regex
                if (regex_cache_.size() >= MAX_REGEX_CACHE_SIZE) {
                    // Clear cache if too large
                    regex_cache_.clear();
                }
                regex_cache_[pattern] = std::wregex(pattern, std::regex::icase);
                cache_it = regex_cache_.find(pattern);
            }

            return std::regex_match(value, cache_it->second) ? 1.0 : 0.0;
        }
        catch (const std::regex_error&) {
            return 0.0;
        }
    }

    /**
     * @brief Perform wildcard match
     */
    double PatternDatabase::PerformWildcardMatch(
        const std::wstring& value,
        const std::wstring& pattern) const
    {
        // Convert wildcard pattern to regex
        std::wstring regex_pattern;
        regex_pattern.reserve(pattern.length() * 2);

        for (wchar_t c : pattern) {
            switch (c) {
            case L'*':
                regex_pattern += L".*";
                break;
            case L'?':
                regex_pattern += L".";
                break;
            case L'.':
            case L'\\':
            case L'[':
            case L']':
            case L'{':
            case L'}':
            case L'(':
            case L')':
            case L'^':
            case L'$':
            case L'+':
            case L'|':
                regex_pattern += L"\\";
                regex_pattern += c;
                break;
            default:
                regex_pattern += c;
            }
        }

        return PerformRegexMatch(value, regex_pattern);
    }

    /**
     * @brief Perform fuzzy match
     */
    double PatternDatabase::PerformFuzzyMatch(
        const std::wstring& value,
        const std::wstring& pattern) const
    {
        // Use Levenshtein distance for fuzzy matching
        size_t distance = LevenshteinDistance(value, pattern);
        size_t max_length = std::max(value.length(), pattern.length());

        if (max_length == 0) {
            return 1.0;
        }

        double similarity = 1.0 - (static_cast<double>(distance) / max_length);

        return (similarity >= FUZZY_MATCH_THRESHOLD) ? similarity : 0.0;
    }

    /**
     * @brief Calculate Levenshtein distance
     */
    size_t PatternDatabase::LevenshteinDistance(
        const std::wstring& s1,
        const std::wstring& s2) const
    {
        size_t len1 = s1.length();
        size_t len2 = s2.length();

        if (len1 == 0) return len2;
        if (len2 == 0) return len1;

        // Create distance matrix
        std::vector<std::vector<size_t>> dist(len1 + 1, std::vector<size_t>(len2 + 1));

        // Initialize first column and row
        for (size_t i = 0; i <= len1; ++i) {
            dist[i][0] = i;
        }
        for (size_t j = 0; j <= len2; ++j) {
            dist[0][j] = j;
        }

        // Calculate distances
        for (size_t i = 1; i <= len1; ++i) {
            for (size_t j = 1; j <= len2; ++j) {
                size_t cost = (towlower(s1[i - 1]) == towlower(s2[j - 1])) ? 0 : 1;

                dist[i][j] = std::min({
                    dist[i - 1][j] + 1,        // Deletion
                    dist[i][j - 1] + 1,        // Insertion
                    dist[i - 1][j - 1] + cost  // Substitution
                    });
            }
        }

        return dist[len1][len2];
    }

    /**
     * @brief Get patterns by family
     */
    std::vector<RansomwarePattern> PatternDatabase::GetPatternsByFamily(
        const std::wstring& family_name) const
    {
        std::vector<RansomwarePattern> family_patterns;

        std::lock_guard<std::mutex> lock(patterns_mutex_);

        auto range = patterns_by_family_.equal_range(family_name);
        for (auto it = range.first; it != range.second; ++it) {
            auto pattern_it = patterns_.find(it->second);
            if (pattern_it != patterns_.end()) {
                family_patterns.push_back(pattern_it->second);
            }
        }

        return family_patterns;
    }

    /**
     * @brief Get patterns by type
     */
    std::vector<RansomwarePattern> PatternDatabase::GetPatternsByType(PatternType type) const
    {
        std::vector<RansomwarePattern> type_patterns;

        std::lock_guard<std::mutex> lock(patterns_mutex_);

        auto range = patterns_by_type_.equal_range(type);
        for (auto it = range.first; it != range.second; ++it) {
            auto pattern_it = patterns_.find(it->second);
            if (pattern_it != patterns_.end()) {
                type_patterns.push_back(pattern_it->second);
            }
        }

        return type_patterns;
    }

    /**
     * @brief Get pattern by ID
     */
    std::optional<RansomwarePattern> PatternDatabase::GetPattern(
        const std::wstring& pattern_id) const
    {
        std::lock_guard<std::mutex> lock(patterns_mutex_);

        auto it = patterns_.find(pattern_id);
        if (it != patterns_.end()) {
            return it->second;
        }

        return std::nullopt;
    }

    /**
     * @brief Update pattern hit count
     */
    void PatternDatabase::UpdateHitCount(const std::wstring& pattern_id)
    {
        std::lock_guard<std::mutex> lock(patterns_mutex_);

        auto it = patterns_.find(pattern_id);
        if (it != patterns_.end()) {
            it->second.hit_count++;
            it->second.last_updated = std::chrono::system_clock::now();
        }

        // Update total matches statistic
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        statistics_.total_matches++;
    }

    /**
     * @brief Apply pattern updates
     */
    bool PatternDatabase::ApplyUpdate(const PatternUpdate& update)
    {
        try {
            std::lock_guard<std::mutex> lock(patterns_mutex_);

            // Remove patterns
            for (const auto& pattern_id : update.removed_pattern_ids) {
                RemovePattern(pattern_id);
            }

            // Add new patterns
            for (const auto& pattern : update.new_patterns) {
                AddPattern(pattern);
            }

            // Update existing patterns
            for (const auto& pattern : update.updated_patterns) {
                UpdatePattern(pattern);
            }

            // Update last update time
            statistics_.last_update = update.update_timestamp;

            std::wcout << L"[PatternDatabase] Applied update: "
                << update.new_patterns.size() << L" new, "
                << update.updated_patterns.size() << L" updated, "
                << update.removed_pattern_ids.size() << L" removed" << std::endl;

            return true;
        }
        catch (const std::exception& e) {
            std::wcerr << L"[PatternDatabase] Failed to apply update: "
                << e.what() << std::endl;
            return false;
        }
    }

    /**
     * @brief Get patterns that need review
     */
    std::vector<RansomwarePattern> PatternDatabase::GetPatternsNeedingReview(
        double fp_threshold) const
    {
        std::vector<RansomwarePattern> review_patterns;

        std::lock_guard<std::mutex> lock(patterns_mutex_);

        for (const auto& [id, pattern] : patterns_) {
            if (pattern.false_positive_rate >= fp_threshold) {
                review_patterns.push_back(pattern);
            }
        }

        // Sort by false positive rate (highest first)
        std::sort(review_patterns.begin(), review_patterns.end(),
            [](const auto& a, const auto& b) {
                return a.false_positive_rate > b.false_positive_rate;
            });

        return review_patterns;
    }

    /**
     * @brief Search patterns by description
     */
    std::vector<RansomwarePattern> PatternDatabase::SearchPatterns(
        const std::wstring& search_term) const
    {
        std::vector<RansomwarePattern> results;

        if (search_term.empty()) {
            return results;
        }

        std::wstring lower_search = search_term;
        std::transform(lower_search.begin(), lower_search.end(),
            lower_search.begin(), ::towlower);

        std::lock_guard<std::mutex> lock(patterns_mutex_);

        for (const auto& [id, pattern] : patterns_) {
            // Search in multiple fields
            std::wstring combined = pattern.pattern_value + L" " +
                pattern.family_name + L" " +
                pattern.variant_name + L" " +
                pattern.description;

            std::transform(combined.begin(), combined.end(),
                combined.begin(), ::towlower);

            if (combined.find(lower_search) != std::wstring::npos) {
                results.push_back(pattern);
            }
        }

        return results;
    }

    /**
     * @brief Update match statistics
     */
    void PatternDatabase::UpdateMatchStatistics(std::chrono::microseconds match_time)
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);

        double time_ms = match_time.count() / 1000.0;

        // Update average match time
        if (statistics_.total_matches > 0) {
            statistics_.average_match_time_ms =
                (statistics_.average_match_time_ms * (statistics_.total_matches - 1) + time_ms) /
                statistics_.total_matches;
        }
        else {
            statistics_.average_match_time_ms = time_ms;
        }
    }

    // PatternMatcher implementation

    /**
     * @brief Match multiple patterns efficiently
     */
    std::vector<PatternMatch> PatternMatcher::BatchMatch(
        const std::vector<std::wstring>& values,
        const std::vector<RansomwarePattern>& patterns)
    {
        std::vector<PatternMatch> all_matches;

        // Optimize pattern order
        auto optimized_patterns = OptimizePatternOrder(patterns);

        // Preprocess patterns for efficiency
        auto preprocessed = PreprocessPatterns(optimized_patterns);

        // Perform batch matching
        for (const auto& value : values) {
            for (const auto& pattern : optimized_patterns) {
                double match_score = 0.0;

                // Use preprocessed data if available
                auto prep_it = preprocessed.find(pattern.pattern_id);
                std::wstring pattern_value = (prep_it != preprocessed.end()) ?
                    prep_it->second : pattern.pattern_value;

                // Perform matching based on mode
                switch (pattern.match_mode) {
                case MatchMode::EXACT:
                {
                    std::wstring lower_value = value;
                    std::transform(lower_value.begin(), lower_value.end(),
                        lower_value.begin(), ::towlower);
                    match_score = (lower_value == pattern_value) ? 1.0 : 0.0;
                }
                break;

                case MatchMode::SUBSTRING:
                {
                    std::wstring lower_value = value;
                    std::transform(lower_value.begin(), lower_value.end(),
                        lower_value.begin(), ::towlower);
                    match_score = (lower_value.find(pattern_value) != std::wstring::npos) ? 1.0 : 0.0;
                }
                break;

                default:
                    // For other modes, use standard matching
                    continue;
                }

                // Create match if found
                if (match_score > 0.0) {
                    PatternMatch match;
                    match.pattern_id = pattern.pattern_id;
                    match.matched_value = value;
                    match.pattern_type = pattern.type;
                    match.match_score = match_score;
                    match.confidence = pattern.confidence;
                    match.family_name = pattern.family_name;
                    match.variant_name = pattern.variant_name;
                    match.match_time = std::chrono::steady_clock::now();
                    match.context = L"Batch match";

                    all_matches.push_back(match);
                }
            }
        }

        return all_matches;
    }

    /**
     * @brief Optimize pattern order for matching
     */
    std::vector<RansomwarePattern> PatternMatcher::OptimizePatternOrder(
        const std::vector<RansomwarePattern>& patterns)
    {
        std::vector<RansomwarePattern> optimized = patterns;

        // Sort by:
        // 1. Match mode (exact first, then substring, etc.)
        // 2. Confidence level (critical first)
        // 3. Pattern length (shorter first for exact/substring)

        std::sort(optimized.begin(), optimized.end(),
            [](const auto& a, const auto& b) {
                // Match mode priority
                if (a.match_mode != b.match_mode) {
                    return static_cast<int>(a.match_mode) < static_cast<int>(b.match_mode);
                }

                // Confidence priority
                if (a.confidence != b.confidence) {
                    return static_cast<int>(a.confidence) > static_cast<int>(b.confidence);
                }

                // Length priority for exact/substring
                if (a.match_mode == MatchMode::EXACT || a.match_mode == MatchMode::SUBSTRING) {
                    return a.pattern_value.length() < b.pattern_value.length();
                }

                return false;
            });

        return optimized;
    }

    /**
     * @brief Preprocess patterns for faster matching
     */
    std::map<std::wstring, std::wstring> PatternMatcher::PreprocessPatterns(
        const std::vector<RansomwarePattern>& patterns)
    {
        std::map<std::wstring, std::wstring> preprocessed;

        for (const auto& pattern : patterns) {
            // Preprocess based on match mode
            if (pattern.match_mode == MatchMode::EXACT ||
                pattern.match_mode == MatchMode::SUBSTRING) {
                // Convert to lowercase for case-insensitive matching
                std::wstring lower_pattern = pattern.pattern_value;
                std::transform(lower_pattern.begin(), lower_pattern.end(),
                    lower_pattern.begin(), ::towlower);
                preprocessed[pattern.pattern_id] = lower_pattern;
            }
            // Other preprocessing can be added here
        }

        return preprocessed;
    }

} // namespace CryptoShield::Detection