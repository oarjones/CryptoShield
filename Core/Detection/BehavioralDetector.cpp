/**
 * @file BehavioralDetector.cpp
 * @brief Behavioral pattern detection implementation
 * @details Implements mass modification, extension change, and traversal detection
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */
#define NOMINMAX
#include "BehavioralDetector.h"
#include <regex> // Added
#include <iostream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <cmath>
#include <numeric>
#include <cwctype> 


namespace CryptoShield::Detection {

	// Static member definitions
	// const std::vector<std::wstring> FileExtensionMonitor::RANSOMWARE_EXTENSIONS = { ... }; // DELETE THIS
	// const std::vector<std::wstring> FileExtensionMonitor::SUSPICIOUS_PATTERNS = { ... }; // DELETE THIS

	/**
	 * @brief Constructor
	 */
	MassFileModificationDetector::MassFileModificationDetector(const DetectionEngineConfig::BehavioralConfig& config)
		: config_(config) // Ahora recibe y guarda la configuración correcta
	{
		current_window_.start_time = std::chrono::steady_clock::now();
		last_cleanup_ = current_window_.start_time;
	}

	/**
	 * @brief Analyze file operation
	 * @details This version includes the fix for the time window check.
	 */
	BehavioralAnalysisResult MassFileModificationDetector::AnalyzeOperation(
		const FileOperationInfo& operation)
	{
		std::lock_guard<std::mutex> lock(window_mutex_);

		auto now = std::chrono::steady_clock::now();

		// --- INICIO DE LA CORRECCIÓN ---
		// Se ha cambiado 'config_.window_duration' por 'std::chrono::seconds(config_.time_window_seconds)'
		// para usar el valor correcto que se carga desde el fichero de configuración.
		if (now - current_window_.start_time > std::chrono::seconds(config_.time_window_seconds)) {
			ResetWindow();
			current_window_.start_time = now;
		}
		// --- FIN DE LA CORRECCIÓN ---

		// Add operation to current window
		current_window_.operations.push_back(operation);

		// Update statistics
		std::wstring directory = ExtractDirectory(operation.file_path);
		std::wstring extension = ExtractExtension(operation.file_path);

		current_window_.affected_directories.insert(directory);
		if (!extension.empty()) {
			current_window_.file_extensions.insert(extension);
		}
		current_window_.process_operation_count[operation.process_id]++;

		// Calculate suspicion score
		double suspicion_score = CalculateSuspicionScore();

		// Build result
		BehavioralAnalysisResult result;
		result.is_suspicious = suspicion_score >= config_.suspicion_score_threshold;
		result.confidence_score = suspicion_score;
		result.operations_count = current_window_.operations.size();
		result.directories_affected = current_window_.affected_directories.size();
		result.extensions_affected = current_window_.file_extensions.size();

		// Calculate operations per second
		auto duration = now - current_window_.start_time;
		auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
		result.operations_per_second = seconds > 0 ?
			static_cast<double>(result.operations_count) / seconds : 0.0;

		// Build description
		std::wstringstream desc;
		desc << L"Operations: " << result.operations_count
			<< L", Directories: " << result.directories_affected
			<< L", Extensions: " << result.extensions_affected
			<< L", Rate: " << std::fixed << std::setprecision(2)
			<< result.operations_per_second << L" ops/sec";
		result.description = desc.str();

		// Add suspicious patterns
		if (IsRapidEncryptionPattern()) {
			result.suspicious_patterns.push_back(L"Rapid encryption-like pattern");
		}
		if (IsWideSpreadModification()) {
			result.suspicious_patterns.push_back(L"Widespread file modification");
		}

		return result;
	}


	/**
	 * @brief Reset detection window
	 */
	void MassFileModificationDetector::ResetWindow()
	{
		current_window_.operations.clear();
		current_window_.affected_directories.clear();
		current_window_.file_extensions.clear();
		current_window_.process_operation_count.clear();
		current_window_.start_time = std::chrono::steady_clock::now();
	}

	/**
	 * @brief Update configuration
	 */
	 /*void MassFileModificationDetector::UpdateConfiguration(const Configuration& config)
	 {
		 std::lock_guard<std::mutex> lock(window_mutex_);
		 config_ = config;
	 }*/

	 /**
	  * @brief Get current window statistics
	  */
	MassFileModificationDetector::WindowStatistics
		MassFileModificationDetector::GetWindowStatistics() const
	{
		std::lock_guard<std::mutex> lock(window_mutex_);

		WindowStatistics stats;
		stats.operation_count = current_window_.operations.size();
		stats.directory_count = current_window_.affected_directories.size();
		stats.extension_count = current_window_.file_extensions.size();
		stats.window_start = current_window_.start_time;
		stats.window_end = std::chrono::steady_clock::now();

		auto duration = stats.window_end - stats.window_start;
		auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
		stats.operations_per_second = seconds > 0 ?
			static_cast<double>(stats.operation_count) / seconds : 0.0;

		return stats;
	}

	/**
	 * @brief Calculates a suspicion score based on the current operation window.
	 * @details The scoring is now more sensitive once thresholds are met to improve detection rates.
	 * @return A suspicion score between 0.0 and 1.0.
	 */
	double MassFileModificationDetector::CalculateSuspicionScore() const
	{
		double score = 0.0;

		// --- INICIO DE LA CORRECCIÓN ---
		// Se han ajustado las fórmulas de normalización para que el score 
		// aumente más rápido una vez que se superan los umbrales básicos.
		// Esto hace la detección más sensible a ráfagas de actividad.

		// Factor 1: Operation count (contribuye hasta 0.4 al score)
		if (current_window_.operations.size() >= config_.min_operations_threshold) {
			score += 0.4 * std::min(
				static_cast<double>(current_window_.operations.size()) / (config_.min_operations_threshold), 1.0
			);
		}

		// Factor 2: Directory spread (contribuye hasta 0.3 al score)
		if (current_window_.affected_directories.size() >= config_.min_directories_threshold) {
			score += 0.3 * std::min(
				static_cast<double>(current_window_.affected_directories.size()) / (config_.min_directories_threshold), 1.0
			);
		}

		// Factor 3: Extension variety (contribuye hasta 0.2 al score)
		if (current_window_.file_extensions.size() >= config_.min_extensions_threshold) {
			score += 0.2 * std::min(
				static_cast<double>(current_window_.file_extensions.size()) / (config_.min_extensions_threshold), 1.0
			);
		}

		// Factor 4: Operation rate (contribuye hasta 0.1 al score)
		auto duration = std::chrono::steady_clock::now() - current_window_.start_time;
		auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
		if (seconds > 0) {
			double rate = static_cast<double>(current_window_.operations.size()) / seconds;
			if (rate > config_.max_operations_per_second) {
				score += 0.1 * std::min(rate / (config_.max_operations_per_second), 1.0);
			}
		}

		return std::min(score, 1.0); // El score se capa en 1.0 para mantenerlo en el rango [0, 1]
		// --- FIN DE LA CORRECCIÓN ---
	}

	/**
	 * @brief Check if pattern matches rapid encryption
	 */
	bool MassFileModificationDetector::IsRapidEncryptionPattern() const
	{
		if (current_window_.operations.size() < config_.min_operations_threshold) {
			return false;
		}

		// Check for high write/rename ratio
		size_t writes = 0, renames = 0;
		for (const auto& op : current_window_.operations) {
			if (op.type == FileOperationType::Write) writes++;
			else if (op.type == FileOperationType::Rename) renames++;
		}

		double write_ratio = static_cast<double>(writes) / current_window_.operations.size();
		double rename_ratio = static_cast<double>(renames) / current_window_.operations.size();

		return (write_ratio > 0.4 && rename_ratio > 0.2) ||
			(write_ratio > 0.6) ||
			(rename_ratio > 0.4);
	}

	/**
	 * @brief Check if modifications are widespread
	 */
	bool MassFileModificationDetector::IsWideSpreadModification() const
	{
		return current_window_.affected_directories.size() >= config_.min_directories_threshold &&
			current_window_.file_extensions.size() >= config_.min_extensions_threshold;
	}

	/**
	 * @brief Extract directory from file path
	 */
	std::wstring MassFileModificationDetector::ExtractDirectory(const std::wstring& file_path) const
	{
		size_t last_slash = file_path.find_last_of(L"\\");
		if (last_slash != std::wstring::npos) {
			return file_path.substr(0, last_slash);
		}
		return L"";
	}

	/**
	 * @brief Extract file extension
	 */
	std::wstring MassFileModificationDetector::ExtractExtension(const std::wstring& file_path) const
	{
		size_t last_dot = file_path.find_last_of(L".");
		if (last_dot != std::wstring::npos && last_dot < file_path.length() - 1) {
			return file_path.substr(last_dot);
		}
		return L"";
	}

	/**
	 * @brief Constructor
	 */
	FileExtensionMonitor::FileExtensionMonitor(const DetectionEngineConfig::BehavioralConfig& config)
		: config_(config) {

	}

	/**
	 * @brief Analyzes a file rename operation, now including time-based frequency.
	 * @details Checks for bad extensions, suspicious patterns, and a high rate of renames.
	 * @return An ExtensionChangeEvent struct with the analysis result.
	 */
	ExtensionChangeEvent FileExtensionMonitor::AnalyzeFileRename(
		const std::wstring& old_path,
		const std::wstring& new_path,
		ULONG process_id)
	{
		ExtensionChangeEvent event;
		event.file_path = old_path;
		event.timestamp = std::chrono::steady_clock::now();
		event.process_id = process_id;

		std::filesystem::path old_p(old_path);
		std::filesystem::path new_p(new_path);

		event.original_extension = old_p.has_extension() ? old_p.extension().wstring() : L"";
		event.new_extension = new_p.has_extension() ? new_p.extension().wstring() : L"";

		// 1. Puntuación basada en la extensión y el nombre de archivo (lógica que ya teníamos)
		event.suspicion_score = CalculateExtensionSuspicion(event.new_extension);
		if (MatchesSuspiciousPattern(new_p.filename().wstring())) {
			event.suspicion_score = std::max(event.suspicion_score, 0.9);
		}

		// 2. Nuevo: Análisis de frecuencia de renombrado
		{
			std::lock_guard<std::mutex> lock(changes_mutex_); // Usamos el mutex existente
			auto& timestamps = rename_timestamps_;
			auto now = std::chrono::steady_clock::now();

			// Añadir la marca de tiempo actual
			timestamps.push_back(now);

			// Eliminar las marcas de tiempo que estén fuera de la ventana de 60 segundos
			auto time_window = std::chrono::seconds(config_.time_window_seconds);
			while (!timestamps.empty() && (now - timestamps.front() > time_window)) {
				timestamps.pop_front();
			}

			// Si hay muchos renombrados recientes, aumenta la puntuación
			const size_t RENAME_BURST_THRESHOLD = 15; // Umbral de ejemplo: 15 renombres en 60s
			if (timestamps.size() > RENAME_BURST_THRESHOLD) {
				double frequency_score = 0.5 * std::min(static_cast<double>(timestamps.size()) / (RENAME_BURST_THRESHOLD * 2), 1.0);
				event.suspicion_score = std::max(event.suspicion_score, frequency_score);
			}
		}

		event.is_suspicious = event.suspicion_score > 0.5;

		// ... (el resto de la función para almacenar el historial no cambia) ...
		{
			std::lock_guard<std::mutex> lock(extensions_mutex_);
			original_extensions_[new_path] = event.original_extension;
		}
		{
			std::lock_guard<std::mutex> lock(changes_mutex_);
			extension_changes_.push_back(event);
			if (extension_changes_.size() > 10000) {
				extension_changes_.erase(extension_changes_.begin());
			}
		}

		return event;
	}



	/**
	 * @brief Calculate extension suspicion score
	 */
	double FileExtensionMonitor::CalculateExtensionSuspicion(const std::wstring& extension) const
	{
		if (extension.empty()) {
			return 0.0;
		}

		// Convert to lowercase for comparison
		std::wstring lower_ext = extension;
		std::transform(lower_ext.begin(), lower_ext.end(), lower_ext.begin(), ::towlower);

		// Check if it's a known ransomware extension
		if (IsKnownRansomwareExtension(lower_ext)) {
			return 1.0;
		}

		// Check if it matches suspicious patterns
		if (MatchesSuspiciousPattern(lower_ext)) {
			return 0.8;
		}

		// Check for unusual characteristics
		double score = 0.0;

		// Long extensions are suspicious
		if (extension.length() > 10) {
			score += 0.3;
		}

		// Multiple dots are suspicious
		size_t dot_count = std::count(extension.begin(), extension.end(), L'.');
		if (dot_count > 1) {
			score += 0.2;
		}

		// Extensions with numbers are somewhat suspicious
		if (std::any_of(extension.begin(), extension.end(), ::iswdigit)) {
			score += 0.1;
		}

		// Random-looking extensions (high entropy) are suspicious
		std::set<wchar_t> unique_chars(extension.begin(), extension.end());
		double char_ratio = static_cast<double>(unique_chars.size()) / extension.length();
		if (char_ratio > 0.8) {
			score += 0.2;
		}

		return std::min(score, 1.0);
	}

	/**
	 * @brief Check if extension is known ransomware indicator
	 */
	 /*bool FileExtensionMonitor::IsKnownRansomwareExtension(const std::wstring& extension) const
	 {
		 return std::find(config_.suspicious_extensions.begin(), config_.suspicious_extensions.end(), extension) != config_.suspicious_extensions.end();
	 }*/
	bool FileExtensionMonitor::IsKnownRansomwareExtension(const std::wstring& extension) const
	{
		const auto& known_extensions = config_.suspicious_extensions;
		// La llamada correcta a std::find requiere el iterador final.
		return std::find(known_extensions.begin(), known_extensions.end(), extension) != known_extensions.end();
	}

	/**
	 * @brief Get recent extension changes
	 */
	std::vector<ExtensionChangeEvent> FileExtensionMonitor::GetRecentChanges(
		std::chrono::seconds max_age) const
	{
		std::lock_guard<std::mutex> lock(changes_mutex_);

		auto now = std::chrono::steady_clock::now();
		std::vector<ExtensionChangeEvent> recent;

		for (const auto& event : extension_changes_) {
			if (now - event.timestamp <= max_age) {
				recent.push_back(event);
			}
		}

		return recent;
	}

	/**
	 * @brief Clear old extension change records
	 */
	void FileExtensionMonitor::CleanupOldRecords(std::chrono::seconds max_age)
	{
		std::lock_guard<std::mutex> lock(changes_mutex_);

		auto now = std::chrono::steady_clock::now();
		extension_changes_.erase(
			std::remove_if(extension_changes_.begin(), extension_changes_.end(),
				[&](const ExtensionChangeEvent& event) {
					return now - event.timestamp > max_age;
				}),
			extension_changes_.end()
		);
	}

	/**
	 * @brief Checks if a filename matches any of the configured suspicious regex patterns.
	 * @param filename The filename (not the full path) to check.
	 * @return True if a match is found, false otherwise.
	 */
	bool FileExtensionMonitor::MatchesSuspiciousPattern(const std::wstring& filename) const
	{
		// --- INICIO DE LA CORRECCIÓN ---
		// La función ahora opera sobre el nombre de archivo completo, no solo la extensión.
		const auto& patterns = config_.suspicious_patterns_regex;

		for (const auto& pattern_str : patterns) {
			try {
				std::wregex pattern_regex(pattern_str, std::regex_constants::icase);
				if (std::regex_match(filename, pattern_regex)) {
					return true; // Se encontró una coincidencia
				}
			}
			catch (const std::regex_error& e) {
				// Loguea el error si un patrón en la configuración es inválido.
				std::wcerr << L"Invalid regex pattern in configuration: " << pattern_str << L" - " << e.what() << std::endl;
			}
		}

		return false; // No se encontraron coincidencias
		// --- FIN DE LA CORRECCIÓN ---
	}


	/**
	 * @brief Constructor
	 */
	DirectoryTraversalDetector::DirectoryTraversalDetector()
	{
	}

	/**
	 * @brief Analyze file operation for traversal patterns
	 */
	void DirectoryTraversalDetector::AnalyzeOperation(
		const FileOperationInfo& operation, ULONG process_id)
	{
		std::lock_guard<std::mutex> lock(traversal_mutex_);

		// Extract directory
		//size_t last_slash = operation.file_path.find_last_of(L"\\");
		size_t last_slash = operation.file_path.find_last_of(L"\\");
		if (last_slash == std::wstring::npos) {
			return;
		}

		//std::wstring directory = operation.file_path.substr(0, last_slash);
		std::wstring directory = operation.file_path.substr(0, last_slash);

		// Update process traversal info
		auto& info = process_traversals_[process_id];

		if (info.visited_directories.empty()) {
			info.first_access = std::chrono::steady_clock::now();
			info.root_directory = directory;
		}

		info.visited_directories.insert(directory);
		info.last_access = std::chrono::steady_clock::now();
		info.files_affected++;

		// Update max depth
		size_t depth = CalculateDirectoryDepth(directory);
		info.max_depth = std::max(info.max_depth, depth);
	}

	/**
	 * @brief Get traversal pattern for process
	 */
	std::optional<DirectoryTraversalPattern> DirectoryTraversalDetector::GetTraversalPattern(
		ULONG process_id) const
	{
		std::lock_guard<std::mutex> lock(traversal_mutex_);

		auto it = process_traversals_.find(process_id);
		if (it == process_traversals_.end()) {
			return std::nullopt;
		}

		const auto& info = it->second;

		DirectoryTraversalPattern pattern;
		pattern.root_directory = FindCommonRoot(info.visited_directories);
		pattern.traversed_directories = std::vector<std::wstring>(
			info.visited_directories.begin(),
			info.visited_directories.end()
		);
		pattern.depth = info.max_depth;
		pattern.is_recursive = info.max_depth > 2 && info.visited_directories.size() > 5;
		pattern.start_time = info.first_access;
		pattern.end_time = info.last_access;
		pattern.files_affected = info.files_affected;

		return pattern;
	}

	/**
	 * @brief Check if process shows recursive traversal
	 */
	bool DirectoryTraversalDetector::IsRecursiveTraversal(ULONG process_id) const
	{
		auto pattern = GetTraversalPattern(process_id);
		return pattern.has_value() && pattern->is_recursive;
	}

	/**
	 * @brief Calculate traversal suspicion score
	 */
	double DirectoryTraversalDetector::CalculateTraversalSuspicion(
		const DirectoryTraversalPattern& pattern) const
	{
		double score = 0.0;

		// Factor 1: Depth (0-0.3)
		if (pattern.depth > 3) {
			score += 0.3 * std::min(pattern.depth / 10.0, 1.0);
		}

		// Factor 2: Directory count (0-0.3)
		if (pattern.traversed_directories.size() > 10) {
			score += 0.3 * std::min(pattern.traversed_directories.size() / 50.0, 1.0);
		}

		// Factor 3: Files affected (0-0.2)
		if (pattern.files_affected > 100) {
			score += 0.2 * std::min(pattern.files_affected / 1000.0, 1.0);
		}

		// Factor 4: Speed (0-0.2)
		auto duration = pattern.end_time - pattern.start_time;
		auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
		if (seconds > 0 && pattern.files_affected > 0) {
			double files_per_second = static_cast<double>(pattern.files_affected) / seconds;
			if (files_per_second > 10) {
				score += 0.2 * std::min(files_per_second / 50.0, 1.0);
			}
		}

		return score;
	}

	/**
	 * @brief Clear traversal data for process
	 */
	void DirectoryTraversalDetector::ClearProcessData(ULONG process_id)
	{
		std::lock_guard<std::mutex> lock(traversal_mutex_);
		process_traversals_.erase(process_id);
	}

	/**
	 * @brief Calculate directory depth
	 */
	size_t DirectoryTraversalDetector::CalculateDirectoryDepth(const std::wstring& directory) const
	{
		return std::count(directory.begin(), directory.end(), L'\\');
	}

	/**
	 * @brief Find common root directory
	 */
	std::wstring DirectoryTraversalDetector::FindCommonRoot(
		const std::set<std::wstring>& directories) const
	{
		if (directories.empty()) {
			return L"";
		}

		// Start with the first directory
		std::wstring common = *directories.begin();

		// Find common prefix with all other directories
		for (const auto& dir : directories) {
			size_t i = 0;
			while (i < common.length() && i < dir.length() && common[i] == dir[i]) {
				i++;
			}
			common = common.substr(0, i);
		}

		// Trim to last complete directory
		size_t last_slash = common.find_last_of(L"\\");
		if (last_slash != std::wstring::npos) {
			common = common.substr(0, last_slash);
		}

		return common;
	}


	/**
	 * @brief Constructor
	 */
	BehavioralDetector::BehavioralDetector(const DetectionEngineConfig::BehavioralConfig& config)
		: config_(config), // Guarda la configuración
		total_operations_analyzed_(0),
		suspicious_patterns_detected_(0)
	{
		// Pasa la configuración al sub-componente
		mass_modification_detector_ = std::make_unique<MassFileModificationDetector>(config);
		extension_monitor_ = std::make_unique<FileExtensionMonitor>(config);
		traversal_detector_ = std::make_unique<DirectoryTraversalDetector>();
	}

	/**
	 * @brief Destructor
	 */
	BehavioralDetector::~BehavioralDetector() = default;



	/**
	 * @brief Calculates a suspicion score based on the entire historical profile of a process.
	 * @details This function evaluates long-term indicators like total operations, directory/extension
	 * spread, and the ratio of potentially malicious operations (writes/renames).
	 * @param profile The process profile to analyze.
	 * @return A suspicion score between 0.0 and 1.0.
	 */
	double BehavioralDetector::CalculateCombinedScore(const ProcessBehaviorProfile& profile) const
	{
		double score = 0.0;

		// Puntuación basada en el volumen total de operaciones (indicador de actividad masiva)
		if (profile.total_operations > 50) {
			score += 0.3 * std::min(profile.total_operations / 500.0, 1.0);
		}

		// Puntuación basada en la variedad de extensiones afectadas
		if (profile.affected_extensions.size() > 5) {
			score += 0.2 * std::min(profile.affected_extensions.size() / 20.0, 1.0);
		}

		// Puntuación basada en la dispersión de directorios
		if (profile.affected_directories.size() > 3) {
			score += 0.2 * std::min(profile.affected_directories.size() / 15.0, 1.0);
		}

		// Puntuación basada en la proporción de operaciones "peligrosas" (escrituras y renombrados)
		if (profile.total_operations > 0) {
			double write_ratio = static_cast<double>(profile.write_operations) / profile.total_operations;
			double rename_ratio = static_cast<double>(profile.rename_operations) / profile.total_operations;

			if (write_ratio > 0.5 || rename_ratio > 0.3) {
				score += 0.3 * std::max(write_ratio, rename_ratio);
			}
		}

		return std::min(score, 1.0);
	}



	/**
	 * @brief Analyzes a single file operation by orchestrating all behavioral sub-detectors.
	 * @details Combines evidence from short-term window analysis, specific rename analysis,
	 * and long-term historical process profiling to make a final decision.
	 * @param operation The file operation to analyze.
	 * @return A comprehensive behavioral analysis result.
	 */
	BehavioralAnalysisResult BehavioralDetector::AnalyzeOperation(
		const FileOperationInfo& operation)
	{
		total_operations_analyzed_++;
		UpdateProcessProfile(operation);

		// 1. Analizar la actividad en la ventana de tiempo actual (ráfagas)
		BehavioralAnalysisResult result = mass_modification_detector_->AnalyzeOperation(operation);
		double final_score = result.confidence_score;

		// 2. Analizar la operación de renombrado (si aplica)
		if (operation.type == FileOperationType::Rename) {
			auto rename_event = extension_monitor_->AnalyzeFileRename(
				operation.file_path,
				operation.new_file_path,
				operation.process_id
			);
			if (rename_event.is_suspicious) {
				final_score = std::max(final_score, rename_event.suspicion_score);
				result.suspicious_patterns.push_back(L"Suspicious Rename Activity");
			}
		}

		// 3. Analizar el perfil histórico completo del proceso
		{
			std::lock_guard<std::mutex> lock(profiles_mutex_);
			const auto& profile = process_profiles_[operation.process_id];
			double historical_score = CalculateCombinedScore(profile);
			final_score = std::max(final_score, historical_score);
		}

		// 4. Actualizar el resultado con la puntuación final combinada
		result.confidence_score = final_score;
		result.is_suspicious = result.confidence_score >= config_.suspicion_score_threshold;

		if (result.is_suspicious) {
			suspicious_patterns_detected_++;
		}

		return result;
	}



	/**
	 * @brief Analyze batch of operations
	 */
	BehavioralAnalysisResult BehavioralDetector::AnalyzeBatch(
		const std::vector<FileOperationInfo>& operations)
	{
		BehavioralAnalysisResult result;

		if (operations.empty()) {
			return result;
		}

		// Analyze each operation
		double max_score = 0.0;
		for (const auto& op : operations) {
			auto op_result = AnalyzeOperation(op);
			max_score = std::max(max_score, op_result.confidence_score);

			// Merge suspicious patterns
			result.suspicious_patterns.insert(
				result.suspicious_patterns.end(),
				op_result.suspicious_patterns.begin(),
				op_result.suspicious_patterns.end()
			);
		}

		// Remove duplicates
		std::sort(result.suspicious_patterns.begin(), result.suspicious_patterns.end());
		result.suspicious_patterns.erase(
			std::unique(result.suspicious_patterns.begin(), result.suspicious_patterns.end()),
			result.suspicious_patterns.end()
		);

		// Detect temporal anomalies
		double temporal_score = DetectTemporalAnomalies(operations);

		// Final score
		result.confidence_score = std::max(max_score, temporal_score);
		result.is_suspicious = result.confidence_score > 0.6;

		// Get window statistics for description
		auto stats = mass_modification_detector_->GetWindowStatistics();
		result.operations_count = stats.operation_count;
		result.directories_affected = stats.directory_count;
		result.extensions_affected = stats.extension_count;
		result.operations_per_second = stats.operations_per_second;

		return result;
	}

	/**
	 * @brief Configure detection thresholds
	 */
	 /*void BehavioralDetector::ConfigureThresholds(size_t min_operations,
		 size_t min_directories,
		 size_t min_extensions,
		 double max_rate)
	 {
		 MassFileModificationDetector::Configuration config;
		 config.min_operations_threshold = min_operations;
		 config.min_directories_threshold = min_directories;
		 config.min_extensions_threshold = min_extensions;
		 config.max_operations_per_second = max_rate;

		 mass_modification_detector_->UpdateConfiguration(config);
		 config_ = config;
	 }*/

	 /**
	  * @brief Get process behavior profile
	  */
	std::optional<ProcessBehaviorProfile> BehavioralDetector::GetProcessProfile(
		ULONG process_id) const
	{
		std::lock_guard<std::mutex> lock(profiles_mutex_);

		auto it = process_profiles_.find(process_id);
		if (it != process_profiles_.end()) {
			return it->second;
		}

		return std::nullopt;
	}

	/**
	 * @brief Clear process history
	 */
	void BehavioralDetector::ClearProcessHistory(ULONG process_id)
	{
		std::lock_guard<std::mutex> lock(profiles_mutex_);

		if (process_id == 0) {
			process_profiles_.clear();
		}
		else {
			process_profiles_.erase(process_id);
			traversal_detector_->ClearProcessData(process_id);
		}
	}

	/**
	 * @brief Get detector statistics
	 */
	BehavioralDetector::Statistics BehavioralDetector::GetStatistics() const
	{
		Statistics stats;
		stats.total_operations_analyzed = total_operations_analyzed_.load();
		stats.suspicious_patterns_detected = suspicious_patterns_detected_.load();

		{
			std::lock_guard<std::mutex> lock(profiles_mutex_);
			stats.processes_tracked = process_profiles_.size();

			double total_score = 0.0;
			for (const auto& [pid, profile] : process_profiles_) {
				total_score += profile.overall_suspicion_score;
			}

			stats.average_confidence_score = stats.processes_tracked > 0 ?
				total_score / stats.processes_tracked : 0.0;
		}

		return stats;
	}

	/**
	 * @brief Updates the historical behavior profile for a given process.
	 * @details This function ONLY accumulates statistics. It no longer calculates scores.
	 */
	void BehavioralDetector::UpdateProcessProfile(const FileOperationInfo& operation)
	{
		std::lock_guard<std::mutex> lock(profiles_mutex_);

		auto& profile = process_profiles_[operation.process_id];

		if (profile.process_id == 0) {
			profile.process_id = operation.process_id;
			profile.first_seen = std::chrono::steady_clock::now();
			profile.process_name = L"Unknown"; // Se podría obtener el nombre real aquí
		}

		profile.last_seen = std::chrono::steady_clock::now();
		profile.total_operations++;

		switch (operation.type) {
		case FileOperationType::Write: profile.write_operations++; break;
		case FileOperationType::Delete: profile.delete_operations++; break;
		case FileOperationType::Rename: profile.rename_operations++; break;
		default: break;
		}

		std::filesystem::path p(operation.file_path);
		if (p.has_parent_path()) {
			profile.affected_directories.insert(p.parent_path().wstring());
		}
		if (p.has_extension()) {
			profile.affected_extensions.insert(p.extension().wstring());
		}
		// NOTA: Se ha eliminado la llamada a CalculateCombinedScore de aquí.
	}


	/**
	 * @brief Detect temporal anomalies
	 */
	double BehavioralDetector::DetectTemporalAnomalies(
		const std::vector<FileOperationInfo>& operations) const
	{
		if (operations.size() < 10) {
			return 0.0;
		}

		// Calculate inter-operation times
		std::vector<double> intervals;
		for (size_t i = 1; i < operations.size(); ++i) {
			/*
			auto duration = operations[i].timestamp - operations[i - 1].timestamp;
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
			intervals.push_back(static_cast<double>(ms));
			*/

			// Corregido
			ULARGE_INTEGER time1, time2;
			time1.LowPart = operations[i].timestamp.dwLowDateTime;
			time1.HighPart = operations[i].timestamp.dwHighDateTime;
			time2.LowPart = operations[i - 1].timestamp.dwLowDateTime;
			time2.HighPart = operations[i - 1].timestamp.dwHighDateTime;

			// La resta da un valor en unidades de 100-nanosegundos. Lo convertimos a milisegundos.
			auto ms = static_cast<double>((time1.QuadPart - time2.QuadPart) / 10000.0);
			intervals.push_back(ms);




		}

		// Calculate statistics
		double sum = std::accumulate(intervals.begin(), intervals.end(), 0.0);
		double mean = sum / intervals.size();

		double sq_sum = 0.0;
		for (double interval : intervals) {
			sq_sum += (interval - mean) * (interval - mean);
		}
		double std_dev = std::sqrt(sq_sum / intervals.size());

		// Low standard deviation with high frequency indicates automated behavior
		if (std_dev < 100 && mean < 100) {  // Very regular, fast operations
			return 0.8;
		}
		else if (std_dev < 500 && mean < 500) {  // Regular, moderately fast
			return 0.5;
		}

		return 0.0;
	}

} // namespace CryptoShield::Detection