/**
 * @file MessageProcessor.cpp
 * @brief Message processing and analysis implementation
 * @details Processes file operation messages and detects suspicious patterns
 *
 * @copyright Copyright (c) 2025 CryptoShield Project
 */

#include "MessageProcessor.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <psapi.h>
#include <optional>


namespace CryptoShield {

	// Known suspicious extensions used by ransomware
	const std::vector<std::wstring> MessageProcessor::SUSPICIOUS_EXTENSIONS = {
		L".locked", L".encrypted", L".crypto", L".enc", L".crypted",
		L".locked", L".kraken", L".darkness", L".nochance", L".ecc",
		L".ezz", L".exy", L".zzz", L".xyz", L".aaa", L".abc",
		L".crypt", L".darkness", L".encr", L".locky", L".osiris"
	};

	/**
	 * @brief Constructor
	 */
	MessageProcessor::MessageProcessor(const ProcessorConfig& config)
		: config_(config)
		, running_(false)
		, statistics_{ 0, 0, 0, 0, 0, 0 }
	{
		// Set defaults if not provided
		if (config_.log_directory.empty()) {
			config_.log_directory = L"C:\\ProgramData\\CryptoShield\\Logs";
		}
		if (config_.max_queue_size == 0) {
			config_.max_queue_size = 10000;
		}
		if (config_.processing_threads == 0) {
			config_.processing_threads = 2;
		}
		if (config_.alert_threshold == 0) {
			config_.alert_threshold = 50;
		}

		statistics_.start_time = std::chrono::steady_clock::now();
	}

	/**
	 * @brief Destructor
	 */
	MessageProcessor::~MessageProcessor()
	{
		Stop();
	}

	/**
	 * @brief Start processing
	 */
	bool MessageProcessor::Start()
	{
		if (running_.load()) {
			return false;
		}

		std::wcout << L"[MessageProcessor] Starting with "
			<< config_.processing_threads << L" threads" << std::endl;

		// Create log directory if needed
		if (config_.enable_logging) {
			try {
				std::filesystem::create_directories(config_.log_directory);
			}
			catch (const std::exception& e) {
				std::wcerr << L"[MessageProcessor] Failed to create log directory: "
					<< e.what() << std::endl;
				return false;
			}
		}

		running_ = true;

		// Start processing threads
		for (ULONG i = 0; i < config_.processing_threads; ++i) {
			processing_threads_.emplace_back(&MessageProcessor::ProcessingThreadProc, this);
		}

		return true;
	}

	/**
	 * @brief Stop processing
	 */
	void MessageProcessor::Stop()
	{
		if (!running_.load()) {
			return;
		}

		std::wcout << L"[MessageProcessor] Stopping..." << std::endl;

		// Signal threads to stop
		running_ = false;
		queue_cv_.notify_all();

		// Wait for threads to finish
		for (auto& thread : processing_threads_) {
			if (thread.joinable()) {
				thread.join();
			}
		}
		processing_threads_.clear();

		// Close log file
		{
			std::lock_guard<std::mutex> lock(log_mutex_);
			if (log_file_.is_open()) {
				log_file_.close();
			}
		}

		std::wcout << L"[MessageProcessor] Stopped" << std::endl;
	}

	/**
	 * @brief Enqueue operation for processing
	 */
	void MessageProcessor::EnqueueOperation(const FileOperationInfo& operation)
	{
		{
			std::lock_guard<std::mutex> lock(queue_mutex_);

			// Check queue size limit
			if (operation_queue_.size() >= config_.max_queue_size) {
				// Remove oldest operation
				operation_queue_.pop();
			}

			operation_queue_.push(operation);
		}

		queue_cv_.notify_one();
	}

	/**
	 * @brief Get current queue size
	 */
	size_t MessageProcessor::GetQueueSize() const
	{
		std::lock_guard<std::mutex> lock(queue_mutex_);
		return operation_queue_.size();
	}

	/**
	 * @brief Get statistics
	 */
	FileOperationStats MessageProcessor::GetStatistics() const
	{
		std::lock_guard<std::mutex> lock(stats_mutex_);
		return statistics_;
	}

	/**
	 * @brief Get process information
	 */
	std::optional<ProcessInfo> MessageProcessor::GetProcessInfo(ULONG process_id) const
	{
		std::lock_guard<std::mutex> lock(process_mutex_);

		auto it = process_map_.find(process_id);
		if (it != process_map_.end()) {
			return it->second;
		}

		return std::nullopt;
	}

	/**
	 * @brief Get all tracked processes
	 */
	std::vector<ProcessInfo> MessageProcessor::GetAllProcesses() const
	{
		std::lock_guard<std::mutex> lock(process_mutex_);

		std::vector<ProcessInfo> processes;
		processes.reserve(process_map_.size());

		for (const auto& pair : process_map_) {
			processes.push_back(pair.second);
		}

		return processes;
	}

	/**
	 * @brief Set alert callback
	 */
	void MessageProcessor::SetAlertCallback(AlertCallback callback)
	{
		std::lock_guard<std::mutex> lock(alert_mutex_);
		alert_callback_ = callback;
	}

	/**
	 * @brief Update configuration
	 */
	void MessageProcessor::UpdateConfiguration(const ProcessorConfig& config)
	{
		// Note: Some config changes may require restart
		config_ = config;
		std::wcout << L"[MessageProcessor] Configuration updated" << std::endl;
	}

	/**
	 * @brief Clear operation history
	 */
	void MessageProcessor::ClearHistory()
	{
		{
			std::lock_guard<std::mutex> lock(process_mutex_);
			process_map_.clear();
		}

		{
			std::lock_guard<std::mutex> lock(stats_mutex_);
			statistics_ = { 0, 0, 0, 0, 0, 0 };
			statistics_.start_time = std::chrono::steady_clock::now();
		}

		{
			std::lock_guard<std::mutex> lock(alert_mutex_);
			recent_alerts_.clear();
		}

		std::wcout << L"[MessageProcessor] History cleared" << std::endl;
	}

	/**
	 * @brief Processing thread procedure
	 */
	void MessageProcessor::ProcessingThreadProc()
	{
		std::wcout << L"[MessageProcessor] Processing thread started" << std::endl;

		while (running_.load()) {
			FileOperationInfo operation;

			// Get operation from queue
			{
				std::unique_lock<std::mutex> lock(queue_mutex_);

				queue_cv_.wait(lock, [this] {
					return !operation_queue_.empty() || !running_.load();
					});

				if (!running_.load()) {
					break;
				}

				if (operation_queue_.empty()) {
					continue;
				}

				operation = operation_queue_.front();
				operation_queue_.pop();
			}

			// Process the operation
			ProcessOperation(operation);
		}

		std::wcout << L"[MessageProcessor] Processing thread stopped" << std::endl;
	}

	/**
	 * @brief Process single operation
	 */
	void MessageProcessor::ProcessOperation(const FileOperationInfo& operation)
	{
		// Update statistics
		{
			std::lock_guard<std::mutex> lock(stats_mutex_);
			statistics_.total_operations++;
			statistics_.last_operation = std::chrono::steady_clock::now();

			switch (operation.type) {
			case FileOperationType::Create:
				statistics_.creates++;
				break;
			case FileOperationType::Write:
				statistics_.writes++;
				break;
			case FileOperationType::Delete:
				statistics_.deletes++;
				break;
			case FileOperationType::Rename:
				statistics_.renames++;
				break;
			case FileOperationType::SetInformation:
				statistics_.set_information++;
				break;
			}
		}

		// Update process information
		UpdateProcessInfo(operation);

		// Analyze operation
		ULONG suspicion_level = AnalyzeOperation(operation);

		// Log operation if enabled
		if (config_.enable_logging) {
			LogOperation(operation);
		}

		// Check for alerts
		if (config_.enable_alerts && suspicion_level >= config_.alert_threshold) {
			AlertSeverity severity = AlertSeverity::Low;
			if (suspicion_level >= 80) {
				severity = AlertSeverity::Critical;
			}
			else if (suspicion_level >= 60) {
				severity = AlertSeverity::High;
			}
			else if (suspicion_level >= 40) {
				severity = AlertSeverity::Medium;
			}

			std::wstring description = L"Suspicious activity detected: " +
				operation.GetOperationTypeString() +
				L" on " + operation.file_path;

			GenerateAlert(severity, description, operation);
		}

		// Check for suspicious patterns
		if (CheckSuspiciousPatterns(operation.process_id)) {
			GenerateAlert(AlertSeverity::High,
				L"Suspicious pattern detected for process " +
				std::to_wstring(operation.process_id),
				operation);
		}
	}

	/**
	 * @brief Update process information
	 */
	void MessageProcessor::UpdateProcessInfo(const FileOperationInfo& operation)
	{
		std::lock_guard<std::mutex> lock(process_mutex_);

		auto& process_info = process_map_[operation.process_id];

		if (process_info.process_id == 0) {
			// New process
			process_info.process_id = operation.process_id;
			process_info.process_name = GetProcessName(operation.process_id);
			process_info.first_seen = std::chrono::steady_clock::now();
			process_info.operation_count = 0;
			process_info.suspicious_operations = 0;
		}

		process_info.last_seen = std::chrono::steady_clock::now();
		process_info.operation_count++;
	}

	/**
	 * @brief Analyze operation for suspicious behavior
	 */
	ULONG MessageProcessor::AnalyzeOperation(const FileOperationInfo& operation)
	{
		ULONG suspicion_level = 0;

		// Check for suspicious file extensions
		if (IsSuspiciousExtension(operation.file_path)) {
			suspicion_level += 30;
		}

		// Check operation type patterns
		switch (operation.type) {
		case FileOperationType::Write:
			// Multiple writes could indicate encryption
			suspicion_level += 5;
			break;

		case FileOperationType::Delete:
			// Mass deletion is suspicious
			suspicion_level += 10;
			break;

		case FileOperationType::Rename:
			// Check if renaming to suspicious extension
			if (IsSuspiciousExtension(operation.file_path)) {
				suspicion_level += 40;
			}
			else {
				suspicion_level += 5;
			}
			break;
		}

		// Check operation rate
		double rate = CalculateOperationRate(operation.process_id);
		if (rate > SUSPICIOUS_RATE_THRESHOLD) {
			suspicion_level += static_cast<ULONG>(rate / SUSPICIOUS_RATE_THRESHOLD * 10);
		}

		// Check for known ransomware patterns
		if (operation.file_path.find(L".txt") != std::wstring::npos &&
			operation.type == FileOperationType::Create) {
			// Creating text files (possible ransom notes)
			suspicion_level += 15;
		}

		// Cap at 100
		//return std::min(suspicion_level, 100UL);
		return (std::min)(suspicion_level, 100UL);
	}

	/**
	 * @brief Check for suspicious patterns
	 */
	bool MessageProcessor::CheckSuspiciousPatterns(ULONG process_id)
	{
		std::lock_guard<std::mutex> lock(process_mutex_);

		auto it = process_map_.find(process_id);
		if (it == process_map_.end()) {
			return false;
		}

		const auto& process_info = it->second;

		// Check operation count thresholds
		if (process_info.operation_count > SUSPICIOUS_WRITE_THRESHOLD) {
			return true;
		}

		// Check time-based patterns
		auto duration = std::chrono::steady_clock::now() - process_info.first_seen;
		auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();

		if (seconds > 0 && process_info.operation_count / seconds > SUSPICIOUS_RATE_THRESHOLD) {
			return true;
		}

		return false;
	}

	/**
	 * @brief Generate alert
	 */
	void MessageProcessor::GenerateAlert(AlertSeverity severity,
		const std::wstring& description,
		const FileOperationInfo& operation)
	{
		AlertInfo alert;
		alert.severity = severity;
		alert.description = description;
		alert.process_id = operation.process_id;
		alert.file_path = operation.file_path;
		alert.timestamp = std::chrono::steady_clock::now();

		// Store alert
		{
			std::lock_guard<std::mutex> lock(alert_mutex_);
			recent_alerts_.push_back(alert);

			// Keep only recent alerts (last 100)
			if (recent_alerts_.size() > 100) {
				recent_alerts_.erase(recent_alerts_.begin());
			}
		}

		// Call alert callback
		AlertCallback callback;
		{
			std::lock_guard<std::mutex> lock(alert_mutex_);
			callback = alert_callback_;
		}

		if (callback) {
			callback(alert);
		}

		std::wcout << L"[MessageProcessor] ALERT: " << description << std::endl;
	}

	/**
	 * @brief Log operation to file
	 */
	void MessageProcessor::LogOperation(const FileOperationInfo& operation)
	{
		std::lock_guard<std::mutex> lock(log_mutex_);

		// Check if we need to open a new log file
		if (!OpenLogFile()) {
			return;
		}

		// Get process name
		std::wstring process_name = GetProcessName(operation.process_id);

		// Format log entry
		log_file_ << operation.GetFormattedTimestamp() << L"|"
			<< operation.process_id << L"|"
			<< process_name << L"|"
			<< operation.GetOperationTypeString() << L"|"
			<< operation.file_path << std::endl;
	}

	/**
	 * @brief Open log file for current date
	 */
	bool MessageProcessor::OpenLogFile()
	{
		// Get current date
		auto now = std::chrono::system_clock::now();
		auto time_t = std::chrono::system_clock::to_time_t(now);

		struct tm local_time;
		localtime_s(&local_time, &time_t);

		wchar_t date_buffer[32];
		wcsftime(date_buffer, sizeof(date_buffer) / sizeof(wchar_t),
			L"%Y-%m-%d", &local_time);

		std::wstring current_date(date_buffer);

		// Check if we need a new file
		if (current_date != current_log_date_ || !log_file_.is_open()) {
			if (log_file_.is_open()) {
				log_file_.close();
			}

			// Create log filename
			std::wstring log_filename = config_.log_directory + L"\\operations_" +
				current_date + L".log";

			// Open log file
			log_file_.open(log_filename, std::ios::app);
			if (!log_file_.is_open()) {
				std::wcerr << L"[MessageProcessor] Failed to open log file: "
					<< log_filename << std::endl;
				return false;
			}

			current_log_date_ = current_date;

			// Write header if file is empty
			log_file_.seekp(0, std::ios::end);
			if (log_file_.tellp() == 0) {
				log_file_ << L"Timestamp|ProcessID|ProcessName|Operation|FilePath" << std::endl;
			}
		}

		return true;
	}

	/**
	 * @brief Get process name from ID
	 */
	std::wstring MessageProcessor::GetProcessName(ULONG process_id)
	{
		wchar_t process_name[MAX_PATH] = L"<unknown>";

		HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE, process_id);
		if (process != nullptr) {
			HMODULE module;
			DWORD needed;

			if (EnumProcessModules(process, &module, sizeof(module), &needed)) {
				GetModuleBaseNameW(process, module, process_name, MAX_PATH);
			}

			CloseHandle(process);
		}

		return process_name;
	}

	/**
	 * @brief Check if file extension is suspicious
	 */
	bool MessageProcessor::IsSuspiciousExtension(const std::wstring& file_path)
	{
		// Extract extension
		size_t dot_pos = file_path.find_last_of(L'.');
		if (dot_pos == std::wstring::npos) {
			return false;
		}

		std::wstring extension = file_path.substr(dot_pos);

		// Convert to lowercase for comparison
		std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);

		// Check against known suspicious extensions
		return std::find(SUSPICIOUS_EXTENSIONS.begin(),
			SUSPICIOUS_EXTENSIONS.end(),
			extension) != SUSPICIOUS_EXTENSIONS.end();
	}

	/**
	 * @brief Calculate operation rate for process
	 */
	double MessageProcessor::CalculateOperationRate(ULONG process_id)
	{
		std::lock_guard<std::mutex> lock(process_mutex_);

		auto it = process_map_.find(process_id);
		if (it == process_map_.end()) {
			return 0.0;
		}

		const auto& process_info = it->second;

		auto duration = std::chrono::steady_clock::now() - process_info.first_seen;
		auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();

		if (seconds == 0) {
			return static_cast<double>(process_info.operation_count);
		}

		return static_cast<double>(process_info.operation_count) / seconds;
	}

	// FileOperationLogger implementation

	/**
	 * @brief Constructor
	 */
	FileOperationLogger::FileOperationLogger(const std::wstring& log_directory)
		: log_directory_(log_directory)
	{
		EnsureLogDirectory();
	}

	/**
	 * @brief Destructor
	 */
	FileOperationLogger::~FileOperationLogger()
	{
		std::lock_guard<std::mutex> lock(log_mutex_);

		if (operation_log_.is_open()) {
			operation_log_.close();
		}

		if (alert_log_.is_open()) {
			alert_log_.close();
		}
	}

	/**
	 * @brief Log operation
	 */
	void FileOperationLogger::LogOperation(const FileOperationInfo& operation,
		const std::wstring& process_name,
		ULONG suspicion_level)
	{
		std::lock_guard<std::mutex> lock(log_mutex_);

		if (!operation_log_.is_open()) {
			operation_log_.open(GetLogFilename(L"operations"), std::ios::app);
			if (!operation_log_.is_open()) {
				return;
			}
		}

		operation_log_ << operation.GetFormattedTimestamp() << L"|"
			<< operation.process_id << L"|"
			<< process_name << L"|"
			<< operation.GetOperationTypeString() << L"|"
			<< operation.file_path << L"|"
			<< suspicion_level << std::endl;
	}

	/**
	 * @brief Log alert
	 */
	void FileOperationLogger::LogAlert(const AlertInfo& alert)
	{
		std::lock_guard<std::mutex> lock(log_mutex_);

		if (!alert_log_.is_open()) {
			alert_log_.open(GetLogFilename(L"alerts"), std::ios::app);
			if (!alert_log_.is_open()) {
				return;
			}
		}

		auto now = std::chrono::system_clock::now();
		auto time_t = std::chrono::system_clock::to_time_t(now);

		struct tm local_time;
		localtime_s(&local_time, &time_t);

		wchar_t time_buffer[64];
		wcsftime(time_buffer, sizeof(time_buffer) / sizeof(wchar_t),
			L"%Y-%m-%d %H:%M:%S", &local_time);

		alert_log_ << time_buffer << L"|"
			<< static_cast<int>(alert.severity) << L"|"
			<< alert.description << L"|"
			<< alert.process_id << L"|"
			<< alert.file_path << std::endl;
	}

	/**
	 * @brief Ensure log directory exists
	 */
	bool FileOperationLogger::EnsureLogDirectory()
	{
		try {
			std::filesystem::create_directories(log_directory_);
			return true;
		}
		catch (const std::exception&) {
			return false;
		}
	}

	/**
	 * @brief Get current log filename
	 */
	std::wstring FileOperationLogger::GetLogFilename(const std::wstring& prefix)
	{
		auto now = std::chrono::system_clock::now();
		auto time_t = std::chrono::system_clock::to_time_t(now);

		struct tm local_time;
		localtime_s(&local_time, &time_t);

		wchar_t date_buffer[32];
		wcsftime(date_buffer, sizeof(date_buffer) / sizeof(wchar_t),
			L"%Y-%m-%d", &local_time);

		return log_directory_ + L"\\" + prefix + L"_" + date_buffer + L".log";
	}

} // namespace CryptoShield