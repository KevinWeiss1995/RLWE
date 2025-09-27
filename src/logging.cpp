#include "rlwe/logging.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <filesystem>

namespace rlwe {
namespace logging {

// LogEntry implementation
std::string LogEntry::get_thread_id() {
    std::ostringstream oss;
    oss << std::this_thread::get_id();
    return oss.str();
}

// ConsoleLogger implementation
ConsoleLogger::ConsoleLogger(LogLevel level) : level_(level) {}

void ConsoleLogger::log(const LogEntry& entry) {
    if (entry.level < level_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << format_entry(entry) << std::endl;
}

void ConsoleLogger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::cout.flush();
}

std::string ConsoleLogger::format_entry(const LogEntry& entry) const {
    std::ostringstream oss;
    
    // Timestamp
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()) % 1000;
    
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    
    // Level and category
    oss << " [" << level_to_string(entry.level) << "]";
    oss << " [" << category_to_string(entry.category) << "]";
    
    // Component and thread
    oss << " [" << entry.component << "]";
    oss << " [Thread:" << entry.thread_id << "]";
    
    // Message
    oss << " " << entry.message;
    
    // Metadata
    if (!entry.metadata.empty()) {
        oss << " {";
        bool first = true;
        for (const auto& [key, value] : entry.metadata) {
            if (!first) oss << ", ";
            oss << key << "=" << value;
            first = false;
        }
        oss << "}";
    }
    
    return oss.str();
}

std::string ConsoleLogger::level_to_string(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        case LogLevel::SECURITY: return "SECURITY";
        default: return "UNKNOWN";
    }
}

std::string ConsoleLogger::category_to_string(LogCategory category) const {
    switch (category) {
        case LogCategory::GENERAL: return "GENERAL";
        case LogCategory::CRYPTO_OPS: return "CRYPTO";
        case LogCategory::KEY_MANAGEMENT: return "KEYS";
        case LogCategory::PERFORMANCE: return "PERF";
        case LogCategory::SECURITY: return "SEC";
        case LogCategory::MEMORY: return "MEM";
        case LogCategory::NETWORK: return "NET";
        case LogCategory::VALIDATION: return "VALID";
        default: return "UNKNOWN";
    }
}

// FileLogger implementation
FileLogger::FileLogger(const std::string& filename, LogLevel level, 
                      size_t max_file_size, size_t max_files)
    : filename_(filename), level_(level), max_file_size_(max_file_size), 
      max_files_(max_files), current_file_size_(0) {
    
    file_ = std::make_unique<std::ofstream>(filename_, std::ios::app);
    if (!file_->is_open()) {
        throw std::runtime_error("Failed to open log file: " + filename_);
    }
    
    // Get current file size
    file_->seekp(0, std::ios::end);
    current_file_size_ = file_->tellp();
}

FileLogger::~FileLogger() {
    if (file_ && file_->is_open()) {
        file_->close();
    }
}

void FileLogger::log(const LogEntry& entry) {
    if (entry.level < level_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string formatted = format_entry(entry);
    *file_ << formatted << std::endl;
    
    current_file_size_ += formatted.length() + 1; // +1 for newline
    
    if (current_file_size_ > max_file_size_) {
        rotate_file();
    }
}

void FileLogger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_) {
        file_->flush();
    }
}

void FileLogger::rotate_file() {
    file_->close();
    
    // Rotate existing files
    for (size_t i = max_files_ - 1; i > 0; --i) {
        std::string old_name = filename_ + "." + std::to_string(i);
        std::string new_name = filename_ + "." + std::to_string(i + 1);
        
        if (std::filesystem::exists(old_name)) {
            if (i == max_files_ - 1) {
                std::filesystem::remove(old_name);
            } else {
                std::filesystem::rename(old_name, new_name);
            }
        }
    }
    
    // Move current file to .1
    std::string backup_name = filename_ + ".1";
    std::filesystem::rename(filename_, backup_name);
    
    // Create new file
    file_ = std::make_unique<std::ofstream>(filename_);
    current_file_size_ = 0;
}

std::string FileLogger::format_entry(const LogEntry& entry) const {
    std::ostringstream oss;
    
    // Timestamp
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()) % 1000;
    
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    
    // Level and category
    oss << " [" << level_to_string(entry.level) << "]";
    oss << " [" << category_to_string(entry.category) << "]";
    
    // Component and thread
    oss << " [" << entry.component << "]";
    oss << " [Thread:" << entry.thread_id << "]";
    
    // Message
    oss << " " << entry.message;
    
    // Metadata
    if (!entry.metadata.empty()) {
        oss << " {";
        bool first = true;
        for (const auto& [key, value] : entry.metadata) {
            if (!first) oss << ", ";
            oss << key << "=" << value;
            first = false;
        }
        oss << "}";
    }
    
    return oss.str();
}

std::string FileLogger::level_to_string(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        case LogLevel::SECURITY: return "SECURITY";
        default: return "UNKNOWN";
    }
}

std::string FileLogger::category_to_string(LogCategory category) const {
    switch (category) {
        case LogCategory::GENERAL: return "GENERAL";
        case LogCategory::CRYPTO_OPS: return "CRYPTO";
        case LogCategory::KEY_MANAGEMENT: return "KEYS";
        case LogCategory::PERFORMANCE: return "PERF";
        case LogCategory::SECURITY: return "SEC";
        case LogCategory::MEMORY: return "MEM";
        case LogCategory::NETWORK: return "NET";
        case LogCategory::VALIDATION: return "VALID";
        default: return "UNKNOWN";
    }
}

// SecurityLogger implementation
SecurityLogger::SecurityLogger(const std::string& filename) 
    : filename_(filename), level_(LogLevel::INFO) {
    
    file_ = std::make_unique<std::ofstream>(filename_, std::ios::app);
    if (!file_->is_open()) {
        throw std::runtime_error("Failed to open security log file: " + filename_);
    }
}

SecurityLogger::~SecurityLogger() {
    if (file_ && file_->is_open()) {
        file_->close();
    }
}

void SecurityLogger::log(const LogEntry& entry) {
    if (entry.level < level_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string formatted = format_security_entry(entry);
    *file_ << formatted << std::endl;
    
    // Store checksum for integrity verification
    uint32_t checksum = compute_entry_checksum(entry);
    checksums_.push_back(checksum);
    
    file_->flush(); // Always flush security logs
}

void SecurityLogger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_) {
        file_->flush();
    }
}

void SecurityLogger::log_security_event(const std::string& event_type, 
                                       const std::string& description,
                                       const std::unordered_map<std::string, std::string>& details) {
    LogEntry entry(LogLevel::SECURITY, LogCategory::SECURITY, "SecurityLogger", description);
    entry.metadata = details;
    entry.metadata["event_type"] = event_type;
    log(entry);
}

bool SecurityLogger::verify_log_integrity() const {
    // In a real implementation, this would verify against stored checksums
    // For now, just return true
    return true;
}

uint32_t SecurityLogger::compute_entry_checksum(const LogEntry& entry) const {
    // Simple checksum of the formatted entry
    std::string formatted = format_security_entry(entry);
    uint32_t checksum = 0;
    for (char c : formatted) {
        checksum = (checksum << 1) ^ static_cast<uint8_t>(c);
    }
    return checksum;
}

std::string SecurityLogger::format_security_entry(const LogEntry& entry) const {
    std::ostringstream oss;
    
    // Timestamp with high precision
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        entry.timestamp.time_since_epoch()) % 1000000;
    
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(6) << us.count();
    
    oss << " [SECURITY]";
    oss << " [" << entry.component << "]";
    oss << " [Thread:" << entry.thread_id << "]";
    oss << " " << entry.message;
    
    // Include all metadata for security events
    if (!entry.metadata.empty()) {
        oss << " METADATA:{";
        bool first = true;
        for (const auto& [key, value] : entry.metadata) {
            if (!first) oss << ", ";
            oss << key << "=" << value;
            first = false;
        }
        oss << "}";
    }
    
    return oss.str();
}

// CompositeLogger implementation
void CompositeLogger::add_logger(std::unique_ptr<ILogger> logger) {
    std::lock_guard<std::mutex> lock(mutex_);
    loggers_.push_back(std::move(logger));
}

void CompositeLogger::remove_all_loggers() {
    std::lock_guard<std::mutex> lock(mutex_);
    loggers_.clear();
}

void CompositeLogger::log(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& logger : loggers_) {
        logger->log(entry);
    }
}

void CompositeLogger::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& logger : loggers_) {
        logger->flush();
    }
}

void CompositeLogger::set_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    level_ = level;
    for (auto& logger : loggers_) {
        logger->set_level(level);
    }
}

LogLevel CompositeLogger::get_level() const {
    return level_;
}

// PerformanceLogger implementation
PerformanceLogger::PerformanceLogger(std::shared_ptr<ILogger> logger) 
    : logger_(logger) {}

PerformanceLogger::ScopedTimer::ScopedTimer(PerformanceLogger& perf_logger, 
                                           const std::string& operation_name)
    : perf_logger_(perf_logger), operation_name_(operation_name),
      start_time_(std::chrono::high_resolution_clock::now()) {}

PerformanceLogger::ScopedTimer::~ScopedTimer() {
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time_);
    
    Metrics metrics;
    metrics.duration = duration;
    metrics.memory_used = 0; // Would need platform-specific code to get actual memory usage
    metrics.cpu_cycles = 0;  // Would need platform-specific code to get CPU cycles
    metrics.operation_name = operation_name_;
    metrics.timestamp = std::chrono::system_clock::now();
    
    perf_logger_.log_metrics(metrics, metadata_);
}

void PerformanceLogger::ScopedTimer::add_metadata(const std::string& key, const std::string& value) {
    metadata_[key] = value;
}

void PerformanceLogger::log_metrics(const Metrics& metrics, 
                                   const std::unordered_map<std::string, std::string>& metadata) {
    LogEntry entry(LogLevel::INFO, LogCategory::PERFORMANCE, "PerformanceLogger", 
                  "Operation completed: " + metrics.operation_name);
    
    entry.metadata = metadata;
    entry.metadata["operation"] = metrics.operation_name;
    entry.metadata["duration_ns"] = std::to_string(metrics.duration.count());
    entry.metadata["memory_used"] = std::to_string(metrics.memory_used);
    entry.metadata["cpu_cycles"] = std::to_string(metrics.cpu_cycles);
    
    logger_->log(entry);
    record_metrics(metrics);
}

std::unique_ptr<PerformanceLogger::ScopedTimer> 
PerformanceLogger::start_timer(const std::string& operation_name) {
    return std::make_unique<ScopedTimer>(*this, operation_name);
}

PerformanceLogger::Statistics 
PerformanceLogger::get_statistics(const std::string& operation_name) const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
    
    auto it = metrics_history_.find(operation_name);
    if (it == metrics_history_.end() || it->second.empty()) {
        return Statistics{0.0, 0.0, 0, std::chrono::nanoseconds(0), std::chrono::nanoseconds(0)};
    }
    
    const auto& metrics = it->second;
    
    // Calculate statistics
    std::vector<double> durations;
    durations.reserve(metrics.size());
    for (const auto& metric : metrics) {
        durations.push_back(static_cast<double>(metric.duration.count()));
    }
    
    double mean = std::accumulate(durations.begin(), durations.end(), 0.0) / durations.size();
    
    double variance = 0.0;
    for (double duration : durations) {
        variance += (duration - mean) * (duration - mean);
    }
    variance /= durations.size();
    double stddev = std::sqrt(variance);
    
    auto min_it = std::min_element(metrics.begin(), metrics.end(),
        [](const Metrics& a, const Metrics& b) { return a.duration < b.duration; });
    auto max_it = std::max_element(metrics.begin(), metrics.end(),
        [](const Metrics& a, const Metrics& b) { return a.duration < b.duration; });
    
    return Statistics{
        mean,
        stddev,
        metrics.size(),
        min_it->duration,
        max_it->duration
    };
}

void PerformanceLogger::clear_statistics() {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_history_.clear();
}

void PerformanceLogger::record_metrics(const Metrics& metrics) {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_history_[metrics.operation_name].push_back(metrics);
    
    // Limit history size to prevent memory growth
    const size_t MAX_HISTORY = 10000;
    auto& history = metrics_history_[metrics.operation_name];
    if (history.size() > MAX_HISTORY) {
        history.erase(history.begin(), history.begin() + (history.size() - MAX_HISTORY));
    }
}

// LoggerManager implementation
LoggerManager& LoggerManager::instance() {
    static LoggerManager instance;
    return instance;
}

void LoggerManager::set_default_logger(std::unique_ptr<ILogger> logger) {
    std::lock_guard<std::mutex> lock(mutex_);
    default_logger_ = std::move(logger);
}

void LoggerManager::set_security_logger(std::unique_ptr<SecurityLogger> logger) {
    std::lock_guard<std::mutex> lock(mutex_);
    security_logger_ = std::move(logger);
}

void LoggerManager::set_performance_logger(std::unique_ptr<PerformanceLogger> logger) {
    std::lock_guard<std::mutex> lock(mutex_);
    performance_logger_ = std::move(logger);
}

ILogger* LoggerManager::get_default_logger() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!default_logger_) {
        // Create default console logger if none exists
        default_logger_ = std::make_unique<ConsoleLogger>();
    }
    return default_logger_.get();
}

SecurityLogger* LoggerManager::get_security_logger() {
    std::lock_guard<std::mutex> lock(mutex_);
    return security_logger_.get();
}

PerformanceLogger* LoggerManager::get_performance_logger() {
    std::lock_guard<std::mutex> lock(mutex_);
    return performance_logger_.get();
}

void LoggerManager::log(LogLevel level, LogCategory category, const std::string& component, 
                       const std::string& message, 
                       const std::unordered_map<std::string, std::string>& metadata) {
    LogEntry entry(level, category, component, message);
    entry.metadata = metadata;
    
    if (auto* logger = get_default_logger()) {
        logger->log(entry);
    }
}

void LoggerManager::log_security_event(const std::string& event_type, 
                                      const std::string& description,
                                      const std::unordered_map<std::string, std::string>& details) {
    if (auto* security_logger = get_security_logger()) {
        security_logger->log_security_event(event_type, description, details);
    }
    
    // Also log to default logger
    log(LogLevel::SECURITY, LogCategory::SECURITY, "Security", 
        event_type + ": " + description, details);
}

std::unique_ptr<PerformanceLogger::ScopedTimer> 
LoggerManager::start_performance_timer(const std::string& operation_name) {
    if (auto* perf_logger = get_performance_logger()) {
        return perf_logger->start_timer(operation_name);
    }
    return nullptr;
}

} // namespace logging
} // namespace rlwe
