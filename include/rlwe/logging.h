#pragma once

#include <string>
#include <memory>
#include <chrono>
#include <mutex>
#include <fstream>
#include <vector>
#include <unordered_map>

namespace rlwe {
namespace logging {

/**
 * @brief Log levels for enterprise logging
 */
enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    CRITICAL = 5,
    SECURITY = 6  // Special level for security events
};

/**
 * @brief Log categories for structured logging
 */
enum class LogCategory {
    GENERAL,
    CRYPTO_OPS,
    KEY_MANAGEMENT,
    PERFORMANCE,
    SECURITY,
    MEMORY,
    NETWORK,
    VALIDATION
};

/**
 * @brief Structured log entry
 */
struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    LogLevel level;
    LogCategory category;
    std::string component;
    std::string message;
    std::string thread_id;
    std::unordered_map<std::string, std::string> metadata;
    
    LogEntry(LogLevel lvl, LogCategory cat, const std::string& comp, const std::string& msg)
        : timestamp(std::chrono::system_clock::now())
        , level(lvl)
        , category(cat)
        , component(comp)
        , message(msg)
        , thread_id(get_thread_id()) {}
    
private:
    static std::string get_thread_id();
};

/**
 * @brief Abstract logger interface
 */
class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void log(const LogEntry& entry) = 0;
    virtual void flush() = 0;
    virtual void set_level(LogLevel level) = 0;
    virtual LogLevel get_level() const = 0;
};

/**
 * @brief Console logger implementation
 */
class ConsoleLogger : public ILogger {
public:
    ConsoleLogger(LogLevel level = LogLevel::INFO);
    
    void log(const LogEntry& entry) override;
    void flush() override;
    void set_level(LogLevel level) override { level_ = level; }
    LogLevel get_level() const override { return level_; }
    
private:
    LogLevel level_;
    std::mutex mutex_;
    
    std::string format_entry(const LogEntry& entry) const;
    std::string level_to_string(LogLevel level) const;
    std::string category_to_string(LogCategory category) const;
};

/**
 * @brief File logger implementation with rotation
 */
class FileLogger : public ILogger {
public:
    FileLogger(const std::string& filename, 
              LogLevel level = LogLevel::INFO,
              size_t max_file_size = 100 * 1024 * 1024,  // 100MB
              size_t max_files = 10);
    
    ~FileLogger();
    
    void log(const LogEntry& entry) override;
    void flush() override;
    void set_level(LogLevel level) override { level_ = level; }
    LogLevel get_level() const override { return level_; }
    
private:
    std::string filename_;
    LogLevel level_;
    size_t max_file_size_;
    size_t max_files_;
    size_t current_file_size_;
    std::unique_ptr<std::ofstream> file_;
    std::mutex mutex_;
    
    void rotate_file();
    std::string format_entry(const LogEntry& entry) const;
    std::string level_to_string(LogLevel level) const;
    std::string category_to_string(LogCategory category) const;
};

/**
 * @brief Security event logger with tamper detection
 */
class SecurityLogger : public ILogger {
public:
    SecurityLogger(const std::string& filename);
    ~SecurityLogger();
    
    void log(const LogEntry& entry) override;
    void flush() override;
    void set_level(LogLevel level) override { level_ = level; }
    LogLevel get_level() const override { return level_; }
    
    // Security-specific methods
    void log_security_event(const std::string& event_type, 
                           const std::string& description,
                           const std::unordered_map<std::string, std::string>& details = {});
    
    bool verify_log_integrity() const;
    
private:
    std::string filename_;
    LogLevel level_;
    std::unique_ptr<std::ofstream> file_;
    std::mutex mutex_;
    std::vector<uint32_t> checksums_;
    
    uint32_t compute_entry_checksum(const LogEntry& entry) const;
    std::string format_security_entry(const LogEntry& entry) const;
};

/**
 * @brief Composite logger that can write to multiple destinations
 */
class CompositeLogger : public ILogger {
public:
    void add_logger(std::unique_ptr<ILogger> logger);
    void remove_all_loggers();
    
    void log(const LogEntry& entry) override;
    void flush() override;
    void set_level(LogLevel level) override;
    LogLevel get_level() const override;
    
private:
    std::vector<std::unique_ptr<ILogger>> loggers_;
    std::mutex mutex_;
    LogLevel level_ = LogLevel::INFO;
};

/**
 * @brief Performance metrics collector
 */
class PerformanceLogger {
public:
    struct Metrics {
        std::chrono::nanoseconds duration;
        size_t memory_used;
        size_t cpu_cycles;
        std::string operation_name;
        std::chrono::system_clock::time_point timestamp;
    };
    
    PerformanceLogger(std::shared_ptr<ILogger> logger);
    
    // RAII performance measurement
    class ScopedTimer {
    public:
        ScopedTimer(PerformanceLogger& perf_logger, const std::string& operation_name);
        ~ScopedTimer();
        
        void add_metadata(const std::string& key, const std::string& value);
        
    private:
        PerformanceLogger& perf_logger_;
        std::string operation_name_;
        std::chrono::high_resolution_clock::time_point start_time_;
        std::unordered_map<std::string, std::string> metadata_;
    };
    
    void log_metrics(const Metrics& metrics, 
                    const std::unordered_map<std::string, std::string>& metadata = {});
    
    std::unique_ptr<ScopedTimer> start_timer(const std::string& operation_name);
    
    // Get aggregated statistics
    struct Statistics {
        double mean_duration_ns;
        double stddev_duration_ns;
        size_t total_operations;
        std::chrono::nanoseconds min_duration;
        std::chrono::nanoseconds max_duration;
    };
    
    Statistics get_statistics(const std::string& operation_name) const;
    void clear_statistics();
    
private:
    std::shared_ptr<ILogger> logger_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::vector<Metrics>> metrics_history_;
    
    void record_metrics(const Metrics& metrics);
};

/**
 * @brief Global logger manager - Singleton pattern
 */
class LoggerManager {
public:
    static LoggerManager& instance();
    
    void set_default_logger(std::unique_ptr<ILogger> logger);
    void set_security_logger(std::unique_ptr<SecurityLogger> logger);
    void set_performance_logger(std::unique_ptr<PerformanceLogger> logger);
    
    ILogger* get_default_logger();
    SecurityLogger* get_security_logger();
    PerformanceLogger* get_performance_logger();
    
    // Convenience methods
    void log(LogLevel level, LogCategory category, const std::string& component, 
            const std::string& message, 
            const std::unordered_map<std::string, std::string>& metadata = {});
    
    void log_security_event(const std::string& event_type, 
                           const std::string& description,
                           const std::unordered_map<std::string, std::string>& details = {});
    
    std::unique_ptr<PerformanceLogger::ScopedTimer> start_performance_timer(const std::string& operation_name);
    
private:
    LoggerManager() = default;
    
    std::unique_ptr<ILogger> default_logger_;
    std::unique_ptr<SecurityLogger> security_logger_;
    std::unique_ptr<PerformanceLogger> performance_logger_;
    std::mutex mutex_;
};

// Convenience macros
#define RLWE_LOG(level, category, component, message) \
    rlwe::logging::LoggerManager::instance().log(level, category, component, message)

#define RLWE_LOG_TRACE(component, message) \
    RLWE_LOG(rlwe::logging::LogLevel::TRACE, rlwe::logging::LogCategory::GENERAL, component, message)

#define RLWE_LOG_DEBUG(component, message) \
    RLWE_LOG(rlwe::logging::LogLevel::DEBUG, rlwe::logging::LogCategory::GENERAL, component, message)

#define RLWE_LOG_INFO(component, message) \
    RLWE_LOG(rlwe::logging::LogLevel::INFO, rlwe::logging::LogCategory::GENERAL, component, message)

#define RLWE_LOG_WARN(component, message) \
    RLWE_LOG(rlwe::logging::LogLevel::WARN, rlwe::logging::LogCategory::GENERAL, component, message)

#define RLWE_LOG_ERROR(component, message) \
    RLWE_LOG(rlwe::logging::LogLevel::ERROR, rlwe::logging::LogCategory::GENERAL, component, message)

#define RLWE_LOG_CRITICAL(component, message) \
    RLWE_LOG(rlwe::logging::LogLevel::CRITICAL, rlwe::logging::LogCategory::GENERAL, component, message)

#define RLWE_LOG_SECURITY(event_type, description) \
    rlwe::logging::LoggerManager::instance().log_security_event(event_type, description)

#define RLWE_PERF_TIMER(operation_name) \
    auto _perf_timer = rlwe::logging::LoggerManager::instance().start_performance_timer(operation_name)

} // namespace logging
} // namespace rlwe
