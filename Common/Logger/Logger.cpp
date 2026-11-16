#include "Logger/Logger.h"
#include "ErrorHandling/CryptoException.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

namespace crypto
{
    Logger& Logger::instance()
    {
        static Logger logger;
        return logger;
    }

    void Logger::set_min_level(const LogLevel level)
    {
        std::scoped_lock lock(mutex_);
        minimum_level_ = level;
    }

    void Logger::set_console_enabled(const bool enabled)
    {
        std::scoped_lock lock(mutex_);
        console_enabled_ = enabled;
    }

    void Logger::set_file(const std::filesystem::path& file_path)
    {
        std::scoped_lock lock(mutex_);
        if (file_path.has_parent_path()) std::filesystem::create_directories(file_path.parent_path());
        if (file_.is_open()) file_.close();
        file_.open(file_path, std::ios::out | std::ios::app);
        if (!file_) raise_error(ErrorCode::IoError, "Unable to open the log file.");
    }

    void Logger::close_file()
    {
        std::scoped_lock lock(mutex_);
        if (file_.is_open()) { file_.flush(); file_.close(); }
    }

    void Logger::log(const LogLevel level, const std::string_view message)
    {
        std::scoped_lock lock(mutex_);
        if (minimum_level_ == LogLevel::Off || static_cast<int>(level) < static_cast<int>(minimum_level_)) return;
        std::ostringstream stream;
        stream << '[' << timestamp() << "] [" << level_name(level) << "] [thread "
               << std::this_thread::get_id() << "] " << message;
        const std::string line = stream.str();
        if (console_enabled_) std::clog << line << '\n';
        if (file_.is_open()) { file_ << line << '\n'; file_.flush(); }
    }

    void Logger::trace(const std::string_view text) { log(LogLevel::Trace, text); }
    void Logger::debug(const std::string_view text) { log(LogLevel::Debug, text); }
    void Logger::info(const std::string_view text) { log(LogLevel::Info, text); }
    void Logger::warning(const std::string_view text) { log(LogLevel::Warning, text); }
    void Logger::error(const std::string_view text) { log(LogLevel::Error, text); }
    void Logger::critical(const std::string_view text) { log(LogLevel::Critical, text); }

    std::string_view Logger::level_name(const LogLevel level) noexcept
    {
        switch (level)
        {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warning: return "WARNING";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Critical: return "CRITICAL";
        case LogLevel::Off: return "OFF";
        }
        return "UNKNOWN";
    }

    std::string Logger::timestamp()
    {
        using Clock = std::chrono::system_clock;
        const auto now = Clock::now();
        const auto time = Clock::to_time_t(now);
        const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
        std::tm local{};
#if defined(_WIN32)
        localtime_s(&local, &time);
#else
        localtime_r(&time, &local);
#endif
        std::ostringstream stream;
        stream << std::put_time(&local, "%Y-%m-%d %H:%M:%S")
               << '.' << std::setw(3) << std::setfill('0') << millis;
        return stream.str();
    }
}
