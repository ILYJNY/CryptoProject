#pragma once

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>

namespace crypto
{
    enum class LogLevel { Trace = 0, Debug, Info, Warning, Error, Critical, Off };

    class Logger final
    {
    public:
        static Logger& instance();
        Logger(const Logger&) = delete;
        Logger& operator=(const Logger&) = delete;

        void set_min_level(LogLevel level);
        void set_console_enabled(bool enabled);
        void set_file(const std::filesystem::path& file_path);
        void close_file();
        void log(LogLevel level, std::string_view message);
        void trace(std::string_view message);
        void debug(std::string_view message);
        void info(std::string_view message);
        void warning(std::string_view message);
        void error(std::string_view message);
        void critical(std::string_view message);

    private:
        Logger() = default;
        [[nodiscard]] static std::string_view level_name(LogLevel level) noexcept;
        [[nodiscard]] static std::string timestamp();
        std::mutex mutex_;
        LogLevel minimum_level_ = LogLevel::Info;
        bool console_enabled_ = true;
        std::ofstream file_;
    };
}
