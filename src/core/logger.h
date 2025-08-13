#pragma once
#include <string>
#include <mutex>
#include <iostream>

// Simple thread-safe logger with severity levels.
// Avoids dynamic allocation where possible and flushes immediately.
namespace malrev {
enum class LogLevel { Error=0, Warn=1, Info=2, Debug=3 };

class Logger {
public:
    explicit Logger(LogLevel level = LogLevel::Info) noexcept : level_(level) {}
    void set_level(LogLevel lvl) noexcept { level_ = lvl; }

    void error(const std::string& msg) noexcept { log("ERROR", msg, LogLevel::Error); }
    void warn(const std::string& msg) noexcept { log("WARN", msg, LogLevel::Warn); }
    void info(const std::string& msg) noexcept { log("INFO", msg, LogLevel::Info); }
    void debug(const std::string& msg) noexcept { log("DEBUG", msg, LogLevel::Debug); }

private:
    void log(const char* prefix, const std::string& msg, LogLevel msgLvl) noexcept {
        if (static_cast<int>(msgLvl) > static_cast<int>(level_)) return;
        std::scoped_lock lock(mu_);
        std::cerr << "[" << prefix << "] " << msg << std::endl;
    }
    LogLevel level_;
    std::mutex mu_;
};
} // namespace malrev
