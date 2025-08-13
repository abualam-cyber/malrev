#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace malrev {

struct DynEvent {
    std::string type;               // "exec", "open", "connect", "write", "exit"
    std::string detail;             // path/addr or summary
    std::int64_t value = 0;         // e.g., bytes written or exit code
};

struct DynOptions {
    std::string exec_path;
    std::string args;
    int timeout_sec = 60;
};

// Linux-only. Traces a child process syscalls and returns events until exit or timeout.
// This is deliberately minimal; does not follow forks, and captures only broad events.
std::optional<std::vector<DynEvent>> trace_with_ptrace(const DynOptions& opt);

}
