#include "ptrace_monitor.h"
#include <vector>
#include <string>
#include <optional>

#if defined(MALREV_PLATFORM_LINUX)
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

namespace malrev {

static long get_sysno(user_regs_struct& regs){
#if defined(__x86_64__)
    return regs.orig_rax;
#elif defined(__aarch64__)
    return regs.regs[8];
#else
    return -1;
#endif
}

static long get_arg(user_regs_struct& regs, int idx){
#if defined(__x86_64__)
    switch (idx){ case 0: return regs.rdi; case 1: return regs.rsi; case 2: return regs.rdx;
                  case 3: return regs.r10; case 4: return regs.r8; case 5: return regs.r9; default: return 0; }
#elif defined(__aarch64__)
    return regs.regs[idx];
#else
    return 0;
#endif
}

static std::string safe_read_str(pid_t pid, unsigned long addr, size_t max=256){
    std::string out; out.reserve(64);
    unsigned long word = 0;
    for (size_t off=0; off<max; off+=sizeof(long)) {
        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, pid, addr+off, 0);
        if (errno) break;
        for (size_t i=0;i<sizeof(long);++i){
            char c = (word >> (i*8)) & 0xFF;
            if (c==0) return out;
            if (isprint((unsigned char)c)) out.push_back(c);
            else return out;
            if (out.size()>=max) return out;
        }
    }
    return out;
}

std::optional<std::vector<DynEvent>> trace_with_ptrace(const DynOptions& opt){
    std::vector<DynEvent> events;
    if (opt.exec_path.empty()) return std::nullopt;
    int pipefd[2]; if (pipe(pipefd) != 0) return std::nullopt;

    pid_t pid = fork();
    if (pid == -1) return std::nullopt;
    if (pid == 0) {
        // Child: set tracing and exec
        close(pipefd[0]);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) _exit(127);
        // Stop ourselves until parent is ready
        raise(SIGSTOP);
        // Build argv
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(opt.exec_path.c_str()));
        if (!opt.args.empty()) argv.push_back(const_cast<char*>(opt.args.c_str()));
        argv.push_back(nullptr);
        execv(opt.exec_path.c_str(), argv.data());
        _exit(127);
    }

    // Parent
    close(pipefd[1]);
    int status = 0;
    auto deadline = time(nullptr) + opt.timeout_sec;
    // Wait initial stop
    if (waitpid(pid, &status, 0) < 0) return std::nullopt;
    if (WIFSTOPPED(status)) {
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
    }

    bool in_syscall = false;
    long sysno = -1;
    while (true) {
        if (time(nullptr) > deadline) {
            kill(pid, SIGKILL);
            events.push_back({"exit","timeout", -1});
            break;
        }
        if (waitpid(pid, &status, 0) < 0) {
            break;
        }
        if (WIFEXITED(status)) {
            events.push_back({"exit","normal", WEXITSTATUS(status)});
            break;
        } else if (WIFSIGNALED(status)) {
            events.push_back({"exit","signal", WTERMSIG(status)});
            break;
        }
        user_regs_struct regs{};
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        sysno = get_sysno(regs);
        if (!in_syscall) {
            // Syscall entry
            in_syscall = true;
            // Recognize a few calls
            if (sysno == SYS_execve) {
                auto path = safe_read_str(pid, (unsigned long)get_arg(regs,0));
                events.push_back({"exec", path, 0});
            } else if (sysno == SYS_openat) {
                auto path = safe_read_str(pid, (unsigned long)get_arg(regs,1));
                events.push_back({"open", path, 0});
            } else if (sysno == SYS_connect) {
                // best effort: read sockaddr_in
                unsigned long addr = (unsigned long)get_arg(regs,1);
                unsigned long word = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
                if (!errno) {
                    unsigned short family = word & 0xFFFF;
                    if (family == AF_INET) {
                        unsigned long w2 = ptrace(PTRACE_PEEKDATA, pid, addr+4, 0);
                        unsigned short port_be = (w2 & 0xFFFF);
                        unsigned long ip = (w2 >> 16) & 0xFFFFFFFF;
                        char buf[64]{};
                        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
                            (unsigned)((ip)&0xFF), (unsigned)((ip>>8)&0xFF),
                            (unsigned)((ip>>16)&0xFF), (unsigned)((ip>>24)&0xFF),
                            ntohs(port_be));
                        events.push_back({"connect", buf, 0});
                    } else {
                        events.push_back({"connect", "non-IPv4", 0});
                    }
                }
            } else if (sysno == SYS_write) {
                long count = get_arg(regs,2);
                events.push_back({"write","fd="+std::to_string(get_arg(regs,0)), count});
            }
        } else {
            in_syscall = false; // syscall exit
        }
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
    }
    return events;
}

} // namespace malrev
#else
namespace malrev {
std::optional<std::vector<DynEvent>> trace_with_ptrace(const DynOptions&) { return std::nullopt; }
} // namespace malrev
#endif
