#include "util.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace fs = std::filesystem;

namespace malrev {

std::optional<FileData> read_file_limited(const fs::path& p, std::uint64_t max_bytes) {
    // Basic checks: exists, regular file
    std::error_code ec;
    if (!fs::exists(p, ec) || ec) return std::nullopt;
    if (!fs::is_regular_file(p, ec) || ec) return std::nullopt;

    auto sz = fs::file_size(p, ec);
    if (ec) return std::nullopt;
    if (sz > max_bytes) return std::nullopt;

    std::ifstream ifs(p, std::ios::binary);
    if (!ifs) return std::nullopt;
    std::vector<std::byte> buf(static_cast<size_t>(sz));
    if (sz > 0) {
        if (!ifs.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(sz))) {
            return std::nullopt;
        }
    }
    return FileData{p, std::move(buf)};
}

std::string to_hex(std::span<const std::byte> data) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0');
    bool first = true;
    for (auto b : data) {
        if (!first) oss << ' ';
        first = false;
        oss << std::setw(2) << (static_cast<unsigned>(std::to_integer<unsigned char>(b)));
    }
    return oss.str();
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b-1]))) --b;
    return s.substr(a, b - a);
}

std::string iso8601_now_utc() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto t = system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return std::string(buf);
}

} // namespace malrev
