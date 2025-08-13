#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <optional>
#include <filesystem>
#include <span>

namespace malrev {

struct FileData {
    std::filesystem::path path;
    std::vector<std::byte> bytes;
};

// Reads a file safely with a maximum size limit (in bytes). Returns std::nullopt on error.
std::optional<FileData> read_file_limited(const std::filesystem::path& p, std::uint64_t max_bytes);

// Convert a span of bytes to a hex string (uppercase, space-separated) for debugging.
std::string to_hex(std::span<const std::byte> data);

// Safe string trimming (both ends). Returns a new string.
std::string trim(const std::string& s);

// Simple wall-clock timestamp ISO8601 (UTC) string.
std::string iso8601_now_utc();

} // namespace malrev
