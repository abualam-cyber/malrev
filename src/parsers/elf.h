#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <span>
#include <optional>

namespace malrev {

struct ELFSection { std::string name; std::uint64_t addr{}, off{}, size{}; double entropy{}; };
struct ELFInfo {
    bool valid = false;
    bool is64 = false;
    std::vector<ELFSection> sections;
};

std::optional<ELFInfo> parse_elf(std::span<const std::byte> data);

}
