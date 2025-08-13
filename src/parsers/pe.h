#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <span>
#include <optional>

namespace malrev {

struct PESection { std::string name; std::uint32_t vsize{}, vaddr{}, rsize{}, rptr{}; double entropy{}; };
struct PEInfo {
    bool valid = false;
    std::uint32_t timestamp = 0;
    std::vector<PESection> sections;
    std::vector<std::string> imports; // simplified
};

std::optional<PEInfo> parse_pe(std::span<const std::byte> data);

}
