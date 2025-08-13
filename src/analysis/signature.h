#pragma once
#include <vector>
#include <string>
#include <span>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace malrev {

struct Signature {
    std::string name;
    std::string category;
    std::vector<std::optional<std::uint8_t>> pattern; // byte or wildcard
};

// Parse a simple JSON array of {name,category,hex} with bytes separated by spaces and "??" wildcard.
std::vector<Signature> load_signatures(const std::string& json_text);

// Match signatures in a buffer, returning names of hits.
std::vector<std::string> match_signatures(std::span<const std::byte> data, const std::vector<Signature>& sigs);

}
