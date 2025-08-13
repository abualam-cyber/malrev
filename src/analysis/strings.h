#pragma once
#include <vector>
#include <string>
#include <span>
#include <cstddef>

namespace malrev {

struct StringsOptions {
    std::size_t min_ascii = 6;
    std::size_t max_ascii = 200;
    bool ascii = true;
    bool utf16le = true;
};

std::vector<std::string> extract_strings(std::span<const std::byte> data, const StringsOptions& opt);

}
