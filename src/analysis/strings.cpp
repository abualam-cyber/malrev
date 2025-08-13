#include "strings.h"
#include <cctype>

namespace malrev {

static bool is_print(char c){ return std::isprint(static_cast<unsigned char>(c)); }

std::vector<std::string> extract_strings(std::span<const std::byte> data, const StringsOptions& opt) {
    std::vector<std::string> out;
    if (opt.ascii) {
        std::string cur;
        for (auto b : data) {
            char c = static_cast<char>(std::to_integer<unsigned char>(b));
            if (is_print(c)) {
                if (cur.size() < opt.max_ascii) cur.push_back(c);
            } else {
                if (cur.size() >= opt.min_ascii) out.push_back(cur);
                cur.clear();
            }
        }
        if (cur.size() >= opt.min_ascii) out.push_back(cur);
    }
    if (opt.utf16le) {
        std::string cur;
        for (size_t i=0;i+1<data.size();i+=2) {
            char c = static_cast<char>(std::to_integer<unsigned char>(data[i]));
            unsigned char hi = static_cast<unsigned char>(std::to_integer<unsigned char>(data[i+1]));
            if (hi==0 && is_print(c)) {
                if (cur.size() < opt.max_ascii) cur.push_back(c);
            } else {
                if (cur.size() >= opt.min_ascii) out.push_back(cur);
                cur.clear();
            }
        }
        if (cur.size() >= opt.min_ascii) out.push_back(cur);
    }
    return out;
}

} // namespace malrev
