#include "signature.h"
#include <sstream>
#include <cctype>
#include <optional>

namespace malrev {

static std::vector<std::string> split_ws(const std::string& s){
    std::istringstream iss(s);
    std::vector<std::string> out; std::string t;
    while (iss >> t) out.push_back(t);
    return out;
}

// Tiny hand-rolled "parser": we just look for "name":, "category":, "hex": fields in objects.
// This avoids third-party JSON libs. Assumes the file is trusted (local config).
std::vector<Signature> load_signatures(const std::string& json_text) {
    std::vector<Signature> out;
    size_t i = 0;
    auto skip_ws=[&]{ while (i<json_text.size() && std::isspace((unsigned char)json_text[i])) ++i; };
    skip_ws();
    if (i>=json_text.size() || json_text[i] != '[') return out;
    ++i; skip_ws();
    while (i<json_text.size() && json_text[i] != ']') {
        if (json_text[i] != '{') break; ++i; skip_ws();
        std::string name, category, hex;
        while (i<json_text.size() && json_text[i] != '}') {
            skip_ws(); if (json_text[i] != '"') break; ++i;
            size_t k1 = json_text.find('"', i); if (k1==std::string::npos) return out;
            std::string key = json_text.substr(i, k1 - i); i = k1+1; skip_ws();
            if (i>=json_text.size() || json_text[i] != ':') return out; ++i; skip_ws();
            if (i>=json_text.size() || json_text[i] != '"') return out; ++i;
            size_t v1 = json_text.find('"', i); if (v1==std::string::npos) return out;
            std::string val = json_text.substr(i, v1 - i); i = v1+1; skip_ws();
            if (key == "name") name = val;
            else if (key == "category") category = val;
            else if (key == "hex") hex = val;
            if (i<json_text.size() && json_text[i] == ','){ ++i; skip_ws(); }
        }
        if (i<json_text.size() && json_text[i]=='}') { ++i; skip_ws(); }
        if (i<json_text.size() && json_text[i]==','){ ++i; skip_ws(); }
        if (!name.empty() && !hex.empty()) {
            Signature s; s.name = name; s.category = category;
            for (auto &tok : split_ws(hex)) {
                if (tok=="??") s.pattern.push_back(std::nullopt);
                else {
                    if (tok.size()!=2) continue;
                    unsigned x = 0;
                    std::istringstream iss(tok);
                    iss >> std::hex >> x;
                    s.pattern.push_back(static_cast<std::uint8_t>(x));
                }
            }
            if (!s.pattern.empty()) out.push_back(std::move(s));
        }
    }
    return out;
}

std::vector<std::string> match_signatures(std::span<const std::byte> data, const std::vector<Signature>& sigs) {
    std::vector<std::string> hits;
    for (const auto& s : sigs) {
        const auto& p = s.pattern;
        if (p.empty() || data.size() < p.size()) continue;
        for (size_t i=0;i + p.size() <= data.size(); ++i) {
            bool ok = true;
            for (size_t j=0;j<p.size();++j) {
                if (p[j].has_value()) {
                    if (static_cast<std::uint8_t>(std::to_integer<unsigned char>(data[i+j])) != p[j].value()) { ok=false; break; }
                }
            }
            if (ok) { hits.push_back(s.name); break; }
        }
    }
    return hits;
}

} // namespace malrev
