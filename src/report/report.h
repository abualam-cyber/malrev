#pragma once
#include <string>
#include <vector>
#include <optional>
#include <span>
#include <cstddef>

namespace malrev {

struct JsonValue {
    // Very small JSON writer (objects/arrays/strings/numbers/bools/null).
    std::string s;
    static JsonValue str(const std::string& v);
    static JsonValue num(long long v);
    static JsonValue boolean(bool v);
    static JsonValue null();
    static JsonValue obj(const std::vector<std::pair<std::string, JsonValue>>& kv);
    static JsonValue arr(const std::vector<JsonValue>& items);
};

// Writes JSON to path. Returns true on success.
bool write_text_file(const std::string& path, const std::string& content);

// Embeds a JSON blob into HTML template (with placeholders) and writes to path.
bool write_html_report(const std::string& path, const std::string& template_html, const std::string& json_blob);

} // namespace malrev
