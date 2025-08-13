#include "report.h"
#include <fstream>
#include <sstream>

namespace malrev {

static std::string esc(const std::string& in){
    std::string o; o.reserve(in.size()+8);
    for (char c: in){
        switch (c){
            case '\"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) { o += "\\u00"; const char* hex="0123456789abcdef"; o+=hex[(c>>4)&0xF]; o+=hex[c&0xF];}
                else o += c;
        }
    }
    return o;
}

JsonValue JsonValue::str(const std::string& v){ JsonValue j; j.s = "\"" + esc(v) + "\""; return j; }
JsonValue JsonValue::num(long long v){ JsonValue j; j.s = std::to_string(v); return j; }
JsonValue JsonValue::boolean(bool v){ JsonValue j; j.s = v ? "true" : "false"; return j; }
JsonValue JsonValue::null(){ JsonValue j; j.s = "null"; return j; }

JsonValue JsonValue::obj(const std::vector<std::pair<std::string, JsonValue>>& kv){
    std::ostringstream oss; oss << "{";
    bool first=true;
    for (auto &p : kv){
        if (!first) oss << ",";
        first=false;
        oss << "\"" << esc(p.first) << "\":" << p.second.s;
    }
    oss << "}";
    JsonValue j; j.s = oss.str(); return j;
}

JsonValue JsonValue::arr(const std::vector<JsonValue>& items){
    std::ostringstream oss; oss << "[";
    bool first=true;
    for (auto &it : items){
        if (!first) oss << ","; first=false;
        oss << it.s;
    }
    oss << "]";
    JsonValue j; j.s = oss.str(); return j;
}

bool write_text_file(const std::string& path, const std::string& content){
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    return ofs.good();
}

bool write_html_report(const std::string& path, const std::string& template_html, const std::string& json_blob){
    std::string out = template_html;
    // Two placeholders: {{generated}} and {{json_blob}}
    auto pos = out.find("{{generated}}");
    if (pos != std::string::npos) out.replace(pos, std::string("{{generated}}").size(), "now");
    pos = out.find("{{json_blob}}");
    if (pos != std::string::npos) out.replace(pos, std::string("{{json_blob}}").size(), json_blob);
    return write_text_file(path, out);
}

} // namespace malrev
