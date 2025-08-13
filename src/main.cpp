#include <iostream>
#include <filesystem>
#include <fstream>
#include <optional>
#include <vector>
#include <string>
#include <cstdint>
#include "core/logger.h"
#include "core/util.h"
#include "core/sha256.h"
#include "analysis/entropy.h"
#include "analysis/strings.h"
#include "analysis/signature.h"
#include "parsers/pe.h"
#include "parsers/elf.h"
#include "dynamic/ptrace_monitor.h"
#include "report/report.h"

// This file orchestrates the CLI: parse args, run static analysis, optional dynamic tracing,
// then emit JSON and HTML reports. Each block includes commentary about safety and checks.

namespace fs = std::filesystem;
using namespace malrev;

struct Options {
    fs::path input;
    fs::path out_json;
    fs::path out_html;
    fs::path sig_db = "configs/signatures.json";
    bool dynamic = false;
    fs::path exec_path;
    std::string exec_args;
    bool verbose = false;
    std::size_t min_str = 6, max_str = 200;
    bool ascii = true, utf16 = true;
    std::uint64_t limit_bytes = 128ull * 1024ull * 1024ull;
    int timeout_sec = 60;
};

static void print_usage(){
    std::cerr << "malrev - C++ Malware Reverse Engineering CLI\n"
              << "Usage:\n"
              << "  malrev --input <path> [--dynamic [--exec <path> [--args \"...\"]]]\n"
              << "         [--out report.json] [--html report.html]\n"
              << "         [--sig configs/signatures.json]\n"
              << "         [--max-string N] [--min-string N] [--no-utf16] [--no-ascii]\n"
              << "         [--limit-mb N] [--timeout N] [--verbose]\n";
}

static std::optional<Options> parse_args(int argc, char** argv){
    Options o{};
    for (int i=1;i<argc;++i){
        std::string a = argv[i];
        auto need = [&](int n){ return (i+n) < argc; };
        if (a=="--input" && need(1)) o.input = argv[++i];
        else if (a=="--out" && need(1)) o.out_json = argv[++i];
        else if (a=="--html" && need(1)) o.out_html = argv[++i];
        else if (a=="--sig" && need(1)) o.sig_db = argv[++i];
        else if (a=="--dynamic") o.dynamic = true;
        else if (a=="--exec" && need(1)) o.exec_path = argv[++i];
        else if (a=="--args" && need(1)) o.exec_args = argv[++i];
        else if (a=="--max-string" && need(1)) o.max_str = std::stoul(argv[++i]);
        else if (a=="--min-string" && need(1)) o.min_str = std::stoul(argv[++i]);
        else if (a=="--no-utf16") o.utf16 = false;
        else if (a=="--no-ascii") o.ascii = false;
        else if (a=="--limit-mb" && need(1)) o.limit_bytes = std::stoull(argv[++i]) * 1024ull * 1024ull;
        else if (a=="--timeout" && need(1)) o.timeout_sec = std::stoi(argv[++i]);
        else if (a=="--verbose") o.verbose = true;
        else { std::cerr << "Unknown or incomplete option: " << a << "\n"; return std::nullopt; }
    }
    if (o.input.empty()) { print_usage(); return std::nullopt; }
    return o;
}

// Load signatures file if present.
static std::vector<Signature> try_load_sigs(const fs::path& p, Logger& log){
    std::vector<Signature> sigs;
    std::error_code ec;
    if (!p.empty() && fs::exists(p, ec) && fs::is_regular_file(p, ec)) {
        std::ifstream ifs(p, std::ios::binary);
        if (ifs) {
            std::string s((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            sigs = load_signatures(s);
            if (sigs.empty()) log.warn("No signatures parsed from: " + p.string());
        }
    } else {
        log.warn("Signature DB not found: " + p.string());
    }
    return sigs;
}

int main(int argc, char** argv){
    auto opt = parse_args(argc, argv);
    if (!opt) return 2;
    Logger log(opt->verbose ? LogLevel::Debug : LogLevel::Info);

    // SECURITY: refuse huge files to avoid memory exhaustion
    auto fd = read_file_limited(opt->input, opt->limit_bytes);
    if (!fd) { log.error("Failed to read file or exceeds limit."); return 3; }

    // Hashing
    Sha256 sha; sha.update(std::span<const std::byte>(fd->bytes.data(), fd->bytes.size())); sha.finalize();
    auto sha_hex = sha.hex_digest();

    // File type detection by magic
    std::string ftype = "unknown";
    if (fd->bytes.size() >= 2 && static_cast<unsigned>(std::to_integer<unsigned char>(fd->bytes[0]))=='M' &&
        static_cast<unsigned>(std::to_integer<unsigned char>(fd->bytes[1]))=='Z') ftype="pe";
    else if (fd->bytes.size() >= 4 && static_cast<unsigned>(std::to_integer<unsigned char>(fd->bytes[0]))==0x7F &&
             static_cast<unsigned>(std::to_integer<unsigned char>(fd->bytes[1]))=='E' &&
             static_cast<unsigned>(std::to_integer<unsigned char>(fd->bytes[2]))=='L' &&
             static_cast<unsigned>(std::to_integer<unsigned char>(fd->bytes[3]))=='F') ftype="elf";

    // Entropy (whole file)
    double H = shannon_entropy(std::span<const std::byte>(fd->bytes.data(), fd->bytes.size()));

    // Strings extraction with limits
    StringsOptions sopt; sopt.min_ascii = opt->min_str; sopt.max_ascii = opt->max_str; sopt.ascii = opt->ascii; sopt.utf16le = opt->utf16;
    auto strings = extract_strings(std::span<const std::byte>(fd->bytes.data(), fd->bytes.size()), sopt);

    // Signatures
    auto sigs = try_load_sigs(opt->sig_db, log);
    auto matches = match_signatures(std::span<const std::byte>(fd->bytes.data(), fd->bytes.size()), sigs);

    // Parse PE/ELF-specific metadata
    JsonValue specific = JsonValue::obj({});
    if (ftype == "pe") {
        auto pe = parse_pe(std::span<const std::byte>(fd->bytes.data(), fd->bytes.size()));
        if (pe && pe->valid) {
            std::vector<JsonValue> sects;
            for (const auto& s : pe->sections) {
                sects.push_back(JsonValue::obj({
                    {"name", JsonValue::str(s.name)},
                    {"vsize", JsonValue::num(s.vsize)},
                    {"vaddr", JsonValue::num(s.vaddr)},
                    {"rsize", JsonValue::num(s.rsize)},
                    {"rptr",  JsonValue::num(s.rptr)},
                    {"entropy", JsonValue::num((long long)(s.entropy*1000))} // scaled to preserve decimals when rendered
                }));
            }
            std::vector<JsonValue> imps;
            for (const auto& i : pe->imports) imps.push_back(JsonValue::str(i));
            specific = JsonValue::obj({
                {"timestamp", JsonValue::num(pe->timestamp)},
                {"sections", JsonValue::arr(sects)},
                {"imports", JsonValue::arr(imps)}
            });
        }
    } else if (ftype == "elf") {
        auto elf = parse_elf(std::span<const std::byte>(fd->bytes.data(), fd->bytes.size()));
        if (elf && elf->valid) {
            std::vector<JsonValue> sects;
            for (const auto& s : elf->sections) {
                sects.push_back(JsonValue::obj({
                    {"name", JsonValue::str(s.name)},
                    {"addr", JsonValue::num((long long)s.addr)},
                    {"off",  JsonValue::num((long long)s.off)},
                    {"size", JsonValue::num((long long)s.size)},
                    {"entropy", JsonValue::num((long long)(s.entropy*1000))}
                }));
            }
            specific = JsonValue::obj({
                {"is64", JsonValue::boolean(elf->is64)},
                {"sections", JsonValue::arr(sects)}
            });
        }
    }

    // Optional dynamic (Linux only)
    std::optional<std::vector<DynEvent>> dyn;
#if defined(MALREV_PLATFORM_LINUX)
    if (opt->dynamic) {
        DynOptions dopt;
        dopt.exec_path = opt->exec_path.empty() ? opt->input.string() : opt->exec_path.string();
        dopt.args = opt->exec_args;
        dopt.timeout_sec = opt->timeout_sec;
        log.warn("Dynamic analysis is potentially dangerous. Run inside an isolated VM without network.");
        dyn = trace_with_ptrace(dopt);
        if (!dyn) log.warn("ptrace not available or failed.");
    }
#else
    if (opt->dynamic) {
        log.warn("Dynamic analysis is only supported on Linux. Skipping.");
    }
#endif

    // Build JSON
    std::vector<JsonValue> str_js; str_js.reserve(strings.size());
    for (auto& s : strings) str_js.push_back(JsonValue::str(s));
    std::vector<JsonValue> sig_js; for (auto& m : matches) sig_js.push_back(JsonValue::str(m));
    std::vector<JsonValue> dyn_js;
    if (dyn) {
        for (const auto& e : *dyn) {
            dyn_js.push_back(JsonValue::obj({
                {"type", JsonValue::str(e.type)},
                {"detail", JsonValue::str(e.detail)},
                {"value", JsonValue::num(e.value)}
            }));
        }
    }

    JsonValue root = JsonValue::obj({
        {"generated", JsonValue::str(iso8601_now_utc())},
        {"file", JsonValue::obj({
            {"path", JsonValue::str(fd->path.string())},
            {"size_bytes", JsonValue::num((long long)fd->bytes.size())},
            {"type", JsonValue::str(ftype)}
        })},
        {"hashes", JsonValue::obj({
            {"sha256", JsonValue::str(sha_hex)}
        })},
        {"static", JsonValue::obj({
            {"entropy_bpb", JsonValue::num((long long)(H*1000))},
            {"signatures", JsonValue::arr(sig_js)},
            {"specific", specific}
        })},
        {"strings", JsonValue::arr(str_js)},
        {"dynamic", JsonValue::obj({
            {"events", JsonValue::arr(dyn_js)}
        })}
    });

    // Emit to files if requested
    if (!opt->out_json.empty()) {
        if (!write_text_file(opt->out_json.string(), root.s)) {
            log.warn("Failed to write JSON report: " + opt->out_json.string());
        } else {
            log.info("Wrote JSON report: " + opt->out_json.string());
        }
    }
    if (!opt->out_html.empty()) {
        // Load template from resources next to binary is not trivial; for demo, embed at build time or load from known path.
        // Here we expect caller to run from repo root and provide resources/template.html
        std::ifstream ifs("resources/template.html");
        if (!ifs) {
            log.warn("HTML template not found at resources/template.html; skipping HTML.");
        } else {
            std::string tpl((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            if (!write_html_report(opt->out_html.string(), tpl, root.s)) {
                log.warn("Failed to write HTML report: " + opt->out_html.string());
            } else {
                log.info("Wrote HTML report: " + opt->out_html.string());
            }
        }
    }

    // Console summary (non-verbose)
    std::cout << "sha256=" << sha_hex << " type=" << ftype << " size=" << fd->bytes.size()
              << " entropy=" << (H) << " strings=" << strings.size() << "\n";

    return 0;
}
