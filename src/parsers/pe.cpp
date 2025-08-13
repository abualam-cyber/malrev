#include "pe.h"
#include <cstring>
#include <string_view>
#include "../analysis/entropy.h"

namespace malrev {

static std::uint16_t rd16(const std::byte* p){ return (std::uint16_t)p[0] | ((std::uint16_t)p[1] << 8); }
static std::uint32_t rd32(const std::byte* p){ return (std::uint32_t)p[0] | ((std::uint32_t)p[1] << 8) | ((std::uint32_t)p[2] << 16) | ((std::uint32_t)p[3] << 24); }

std::optional<PEInfo> parse_pe(std::span<const std::byte> data) {
    if (data.size() < 0x40) return std::nullopt;
    if (static_cast<unsigned>(std::to_integer<unsigned char>(data[0])) != 'M' ||
        static_cast<unsigned>(std::to_integer<unsigned char>(data[1])) != 'Z') return std::nullopt;

    auto e_lfanew = rd32(reinterpret_cast<const std::byte*>(data.data()+0x3C));
    if (e_lfanew + 24 > data.size()) return std::nullopt;

    const std::byte* nt = data.data() + e_lfanew;
    if (static_cast<unsigned>(std::to_integer<unsigned char>(nt[0])) != 'P' ||
        static_cast<unsigned>(std::to_integer<unsigned char>(nt[1])) != 'E' ||
        nt[2] != std::byte{0} || nt[3] != std::byte{0}) return std::nullopt;

    const std::byte* fh = nt + 4;
    auto num_sections = rd16(fh + 2);
    auto timestamp = rd32(fh + 4);
    auto opt_hdr_size = rd16(fh + 16);
    const std::byte* oh = fh + 20;
    if (oh + opt_hdr_size > data.data() + data.size()) return std::nullopt;

    bool is_pe32plus = (rd16(oh) == 0x20b);
    const std::byte* data_dirs = oh + (is_pe32plus ? 112 : 96);
    if (data_dirs > data.data() + data.size()) return std::nullopt;

    // Import Directory is DataDirectory[1]
    std::uint32_t imp_rva = rd32(data_dirs + 8);
    std::uint32_t imp_size = rd32(data_dirs + 12);

    // Section table follows optional header
    const std::byte* sect = oh + opt_hdr_size;
    std::vector<PESection> sections;
    sections.reserve(num_sections);
    for (int i=0;i<num_sections;++i) {
        if (sect + 40 > data.data() + data.size()) break;
        char name[9]{}; std::memcpy(name, sect, 8); name[8] = 0;
        PESection s;
        s.name = std::string(name);
        s.vsize = rd32(sect + 8);
        s.vaddr = rd32(sect + 12);
        s.rsize = rd32(sect + 16);
        s.rptr  = rd32(sect + 20);
        if (s.rptr + s.rsize <= data.size()) {
            s.entropy = shannon_entropy(std::span<const std::byte>(data.data()+s.rptr, s.rsize));
        }
        sections.push_back(s);
        sect += 40;
    }

    // Helper to map RVA->file offset
    auto rva_to_off = [&](std::uint32_t rva)->std::optional<std::uint32_t> {
        for (const auto& s : sections) {
            if (rva >= s.vaddr && rva < s.vaddr + s.rsize) {
                return s.rptr + (rva - s.vaddr);
            }
        }
        return std::nullopt;
    };

    // Parse a minimal import table (PE32 only here; for PE32+ names are similar)
    std::vector<std::string> imports;
    if (imp_rva && imp_size) {
        auto imp_off = rva_to_off(imp_rva);
        if (imp_off && *imp_off + imp_size <= data.size()) {
            const std::byte* imp = data.data() + *imp_off;
            for (size_t i=0; i+20 <= imp_size; i += 20) {
                std::uint32_t name_rva = rd32(imp + i + 12);
                if (!name_rva) break;
                auto name_off = rva_to_off(name_rva);
                if (!name_off || *name_off >= data.size()) break;
                const char* nm = reinterpret_cast<const char*>(data.data() + *name_off);
                // Safe copy until NUL or end of file
                std::string dll;
                for (size_t k=*name_off; k<data.size() && dll.size()<256; ++k) {
                    char c = reinterpret_cast<const char*>(data.data())[k];
                    if (c==0) break;
                    dll.push_back(c);
                }
                if (!dll.empty()) imports.push_back(dll);
            }
        }
    }

    PEInfo info;
    info.valid = true;
    info.timestamp = timestamp;
    info.sections = std::move(sections);
    info.imports = std::move(imports);
    return info;
}

} // namespace malrev
