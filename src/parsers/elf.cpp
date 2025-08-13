#include "elf.h"
#include <cstring>
#include "../analysis/entropy.h"

namespace malrev {

std::optional<ELFInfo> parse_elf(std::span<const std::byte> data) {
    if (data.size() < 0x40) return std::nullopt;
    if (!(static_cast<unsigned>(std::to_integer<unsigned char>(data[0]))==0x7F &&
          static_cast<unsigned>(std::to_integer<unsigned char>(data[1]))=='E' &&
          static_cast<unsigned>(std::to_integer<unsigned char>(data[2]))=='L' &&
          static_cast<unsigned>(std::to_integer<unsigned char>(data[3]))=='F')) return std::nullopt;

    bool is64 = (static_cast<unsigned>(std::to_integer<unsigned char>(data[4])) == 2);
    bool le   = (static_cast<unsigned>(std::to_integer<unsigned char>(data[5])) == 1);
    if (!le) return std::nullopt; // big-endian not supported here

    auto rd16 = [&](const std::byte* p)->std::uint16_t {
        return (std::uint16_t)p[0] | ((std::uint16_t)p[1] << 8);
    };
    auto rd32 = [&](const std::byte* p)->std::uint32_t {
        return (std::uint32_t)p[0] | ((std::uint32_t)p[1] << 8) | ((std::uint32_t)p[2] << 16) | ((std::uint32_t)p[3] << 24);
    };
    auto rd64 = [&](const std::byte* p)->std::uint64_t {
        return (std::uint64_t)rd32(p) | ((std::uint64_t)rd32(p+4) << 32);
    };

    ELFInfo info; info.valid = true; info.is64 = is64;

    std::uint64_t shoff = is64 ? rd64(data.data()+0x28) : rd32(data.data()+0x20);
    std::uint16_t shentsize = rd16(data.data() + (is64 ? 0x3A : 0x2E));
    std::uint16_t shnum     = rd16(data.data() + (is64 ? 0x3C : 0x30));
    std::uint16_t shstrndx  = rd16(data.data() + (is64 ? 0x3E : 0x32));

    if (shoff + (std::uint64_t)shentsize * shnum > data.size()) return info;

    // Read section header string table first
    if (shstrndx >= shnum) return info;
    const std::byte* shstr = data.data() + shoff + (std::uint64_t)shentsize * shstrndx;
    std::uint64_t shstr_off = is64 ? rd64(shstr + 0x18) : rd32(shstr + 0x10);
    std::uint64_t shstr_size= is64 ? rd64(shstr + 0x20) : rd32(shstr + 0x14);
    if (shstr_off + shstr_size > data.size()) return info;

    auto read_cstr = [&](std::uint64_t off)->std::string {
        std::string s;
        for (std::uint64_t i = off; i < off + shstr_size && i < data.size() && s.size()<256; ++i) {
            char c = reinterpret_cast<const char*>(data.data())[shstr_off + i];
            if (c==0) break; s.push_back(c);
        }
        return s;
    };

    // Iterate sections
    for (std::uint16_t i=0;i<shnum;++i) {
        const std::byte* sh = data.data() + shoff + (std::uint64_t)shentsize * i;
        std::uint32_t name_off = rd32(sh + 0x00);
        std::uint64_t off = is64 ? rd64(sh + 0x18) : rd32(sh + 0x10);
        std::uint64_t size= is64 ? rd64(sh + 0x20) : rd32(sh + 0x14);
        std::uint64_t addr= is64 ? rd64(sh + 0x10) : rd32(sh + 0x0C);
        if (off + size <= data.size()) {
            ELFSection s;
            s.name = read_cstr(name_off);
            s.off = off; s.size = size; s.addr = addr;
            s.entropy = shannon_entropy(std::span<const std::byte>(data.data()+off, size));
            info.sections.push_back(std::move(s));
        }
    }
    return info;
}

} // namespace malrev
