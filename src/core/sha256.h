#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string>

namespace malrev {
// Minimal SHA-256 for hashing files. Avoids dynamic allocations in the inner loop.
class Sha256 {
public:
    Sha256() noexcept { reset(); }
    void reset() noexcept;
    void update(std::span<const std::byte> data) noexcept;
    void finalize() noexcept;
    std::array<std::uint8_t, 32> digest() const noexcept { return H_; }
    std::string hex_digest() const;
private:
    void transform(const std::uint8_t* chunk) noexcept;
    std::array<std::uint8_t, 64> buffer_{};
    std::array<std::uint8_t, 32> H_{};
    std::uint64_t bitlen_ = 0;
    size_t buffer_len_ = 0;
};
} // namespace malrev
