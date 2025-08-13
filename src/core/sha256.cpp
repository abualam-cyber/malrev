#include "sha256.h"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace malrev {

static constexpr std::uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline std::uint32_t rotr(std::uint32_t x, std::uint32_t n){ return (x>>n)|(x<<(32-n)); }

void Sha256::reset() noexcept {
    H_.fill(0);
    buffer_.fill(0);
    bitlen_ = 0;
    buffer_len_ = 0;
    // Initial hash values
    const std::uint32_t H0[8] = {
      0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
      0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    std::memcpy(H_.data(), H0, 32);
}

void Sha256::update(std::span<const std::byte> data) noexcept {
    for (size_t i = 0; i < data.size(); ++i) {
        buffer_[buffer_len_++] = static_cast<std::uint8_t>(std::to_integer<unsigned char>(data[i]));
        if (buffer_len_ == 64) {
            transform(buffer_.data());
            bitlen_ += 512;
            buffer_len_ = 0;
        }
    }
}

void Sha256::finalize() noexcept {
    bitlen_ += buffer_len_ * 8;
    buffer_[buffer_len_++] = 0x80;
    if (buffer_len_ > 56) {
        while (buffer_len_ < 64) buffer_[buffer_len_++] = 0;
        transform(buffer_.data());
        buffer_len_ = 0;
    }
    while (buffer_len_ < 56) buffer_[buffer_len_++] = 0;
    // Append length big-endian
    for (int i = 7; i >= 0; --i) buffer_[buffer_len_++] = (bitlen_ >> (i*8)) & 0xFF;
    transform(buffer_.data());
}

void Sha256::transform(const std::uint8_t* chunk) noexcept {
    std::uint32_t w[64];
    for (int i=0;i<16;++i) {
        w[i]  = (chunk[i*4+0] << 24) | (chunk[i*4+1] << 16) | (chunk[i*4+2] << 8) | (chunk[i*4+3]);
    }
    for (int i=16;i<64;++i) {
        std::uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
        std::uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    std::uint32_t a,b,c,d,e,f,g,h;
    std::memcpy(&a, H_.data()+0, 4); std::memcpy(&b, H_.data()+4, 4);
    std::memcpy(&c, H_.data()+8, 4); std::memcpy(&d, H_.data()+12,4);
    std::memcpy(&e, H_.data()+16,4); std::memcpy(&f, H_.data()+20,4);
    std::memcpy(&g, H_.data()+24,4); std::memcpy(&h, H_.data()+28,4);
    for (int i=0;i<64;++i) {
        std::uint32_t S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
        std::uint32_t ch = (e & f) ^ (~e & g);
        std::uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        std::uint32_t S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
        std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        std::uint32_t temp2 = S0 + maj;
        h=g; g=f; f=e; e=d + temp1; d=c; c=b; b=a; a=temp1 + temp2;
    }
    std::uint32_t* H32 = reinterpret_cast<std::uint32_t*>(H_.data());
    H32[0]+=a; H32[1]+=b; H32[2]+=c; H32[3]+=d; H32[4]+=e; H32[5]+=f; H32[6]+=g; H32[7]+=h;
}

std::string Sha256::hex_digest() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : H_) oss << std::setw(2) << static_cast<unsigned>(b);
    return oss.str();
}

} // namespace malrev
