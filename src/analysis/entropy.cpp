#include "entropy.h"
#include <array>
#include <cmath>

namespace malrev {

double shannon_entropy(std::span<const std::byte> data) {
    if (data.empty()) return 0.0;
    std::array<double,256> freq{};
    for (auto b : data) freq[static_cast<unsigned>(std::to_integer<unsigned char>(b))] += 1.0;
    double H = 0.0, n = static_cast<double>(data.size());
    for (double f : freq) if (f>0) { double p=f/n; H -= p*std::log2(p); }
    return H;
}

std::vector<double> window_entropy(std::span<const std::byte> data, std::size_t window) {
    std::vector<double> res;
    if (window==0 || data.size()<window) return res;
    for (size_t i=0;i+window<=data.size();i+=window) {
        res.push_back(shannon_entropy(data.subspan(i, window)));
    }
    return res;
}

} // namespace malrev
