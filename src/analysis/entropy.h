#pragma once
#include <span>
#include <cstddef>
#include <vector>

namespace malrev {
// Shannon entropy calculation (bytes frequency). Returns bits per byte [0..8].
double shannon_entropy(std::span<const std::byte> data);

// Sliding window entropy (for detecting packed regions). window >= 64 recommended.
std::vector<double> window_entropy(std::span<const std::byte> data, std::size_t window);
}
