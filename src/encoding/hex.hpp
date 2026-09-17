#pragma once

#include <cstdint>
#include <string>
#include <vector>

[[nodiscard]] std::string hex_encode(const std::vector<uint8_t>& v);
[[nodiscard]] std::vector<uint8_t> hex_decode(const std::string& s);
