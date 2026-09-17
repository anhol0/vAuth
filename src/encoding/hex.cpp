#include "hex.hpp"
#include <stdexcept>

uint8_t decode_hex_digit(char digit) {
	if(digit >= '0' && digit <= '9')
		return static_cast<uint8_t>(digit - '0');
	if(digit >= 'a' && digit <= 'f')
		return static_cast<uint8_t>(digit - 'a' + 10);
	if(digit >= 'A' && digit <= 'F')
		return static_cast<uint8_t>(digit - 'A' + 10);

	throw std::invalid_argument("Invalid hexadecimal character");
}

// Hex conversions
std::string hex_encode(const std::vector<uint8_t>& v) {
	std::string s;
	if(v.size() > s.max_size() / 2)
		throw std::length_error("Hex-encoded output is too large");
	s.reserve(v.size() * 2);
	for(const auto& c : v) {
		char buf[3];
		sprintf(buf, "%02X", c);
		s += buf;
	}
	return s;
}

std::vector<uint8_t> hex_decode(const std::string_view s) {
	std::vector<uint8_t> v;
	v.reserve(s.size() / 2);
	if(s.size() % 2)
		throw std::invalid_argument("Odd size string is given");
	for(std::size_t i = 0; i < s.size(); i += 2) {
		const uint8_t high = decode_hex_digit(s[i]);
		const uint8_t low  = decode_hex_digit(s[i + 1]);
		v.push_back(static_cast<uint8_t>((high << 4) | low));
	}
	return v;
}
