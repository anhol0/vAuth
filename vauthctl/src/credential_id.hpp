#pragma once

#include <cstddef>

namespace vauthctl {

inline constexpr std::size_t MIN_CREDENTIAL_ID_SIZE = 16;
inline constexpr std::size_t MAX_CREDENTIAL_ID_SIZE = 1024;

[[nodiscard]] constexpr bool valid_credential_id_hex_length(
	std::size_t length
) noexcept {
	return
		length >= MIN_CREDENTIAL_ID_SIZE * 2 &&
		length <= MAX_CREDENTIAL_ID_SIZE * 2 &&
		length % 2 == 0;
}

} // namespace vauthctl
