#pragma once

#include <array>
#include <cstdint>
#include <sys/types.h>

static const std::array<uint8_t, 16> aaguid		= { 0x87, 0x91, 0xf7, 0xdc,
													0x41, 0x8b, 0x45, 0x10,
													0xbb, 0xf5, 0x3b, 0xaf,
													0x30, 0x71, 0x53, 0x24 };
inline constexpr std::uint32_t firmware_version = 1;
constexpr const char* STORE_PATH = "/var/lib/vauth/credentials.v1";
