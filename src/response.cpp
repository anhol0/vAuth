#include "response.hpp"
#include "device.hpp"
#include "error.hpp"
#include "uhid_report.hpp"
#include <cstdint>
#include <utility>
#include <vector>

constexpr uint8_t CAPABILITY_WINK = 0x01;
constexpr uint8_t CAPABILITY_CBOR = 0x04;
constexpr uint8_t CAPABILITY_NMSG = 0x08;

CTAPPacket handle_init(UHIDReport &request, uint32_t assigned_cid) {
    CTAPPacket response;
    // --- INIT PAYLOAD STRUCTURE ---
    // Echoed Nonce (8 Bytes)
    // New Channel ID (4 bytes)
    // Protocol version identifier (1 Byte) (02)
    // Major device version number (1 Byte)
    // Minor device version number (i Byte)
    // Build number (1 Byte)
    // Capabilities (1 Byte)
    std::vector<uint8_t> payload;
    if(request.payload.size() != 8) {
        return make_hid_error(request.cid, HIDError::CTAP1_ERR_INVALID_LENGTH);
    }
    payload.insert(payload.end(), request.payload.begin(), request.payload.begin() + 8);
    payload.push_back((assigned_cid >> 24) & 0xFF);
    payload.push_back((assigned_cid >> 16) & 0xFF);
    payload.push_back((assigned_cid >>  8) & 0xFF);
    payload.push_back((assigned_cid >>  0) & 0xFF);

    payload.push_back(0x02);
    payload.push_back(0x01);
    payload.push_back(0x00);
    payload.push_back(0x00);

    uint8_t capabilities = CAPABILITY_CBOR | CAPABILITY_NMSG;
    payload.push_back(capabilities);

    response.cid = request.cid;
    response.cmd = CTAPHID_INIT | MASK;
    response.payload = std::move(payload);
    response.len = static_cast<uint16_t>(response.payload.size());
    return response;
}

CTAPPacket handle_ping(UHIDReport &request) {
    CTAPPacket response;
    response.cid = request.cid;
    response.cmd = CTAPHID_PING | MASK;
    response.payload = request.payload;
    response.len =
        static_cast<uint16_t>(response.payload.size());
    return response;
}
