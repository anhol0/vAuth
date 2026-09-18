#include "verifier_protocol.hpp"

#include <algorithm>
#include <cstring>
#include <string_view>
#include <utility>

namespace vauth::uv {
namespace {

enum class MessageType : uint8_t {
    start = 1,
    secret_response = 2,
    cancel = 3,
    status = 4,
    secret_required = 5,
    complete = 6
};

template<typename... Functions>
struct Overloaded : Functions... {
    using Functions::operator()...;
};

template<typename... Functions>
Overloaded(Functions...) -> Overloaded<Functions...>;

[[noreturn]] void invalid(std::string message) {
    throw VerifierProtocolError(std::move(message));
}

void validate_session_id(std::string_view session) {
    if(session.empty())
        invalid("session ID must not be empty");
    if(session.size() > MAX_SESSION_ID_SIZE)
        invalid("session ID exceeds the verifier protocol limit");
    if(session.find('\0') != std::string_view::npos)
        invalid("session ID contains an embedded NUL");
}

void validate_session_id(std::span<const uint8_t> session) {
    if(session.empty())
        invalid("session ID must not be empty");
    if(session.size() > MAX_SESSION_ID_SIZE)
        invalid("session ID exceeds the verifier protocol limit");
    if(std::find(session.begin(), session.end(), uint8_t{0}) != session.end())
        invalid("session ID contains an embedded NUL");
}

void validate_secret(std::span<const uint8_t> secret) {
    if(secret.size() > MAX_VERIFICATION_SECRET_SIZE)
        invalid("secret exceeds the verifier protocol limit");
    if(
        std::find(secret.begin(), secret.end(), uint8_t{0}) !=
        secret.end()
    ) {
        invalid("secret contains an embedded NUL");
    }
}

void set_header(SensitiveBytes& packet, MessageType type) {
    auto bytes = packet.writable_bytes();
    bytes[0] = VERIFIER_PROTOCOL_VERSION;
    bytes[1] = static_cast<uint8_t>(type);
}

void write_uint32_be(std::span<uint8_t, 4> destination, uint32_t value) {
    destination[0] = static_cast<uint8_t>(value >> 24);
    destination[1] = static_cast<uint8_t>(value >> 16);
    destination[2] = static_cast<uint8_t>(value >> 8);
    destination[3] = static_cast<uint8_t>(value);
}

uint32_t read_uint32_be(std::span<const uint8_t, 4> source) {
    return
        (static_cast<uint32_t>(source[0]) << 24) |
        (static_cast<uint32_t>(source[1]) << 16) |
        (static_cast<uint32_t>(source[2]) << 8) |
        static_cast<uint32_t>(source[3]);
}

SensitiveBytes encode_start(const StartVerification& start) {
    validate_session_id(start.sessionId);

    SensitiveBytes packet(
        VERIFIER_PROTOCOL_HEADER_SIZE + sizeof(uint32_t) +
        start.sessionId.size()
    );
    set_header(packet, MessageType::start);
    auto bytes = packet.writable_bytes();
    write_uint32_be(
        std::span<uint8_t, 4>(bytes.subspan(
            VERIFIER_PROTOCOL_HEADER_SIZE,
            sizeof(uint32_t)
        )),
        start.targetUid
    );
    std::memcpy(
        bytes.data() + VERIFIER_PROTOCOL_HEADER_SIZE + sizeof(uint32_t),
        start.sessionId.data(),
        start.sessionId.size()
    );
    return packet;
}

SensitiveBytes encode_secret(const SecretResponse& response) {
    validate_secret(response.secret.bytes());
    SensitiveBytes packet(
        VERIFIER_PROTOCOL_HEADER_SIZE + response.secret.size()
    );
    set_header(packet, MessageType::secret_response);
    std::copy(
        response.secret.bytes().begin(),
        response.secret.bytes().end(),
        packet.writable_bytes().begin() + VERIFIER_PROTOCOL_HEADER_SIZE
    );
    return packet;
}

SensitiveBytes encode_empty(MessageType type) {
    SensitiveBytes packet(VERIFIER_PROTOCOL_HEADER_SIZE);
    set_header(packet, type);
    return packet;
}

SensitiveBytes encode_byte(MessageType type, uint8_t value) {
    SensitiveBytes packet(VERIFIER_PROTOCOL_HEADER_SIZE + 1);
    set_header(packet, type);
    packet.writable_bytes()[VERIFIER_PROTOCOL_HEADER_SIZE] = value;
    return packet;
}

bool is_valid(VerificationProgress progress) {
    switch(progress) {
        case VerificationProgress::interaction_required:
        case VerificationProgress::attempt_failed:
            return true;
    }
    return false;
}

bool is_valid(VerificationResult result) {
    switch(result) {
        case VerificationResult::success:
        case VerificationResult::denied:
        case VerificationResult::error:
            return true;
    }
    return false;
}

}

SensitiveBytes encode_verifier_message(const VerifierMessage& message) {
    return std::visit(Overloaded{
        [](const StartVerification& start) {
            return encode_start(start);
        },
        [](const SecretResponse& response) {
            return encode_secret(response);
        },
        [](const CancelVerification&) {
            return encode_empty(MessageType::cancel);
        },
        [](const VerificationStatus& status) {
            if(!is_valid(status.progress))
                invalid("invalid verification progress");
            return encode_byte(
                MessageType::status,
                static_cast<uint8_t>(status.progress)
            );
        },
        [](const SecretRequired&) {
            return encode_empty(MessageType::secret_required);
        },
        [](const VerificationComplete& complete) {
            if(!is_valid(complete.result))
                invalid("invalid verification result");
            return encode_byte(
                MessageType::complete,
                static_cast<uint8_t>(complete.result)
            );
        }
    }, message);
}

VerifierMessage decode_verifier_message(std::span<const uint8_t> packet) {
    if(packet.size() < VERIFIER_PROTOCOL_HEADER_SIZE)
        invalid("verifier packet header is truncated");
    if(packet.size() > MAX_VERIFIER_PACKET_SIZE)
        invalid("verifier packet exceeds the protocol limit");
    if(packet[0] != VERIFIER_PROTOCOL_VERSION)
        invalid("unsupported verifier protocol version");

    const auto payload = packet.subspan(VERIFIER_PROTOCOL_HEADER_SIZE);
    switch(static_cast<MessageType>(packet[1])) {
        case MessageType::start: {
            if(
                payload.size() <= sizeof(uint32_t) ||
                payload.size() > sizeof(uint32_t) + MAX_SESSION_ID_SIZE
            ) {
                invalid("invalid start-verification packet length");
            }
            const auto session = payload.subspan(sizeof(uint32_t));
            validate_session_id(session);
            std::string session_id(session.size(), '\0');
            std::memcpy(
                session_id.data(),
                session.data(),
                session.size()
            );
            return StartVerification{
                .targetUid = read_uint32_be(
                    std::span<const uint8_t, 4>(
                        payload.first<sizeof(uint32_t)>()
                    )
                ),
                .sessionId = std::move(session_id)
            };
        }
        case MessageType::secret_response: {
            validate_secret(payload);
            SensitiveBytes secret(payload.size());
            std::copy(
                payload.begin(),
                payload.end(),
                secret.writable_bytes().begin()
            );
            return SecretResponse{.secret = std::move(secret)};
        }
        case MessageType::cancel:
            if(!payload.empty())
                invalid("cancel packet contains a payload");
            return CancelVerification{};
        case MessageType::status: {
            if(payload.size() != 1)
                invalid("invalid verification-status packet length");
            const auto progress =
                static_cast<VerificationProgress>(payload[0]);
            if(!is_valid(progress))
                invalid("invalid verification progress");
            return VerificationStatus{.progress = progress};
        }
        case MessageType::secret_required:
            if(!payload.empty())
                invalid("secret-required packet contains a payload");
            return SecretRequired{};
        case MessageType::complete: {
            if(payload.size() != 1)
                invalid("invalid verification-result packet length");
            const auto result = static_cast<VerificationResult>(payload[0]);
            if(!is_valid(result))
                invalid("invalid verification result");
            return VerificationComplete{.result = result};
        }
    }
    invalid("unknown verifier message type");
}

}
