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

bool is_continuation_byte(uint8_t value) noexcept {
    return value >= 0x80 && value <= 0xbf;
}

void validate_display_text(
    std::string_view text,
    std::string_view field
) {
    if(text.size() > MAX_VERIFICATION_TEXT_SIZE)
        invalid(std::string(field) + " exceeds the verifier protocol limit");

    std::size_t index = 0;
    while(index < text.size()) {
        const auto first = static_cast<uint8_t>(text[index]);
        if(first <= 0x7f) {
            if(first < 0x20 || first == 0x7f)
                invalid(std::string(field) + " contains a control character");
            ++index;
            continue;
        }

        if(first >= 0xc2 && first <= 0xdf) {
            if(index + 1 >= text.size())
                invalid(std::string(field) + " is not valid UTF-8");
            const auto second = static_cast<uint8_t>(text[index + 1]);
            if(!is_continuation_byte(second))
                invalid(std::string(field) + " is not valid UTF-8");
            if(first == 0xc2 && second <= 0x9f)
                invalid(std::string(field) + " contains a control character");
            index += 2;
            continue;
        }

        if(first >= 0xe0 && first <= 0xef) {
            if(index + 2 >= text.size())
                invalid(std::string(field) + " is not valid UTF-8");
            const auto second = static_cast<uint8_t>(text[index + 1]);
            const auto third = static_cast<uint8_t>(text[index + 2]);
            const bool valid_second =
                (first == 0xe0 && second >= 0xa0 && second <= 0xbf) ||
                (first >= 0xe1 && first <= 0xec &&
                    is_continuation_byte(second)) ||
                (first == 0xed && second >= 0x80 && second <= 0x9f) ||
                (first >= 0xee && first <= 0xef &&
                    is_continuation_byte(second));
            if(!valid_second || !is_continuation_byte(third))
                invalid(std::string(field) + " is not valid UTF-8");
            index += 3;
            continue;
        }

        if(first >= 0xf0 && first <= 0xf4) {
            if(index + 3 >= text.size())
                invalid(std::string(field) + " is not valid UTF-8");
            const auto second = static_cast<uint8_t>(text[index + 1]);
            const auto third = static_cast<uint8_t>(text[index + 2]);
            const auto fourth = static_cast<uint8_t>(text[index + 3]);
            const bool valid_second =
                (first == 0xf0 && second >= 0x90 && second <= 0xbf) ||
                (first >= 0xf1 && first <= 0xf3 &&
                    is_continuation_byte(second)) ||
                (first == 0xf4 && second >= 0x80 && second <= 0x8f);
            if(
                !valid_second ||
                !is_continuation_byte(third) ||
                !is_continuation_byte(fourth)
            ) {
                invalid(std::string(field) + " is not valid UTF-8");
            }
            index += 4;
            continue;
        }

        invalid(std::string(field) + " is not valid UTF-8");
    }
}

std::string decode_display_text(
    std::span<const uint8_t> payload,
    std::string_view field
) {
    if(payload.size() > MAX_VERIFICATION_TEXT_SIZE)
        invalid(std::string(field) + " exceeds the verifier protocol limit");
    std::string text(payload.size(), '\0');
    if(!payload.empty())
        std::memcpy(text.data(), payload.data(), payload.size());
    validate_display_text(text, field);
    return text;
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

SensitiveBytes encode_status(const VerificationStatus& status) {
    validate_display_text(status.message, "verification status message");
    SensitiveBytes packet(
        VERIFIER_PROTOCOL_HEADER_SIZE + sizeof(uint8_t) +
        status.message.size()
    );
    set_header(packet, MessageType::status);
    auto bytes = packet.writable_bytes();
    bytes[VERIFIER_PROTOCOL_HEADER_SIZE] =
        static_cast<uint8_t>(status.kind);
    if(!status.message.empty()) {
        std::memcpy(
            bytes.data() + VERIFIER_PROTOCOL_HEADER_SIZE + sizeof(uint8_t),
            status.message.data(),
            status.message.size()
        );
    }
    return packet;
}

SensitiveBytes encode_secret_required(const SecretRequired& required) {
    validate_display_text(required.prompt, "verification prompt");
    SensitiveBytes packet(
        VERIFIER_PROTOCOL_HEADER_SIZE + required.prompt.size()
    );
    set_header(packet, MessageType::secret_required);
    if(!required.prompt.empty()) {
        std::memcpy(
            packet.writable_bytes().data() + VERIFIER_PROTOCOL_HEADER_SIZE,
            required.prompt.data(),
            required.prompt.size()
        );
    }
    return packet;
}

bool is_valid(VerificationStatusKind kind) {
    switch(kind) {
        case VerificationStatusKind::information:
        case VerificationStatusKind::error:
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
            if(!is_valid(status.kind))
                invalid("invalid verification status kind");
            return encode_status(status);
        },
        [](const SecretRequired& required) {
            return encode_secret_required(required);
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
            if(
                payload.empty() ||
                payload.size() > sizeof(uint8_t) +
                    MAX_VERIFICATION_TEXT_SIZE
            ) {
                invalid("invalid verification-status packet length");
            }
            const auto kind =
                static_cast<VerificationStatusKind>(payload[0]);
            if(!is_valid(kind))
                invalid("invalid verification status kind");
            return VerificationStatus{
                .kind = kind,
                .message = decode_display_text(
                    payload.subspan(sizeof(uint8_t)),
                    "verification status message"
                )
            };
        }
        case MessageType::secret_required:
            return SecretRequired{
                .prompt = decode_display_text(
                    payload,
                    "verification prompt"
                )
            };
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
