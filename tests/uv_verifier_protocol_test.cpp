#include "test_runner.hpp"
#include "uv/src/verifier_protocol.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace {

#define CHECK(condition) do { \
    if(!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return false; \
    } \
} while(false)

vauth::uv::SensitiveBytes sensitive_bytes(
    std::initializer_list<uint8_t> bytes
) {
    vauth::uv::SensitiveBytes result(bytes.size());
    std::copy(
        bytes.begin(),
        bytes.end(),
        result.writable_bytes().begin()
    );
    return result;
}

template<typename Function>
bool rejects_packet(Function&& function) {
    try {
        std::forward<Function>(function)();
    } catch(const vauth::uv::VerifierProtocolError&) {
        return true;
    } catch(...) {
        return false;
    }
    return false;
}

std::vector<uint8_t> packet(
    uint8_t version,
    uint8_t type,
    std::span<const uint8_t> payload
) {
    std::vector<uint8_t> result{version, type};
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

bool bytes_equal(
    std::span<const uint8_t> left,
    std::span<const uint8_t> right
) {
    return std::equal(
        left.begin(),
        left.end(),
        right.begin(),
        right.end()
    );
}

bool test_start_request_exact_encoding_and_round_trip() {
    const vauth::uv::VerifierMessage message =
        vauth::uv::StartVerification{
            .targetUid = 0x11223344,
            .sessionId = "c2"
        };

    const std::vector<uint8_t> expected{
        0x01, 0x01,
        0x11, 0x22, 0x33, 0x44,
        'c', '2'
    };
    const auto encoded = vauth::uv::encode_verifier_message(message);
    CHECK(bytes_equal(encoded.bytes(), expected));

    auto decoded = vauth::uv::decode_verifier_message(encoded.bytes());
    CHECK(std::holds_alternative<vauth::uv::StartVerification>(decoded));
    CHECK(
        std::get<vauth::uv::StartVerification>(decoded) ==
        std::get<vauth::uv::StartVerification>(message)
    );
    return true;
}

bool test_secret_exact_encoding_and_round_trip() {
    vauth::uv::VerifierMessage message = vauth::uv::SecretResponse{
        .secret = sensitive_bytes({'s', 'e', 'c', 'r', 'e', 't'})
    };
    const std::vector<uint8_t> expected{
        0x01, 0x02,
        's', 'e', 'c', 'r', 'e', 't'
    };
    const auto encoded = vauth::uv::encode_verifier_message(message);
    CHECK(bytes_equal(encoded.bytes(), expected));

    auto decoded = vauth::uv::decode_verifier_message(encoded.bytes());
    CHECK(std::holds_alternative<vauth::uv::SecretResponse>(decoded));
    const auto& secret =
        std::get<vauth::uv::SecretResponse>(decoded).secret;
    CHECK(secret.size() == 6);
    CHECK(std::equal(
        secret.bytes().begin(),
        secret.bytes().end(),
        expected.begin() + vauth::uv::VERIFIER_PROTOCOL_HEADER_SIZE
    ));
    return true;
}

bool test_empty_secret_is_valid() {
    vauth::uv::VerifierMessage message = vauth::uv::SecretResponse{
        .secret = vauth::uv::SensitiveBytes{}
    };
    const auto encoded = vauth::uv::encode_verifier_message(message);
    CHECK(encoded.size() == vauth::uv::VERIFIER_PROTOCOL_HEADER_SIZE);

    auto decoded = vauth::uv::decode_verifier_message(encoded.bytes());
    CHECK(std::holds_alternative<vauth::uv::SecretResponse>(decoded));
    CHECK(std::get<vauth::uv::SecretResponse>(decoded).secret.size() == 0);
    return true;
}

bool test_control_messages_exact_encoding_and_round_trip() {
    const std::array<vauth::uv::VerifierMessage, 7> messages{
        vauth::uv::CancelVerification{},
        vauth::uv::VerificationStatus{
            vauth::uv::VerificationStatusKind::information,
            "Touch sensor"
        },
        vauth::uv::VerificationStatus{
            vauth::uv::VerificationStatusKind::error,
            "No match"
        },
        vauth::uv::SecretRequired{"Password:"},
        vauth::uv::VerificationComplete{
            vauth::uv::VerificationResult::success
        },
        vauth::uv::VerificationComplete{
            vauth::uv::VerificationResult::denied
        },
        vauth::uv::VerificationComplete{
            vauth::uv::VerificationResult::error
        }
    };
    const std::array<std::vector<uint8_t>, 7> expected{
        std::vector<uint8_t>{0x01, 0x03},
        std::vector<uint8_t>{
            0x01, 0x04, 0x01,
            'T', 'o', 'u', 'c', 'h', ' ', 's', 'e', 'n', 's', 'o', 'r'
        },
        std::vector<uint8_t>{
            0x01, 0x04, 0x02,
            'N', 'o', ' ', 'm', 'a', 't', 'c', 'h'
        },
        std::vector<uint8_t>{
            0x01, 0x05,
            'P', 'a', 's', 's', 'w', 'o', 'r', 'd', ':'
        },
        std::vector<uint8_t>{0x01, 0x06, 0x01},
        std::vector<uint8_t>{0x01, 0x06, 0x02},
        std::vector<uint8_t>{0x01, 0x06, 0x03}
    };

    for(std::size_t index = 0; index < messages.size(); ++index) {
        const auto encoded = vauth::uv::encode_verifier_message(
            messages[index]
        );
        CHECK(bytes_equal(encoded.bytes(), expected[index]));
        auto decoded = vauth::uv::decode_verifier_message(encoded.bytes());
        CHECK(decoded.index() == messages[index].index());
        if(std::holds_alternative<vauth::uv::VerificationStatus>(decoded)) {
            CHECK(
                std::get<vauth::uv::VerificationStatus>(decoded) ==
                std::get<vauth::uv::VerificationStatus>(messages[index])
            );
        }
        if(std::holds_alternative<vauth::uv::SecretRequired>(decoded)) {
            CHECK(
                std::get<vauth::uv::SecretRequired>(decoded) ==
                std::get<vauth::uv::SecretRequired>(messages[index])
            );
        }
        if(std::holds_alternative<vauth::uv::VerificationComplete>(decoded)) {
            CHECK(
                std::get<vauth::uv::VerificationComplete>(decoded) ==
                std::get<vauth::uv::VerificationComplete>(messages[index])
            );
        }
    }
    return true;
}

bool test_maximum_sized_fields_round_trip() {
    const vauth::uv::VerifierMessage start =
        vauth::uv::StartVerification{
            .targetUid = 1000,
            .sessionId = std::string(
                vauth::uv::MAX_SESSION_ID_SIZE,
                's'
            )
        };
    auto encoded_start = vauth::uv::encode_verifier_message(start);
    auto decoded_start = vauth::uv::decode_verifier_message(
        encoded_start.bytes()
    );
    CHECK(
        std::get<vauth::uv::StartVerification>(decoded_start).sessionId.size()
        == vauth::uv::MAX_SESSION_ID_SIZE
    );

    vauth::uv::SensitiveBytes secret(
        vauth::uv::MAX_VERIFICATION_SECRET_SIZE
    );
    std::fill(
        secret.writable_bytes().begin(),
        secret.writable_bytes().end(),
        static_cast<uint8_t>('p')
    );
    vauth::uv::VerifierMessage response = vauth::uv::SecretResponse{
        .secret = std::move(secret)
    };
    auto encoded_response = vauth::uv::encode_verifier_message(response);
    CHECK(encoded_response.size() == vauth::uv::MAX_VERIFIER_PACKET_SIZE);
    auto decoded_response = vauth::uv::decode_verifier_message(
        encoded_response.bytes()
    );
    CHECK(
        std::get<vauth::uv::SecretResponse>(decoded_response).secret.size()
        == vauth::uv::MAX_VERIFICATION_SECRET_SIZE
    );

    const std::string maximum_text(
        vauth::uv::MAX_VERIFICATION_TEXT_SIZE,
        'm'
    );
    const vauth::uv::VerifierMessage status =
        vauth::uv::VerificationStatus{
            vauth::uv::VerificationStatusKind::information,
            maximum_text
        };
    const auto encoded_status = vauth::uv::encode_verifier_message(status);
    const auto decoded_status = vauth::uv::decode_verifier_message(
        encoded_status.bytes()
    );
    CHECK(
        std::get<vauth::uv::VerificationStatus>(decoded_status).message ==
        maximum_text
    );

    const vauth::uv::VerifierMessage prompt =
        vauth::uv::SecretRequired{maximum_text};
    const auto encoded_prompt = vauth::uv::encode_verifier_message(prompt);
    const auto decoded_prompt = vauth::uv::decode_verifier_message(
        encoded_prompt.bytes()
    );
    CHECK(
        std::get<vauth::uv::SecretRequired>(decoded_prompt).prompt ==
        maximum_text
    );
    return true;
}

bool test_display_text_rules_are_enforced() {
    using namespace vauth::uv;
    const std::string oversized(MAX_VERIFICATION_TEXT_SIZE + 1, 'x');
    CHECK(rejects_packet([&] {
        const VerifierMessage message = VerificationStatus{
            VerificationStatusKind::information,
            oversized
        };
        static_cast<void>(encode_verifier_message(message));
    }));
    CHECK(rejects_packet([&] {
        const VerifierMessage message = SecretRequired{oversized};
        static_cast<void>(encode_verifier_message(message));
    }));

    const std::array<std::string, 4> invalid_text{
        std::string("line\nfeed", 9),
        std::string("embedded\0nul", 12),
        std::string("\xc0\x80", 2),
        std::string("\xed\xa0\x80", 3)
    };
    for(const auto& text : invalid_text) {
        CHECK(rejects_packet([&] {
            const VerifierMessage message = VerificationStatus{
                VerificationStatusKind::error,
                text
            };
            static_cast<void>(encode_verifier_message(message));
        }));
        CHECK(rejects_packet([&] {
            const VerifierMessage message = SecretRequired{text};
            static_cast<void>(encode_verifier_message(message));
        }));
    }

    std::vector<uint8_t> oversized_status(
        1 + MAX_VERIFICATION_TEXT_SIZE + 1,
        'x'
    );
    oversized_status[0] =
        static_cast<uint8_t>(VerificationStatusKind::information);
    CHECK(rejects_packet([&] {
        static_cast<void>(decode_verifier_message(packet(
            1, 4, oversized_status
        )));
    }));

    std::vector<uint8_t> oversized_prompt(
        MAX_VERIFICATION_TEXT_SIZE + 1,
        'x'
    );
    CHECK(rejects_packet([&] {
        static_cast<void>(decode_verifier_message(packet(
            1, 5, oversized_prompt
        )));
    }));

    const std::array<uint8_t, 3> invalid_utf8_status{0x01, 0xc0, 0x80};
    CHECK(rejects_packet([&] {
        static_cast<void>(decode_verifier_message(packet(
            1, 4, invalid_utf8_status
        )));
    }));
    const std::array<uint8_t, 1> control_prompt{'\n'};
    CHECK(rejects_packet([&] {
        static_cast<void>(decode_verifier_message(packet(
            1, 5, control_prompt
        )));
    }));
    return true;
}

bool test_empty_and_unicode_display_text_round_trip() {
    using namespace vauth::uv;
    const std::string lock_symbol("\xf0\x9f\x94\x90", 4);
    const std::array<VerifierMessage, 3> messages{
        VerificationStatus{
            VerificationStatusKind::information,
            ""
        },
        VerificationStatus{
            VerificationStatusKind::error,
            lock_symbol
        },
        SecretRequired{""}
    };

    for(const auto& message : messages) {
        const auto encoded = encode_verifier_message(message);
        const auto decoded = decode_verifier_message(encoded.bytes());
        CHECK(decoded.index() == message.index());
        if(std::holds_alternative<VerificationStatus>(message)) {
            CHECK(
                std::get<VerificationStatus>(decoded) ==
                std::get<VerificationStatus>(message)
            );
        } else {
            CHECK(
                std::get<SecretRequired>(decoded) ==
                std::get<SecretRequired>(message)
            );
        }
    }
    return true;
}

bool test_invalid_start_requests_are_rejected() {
    CHECK(rejects_packet([] {
        const vauth::uv::VerifierMessage message =
            vauth::uv::StartVerification{1000, ""};
        static_cast<void>(vauth::uv::encode_verifier_message(message));
    }));
    CHECK(rejects_packet([] {
        const vauth::uv::VerifierMessage message =
            vauth::uv::StartVerification{
                1000,
                std::string(vauth::uv::MAX_SESSION_ID_SIZE + 1, 's')
            };
        static_cast<void>(vauth::uv::encode_verifier_message(message));
    }));
    CHECK(rejects_packet([] {
        const vauth::uv::VerifierMessage message =
            vauth::uv::StartVerification{1000, std::string("c\0x", 3)};
        static_cast<void>(vauth::uv::encode_verifier_message(message));
    }));

    const std::array<uint8_t, 4> empty_session{
        0x00, 0x00, 0x03, 0xe8
    };
    CHECK(rejects_packet([&] {
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            1, 1, empty_session
        )));
    }));

    std::vector<uint8_t> oversized_session(
        sizeof(uint32_t) + vauth::uv::MAX_SESSION_ID_SIZE + 1,
        's'
    );
    CHECK(rejects_packet([&] {
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            1, 1, oversized_session
        )));
    }));

    const std::array<uint8_t, 7> embedded_nul_session{
        0x00, 0x00, 0x03, 0xe8, 'c', 0x00, '2'
    };
    CHECK(rejects_packet([&] {
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            1, 1, embedded_nul_session
        )));
    }));
    return true;
}

bool test_invalid_secrets_are_rejected() {
    CHECK(rejects_packet([] {
        const vauth::uv::VerifierMessage message =
            vauth::uv::SecretResponse{
                .secret = sensitive_bytes({'a', 0x00, 'b'})
            };
        static_cast<void>(vauth::uv::encode_verifier_message(message));
    }));
    CHECK(rejects_packet([] {
        const vauth::uv::VerifierMessage message =
            vauth::uv::SecretResponse{
                .secret = vauth::uv::SensitiveBytes(
                    vauth::uv::MAX_VERIFICATION_SECRET_SIZE + 1
                )
            };
        static_cast<void>(vauth::uv::encode_verifier_message(message));
    }));

    std::vector<uint8_t> oversized(
        vauth::uv::MAX_VERIFICATION_SECRET_SIZE + 1,
        'p'
    );
    CHECK(rejects_packet([&] {
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            1, 2, oversized
        )));
    }));

    const std::array<uint8_t, 3> embedded_nul{'a', 0x00, 'b'};
    CHECK(rejects_packet([&] {
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            1, 2, embedded_nul
        )));
    }));
    return true;
}

bool test_malformed_headers_are_rejected() {
    CHECK(rejects_packet([] {
        const std::array<uint8_t, 0> short_header{};
        static_cast<void>(vauth::uv::decode_verifier_message(short_header));
    }));
    CHECK(rejects_packet([] {
        const std::array<uint8_t, 1> short_header{0x01};
        static_cast<void>(vauth::uv::decode_verifier_message(short_header));
    }));
    CHECK(rejects_packet([] {
        const std::array<uint8_t, 0> payload{};
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            2, 3, payload
        )));
    }));
    CHECK(rejects_packet([] {
        const std::array<uint8_t, 0> payload{};
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            1, 0xff, payload
        )));
    }));
    return true;
}

bool test_invalid_control_payloads_are_rejected() {
    const std::array<uint8_t, 0> empty{};
    const std::array<uint8_t, 1> byte{0xff};
    CHECK(rejects_packet([&] {
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            1, 3, byte
        )));
    }));
    CHECK(rejects_packet([&] {
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            1, 4, byte
        )));
    }));
    CHECK(rejects_packet([&] {
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            1, 6, byte
        )));
    }));
    CHECK(rejects_packet([&] {
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            1, 4, empty
        )));
    }));
    CHECK(rejects_packet([&] {
        static_cast<void>(vauth::uv::decode_verifier_message(packet(
            1, 6, empty
        )));
    }));
    CHECK(rejects_packet([] {
        const vauth::uv::VerifierMessage message =
            vauth::uv::VerificationStatus{
                static_cast<vauth::uv::VerificationStatusKind>(0xff),
                "Invalid"
            };
        static_cast<void>(vauth::uv::encode_verifier_message(message));
    }));
    CHECK(rejects_packet([] {
        const vauth::uv::VerifierMessage message =
            vauth::uv::VerificationComplete{
                static_cast<vauth::uv::VerificationResult>(0xff)
            };
        static_cast<void>(vauth::uv::encode_verifier_message(message));
    }));
    return true;
}

} // namespace

int main() {
    test_support::Runner runner;
    runner.run(
        "start request exact encoding and round trip",
        test_start_request_exact_encoding_and_round_trip
    );
    runner.run(
        "secret exact encoding and round trip",
        test_secret_exact_encoding_and_round_trip
    );
    runner.run("empty secret is valid", test_empty_secret_is_valid);
    runner.run(
        "control messages exact encoding and round trip",
        test_control_messages_exact_encoding_and_round_trip
    );
    runner.run(
        "maximum sized fields round trip",
        test_maximum_sized_fields_round_trip
    );
    runner.run(
        "display text rules are enforced",
        test_display_text_rules_are_enforced
    );
    runner.run(
        "empty and Unicode display text round trip",
        test_empty_and_unicode_display_text_round_trip
    );
    runner.run(
        "invalid start requests are rejected",
        test_invalid_start_requests_are_rejected
    );
    runner.run(
        "invalid secrets are rejected",
        test_invalid_secrets_are_rejected
    );
    runner.run(
        "malformed headers are rejected",
        test_malformed_headers_are_rejected
    );
    runner.run(
        "invalid control payloads are rejected",
        test_invalid_control_payloads_are_rejected
    );
    return runner.finish();
}
