#include "verifier_protocol.hpp"

#include <stdexcept>

namespace vauth::uv {

std::vector<uint8_t> encode_verifier_message(const VerifierMessage&) {
    throw std::logic_error("verifier protocol encoding is not implemented");
}

VerifierMessage decode_verifier_message(std::span<const uint8_t>) {
    throw std::logic_error("verifier protocol decoding is not implemented");
}

}
