#include "ctap_command_handler.hpp"

#include <cstdint>
#include <exception>
#include <utility>
#include <vector>

#include "cancellation.hpp"
#include "cbor_operations/cbor.hpp"
#include "device.hpp"
#include "error.hpp"
#include "registration/registration.hpp"

namespace {

CTAPError encoding_error_to_ctap(const CborEncodingError& error) noexcept {
    return error.failure() == CborEncodingFailure::resource_limit
        ? CTAPError::CTAP2_ERR_REQUEST_TOO_LARGE
        : CTAPError::CTAP1_ERR_OTHER;
}

} // namespace

void CTAPCommandHandler::reset() noexcept {
    getAssertion_.clear();
}

CTAPPacket CTAPCommandHandler::handle(
    UHIDReport& request,
    std::stop_token stop,
    CredentialStore& store,
    CredentialKeyProvider& key_provider,
    UserInteraction& user_interaction,
    KeepaliveState& keepalive
) {
    CTAPPacket packet;
    const uint8_t command = request.payload[0];
    std::vector<uint8_t> payload;
    if(command != 0x02 && command != 0x08) {
        reset();
    }

    if(command == 0x04) { // authenticatorGetInfo
        if(request.payload.size() != 1) {
            return make_cbor_error(
                request.cid,
                CTAPError::CTAP1_ERR_INVALID_COMMAND
            );
        }
        try {
            payload = build_getinfo_response();
        } catch(const CborEncodingError& error) {
            return make_cbor_error(
                request.cid,
                encoding_error_to_ctap(error)
            );
        }
    } else if(command == 0x01) { // authenticatorMakeCredential
        payload.insert(
            payload.end(),
            request.payload.begin() + 1,
            request.payload.end()
        );

        CTAPMakeCredentialRequest make_credential;
        if(!make_credential.parseRequest(payload)) {
            return make_cbor_error(
                request.cid,
                CTAPError::CTAP2_ERR_INVALID_CBOR
            );
        }

        try {
            payload = make_credential.build_response(
                request,
                stop,
                store,
                key_provider,
                user_interaction,
                keepalive
            );
        } catch(const OperationCancelled&) {
            throw;
        } catch(const UserActionTimedOut&) {
            throw;
        } catch(const UserInteractionUnavailable&) {
            return make_cbor_error(
                request.cid,
                CTAPError::CTAP2_ERR_OPERATION_DENIED
            );
        } catch(const CborEncodingError& error) {
            return make_cbor_error(
                request.cid,
                encoding_error_to_ctap(error)
            );
        } catch(const std::exception&) {
            return make_cbor_error(
                request.cid,
                CTAPError::CTAP1_ERR_OTHER
            );
        }

        if(payload.size() == 1) {
            return make_cbor_error(
                request.cid,
                static_cast<CTAPError>(payload[0])
            );
        }
    } else if(command == 0x02 || command == 0x08) {
        payload.insert(
            payload.end(),
            request.payload.begin() + 1,
            request.payload.end()
        );

        if(command == 0x02) { // authenticatorGetAssertion
            // A new authenticatorGetAssertion replaces any continuation state.
            reset();
            if(!getAssertion_.parseRequest(payload)) {
                reset();
                return make_cbor_error(
                    request.cid,
                    CTAPError::CTAP2_ERR_INVALID_CBOR
                );
            }
            try {
                payload = getAssertion_.build_response(
                    request,
                    stop,
                    store,
                    key_provider,
                    user_interaction,
                    keepalive
                );
            } catch(const OperationCancelled&) {
                reset();
                throw;
            } catch(const UserActionTimedOut&) {
                reset();
                throw;
            } catch(const UserInteractionUnavailable&) {
                reset();
                return make_cbor_error(
                    request.cid,
                    CTAPError::CTAP2_ERR_OPERATION_DENIED
                );
            } catch(const CborEncodingError& error) {
                reset();
                return make_cbor_error(
                    request.cid,
                    encoding_error_to_ctap(error)
                );
            } catch(const std::exception&) {
                reset();
                return make_cbor_error(
                    request.cid,
                    CTAPError::CTAP1_ERR_OTHER
                );
            }
        } else { // authenticatorGetNextAssertion
            if(
                getAssertion_.get_origin_cid() == 0 ||
                getAssertion_.get_origin_cid() != request.cid
            ) {
                return make_cbor_error(
                    request.cid,
                    CTAPError::CTAP2_ERR_NOT_ALLOWED
                );
            }

            if(request.payload.size() != 1) {
                reset();
                return make_cbor_error(
                    request.cid,
                    CTAPError::CTAP1_ERR_INVALID_COMMAND
                );
            }

            try {
                payload = getAssertion_.build_response_next(
                    request.cid,
                    stop,
                    store,
                    key_provider,
                    user_interaction
                );
            } catch(const OperationCancelled&) {
                reset();
                throw;
            } catch(const UserActionTimedOut&) {
                reset();
                throw;
            } catch(const UserInteractionUnavailable&) {
                reset();
                return make_cbor_error(
                    request.cid,
                    CTAPError::CTAP2_ERR_OPERATION_DENIED
                );
            } catch(const CborEncodingError& error) {
                reset();
                return make_cbor_error(
                    request.cid,
                    encoding_error_to_ctap(error)
                );
            } catch(const std::exception&) {
                reset();
                return make_cbor_error(
                    request.cid,
                    CTAPError::CTAP1_ERR_OTHER
                );
            }
        }

        if(payload.size() == 1) {
            reset();
            return make_cbor_error(
                request.cid,
                static_cast<CTAPError>(payload[0])
            );
        }
    } else {
        return make_cbor_error(
            request.cid,
            CTAPError::CTAP1_ERR_INVALID_COMMAND
        );
    }

    packet.cid = request.cid;
    packet.cmd = CTAPHID_CBOR | MASK;
    if(payload.size() > CTAPHID_MAX_PAYLOAD_SIZE) {
        reset();
        return make_cbor_error(
            request.cid,
            CTAPError::CTAP2_ERR_REQUEST_TOO_LARGE
        );
    }
    packet.len = static_cast<uint16_t>(payload.size());
    packet.payload = std::move(payload);
    return packet;
}
