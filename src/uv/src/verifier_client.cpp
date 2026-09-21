#include "verifier_client.hpp"

#include "cancellation.hpp"
#include "verifier_conversation.hpp"
#include "verifier_socket.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/un.h>
#include <system_error>
#include <unistd.h>
#include <utility>

namespace vauth::uv {
namespace {

class UniqueFd {
	public:
	explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {
	}

	~UniqueFd() {
		if(fd_ >= 0)
			static_cast<void>(close(fd_));
	}

	UniqueFd(const UniqueFd&)			 = delete;
	UniqueFd& operator=(const UniqueFd&) = delete;

	UniqueFd(UniqueFd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {
	}

	UniqueFd& operator=(UniqueFd&& other) noexcept {
		if(this != &other) {
			if(fd_ >= 0)
				static_cast<void>(close(fd_));
			fd_ = std::exchange(other.fd_, -1);
		}
		return *this;
	}

	[[nodiscard]] int get() const noexcept {
		return fd_;
	}

	[[nodiscard]] int release() noexcept {
		return std::exchange(fd_, -1);
	}

	private:
	int fd_;
};

union UnixSocketAddress {
	sockaddr base;
	sockaddr_un local;
};

VerifierSocket connect_to_verifier(const std::filesystem::path& path) {
	const std::string native_path = path.string();
	if(native_path.empty())
		throw std::invalid_argument("verifier socket path is empty");

	UnixSocketAddress address{};
	address.local.sun_family = AF_UNIX;
	if(native_path.size() >= sizeof(address.local.sun_path)) {
		throw std::invalid_argument("verifier socket path exceeds the AF_UNIX "
									"limit");
	}
	std::memcpy(address.local.sun_path, native_path.c_str(), native_path.size() + 1);

	UniqueFd descriptor(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
	if(descriptor.get() < 0) {
		throw std::system_error(errno, std::generic_category(), "create verifier client socket");
	}

	const auto address_size =
		static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + native_path.size() + 1);
	int result;
	do {
		result = connect(descriptor.get(), &address.base, address_size);
	} while(result != 0 && errno == EINTR);
	if(result != 0) {
		throw std::system_error(errno, std::generic_category(), "connect to PAM verifier");
	}
	return VerifierSocket(descriptor.release());
}

} // namespace

VerificationResult run_verifier_service(
	const std::filesystem::path& socket_path,
	StartVerification start,
	std::stop_token stop,
	std::chrono::steady_clock::duration timeout,
	const std::function<void(const VerificationStatus&)>& status_callback,
	const std::function<SensitiveBytes(const SecretRequired&)>& secret_callback,
	const std::function<bool()>& cancellation_requested
) {
	cancellation_point(stop);
	if(cancellation_requested && cancellation_requested())
		throw UserInteractionCancelled{};
	if(timeout <= std::chrono::steady_clock::duration::zero())
		throw std::invalid_argument("verifier service timeout must be positive");
	if(!secret_callback)
		throw std::invalid_argument("verifier secret callback is missing");

	const auto deadline	  = std::chrono::steady_clock::now() + timeout;
	VerifierSocket socket = connect_to_verifier(socket_path);
	VerifierConversationState conversation = VerifierAwaitingStart{};
	VerifierMessage start_message		   = std::move(start);
	socket.send(start_message);
	conversation =
		advance_verifier_conversation(conversation, VerifierMessageSender::daemon, start_message);

	auto send_cancel = [&]() noexcept {
		if(verifier_conversation_is_terminal(conversation))
			return;
		try {
			VerifierMessage cancel = CancelVerification{};
			socket.send(cancel);
			conversation =
				advance_verifier_conversation(conversation, VerifierMessageSender::daemon, cancel);
		} catch(...) {
		}
	};

	while(true) {
		if(stop.stop_requested()) {
			send_cancel();
			throw OperationCancelled{};
		}
		if(cancellation_requested && cancellation_requested()) {
			send_cancel();
			throw UserInteractionCancelled{};
		}

		const auto now = std::chrono::steady_clock::now();
		if(now >= deadline) {
			send_cancel();
			throw UserActionTimedOut{};
		}
		const auto remaining =
			std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
		const int wait_ms =
			static_cast<int>(std::clamp<int64_t>(remaining.count(), 1, 20));
		pollfd descriptor{ .fd = socket.native_handle(), .events = POLLIN, .revents = 0 };
		int poll_result;
		do {
			poll_result = poll(&descriptor, 1, wait_ms);
		} while(poll_result < 0 && errno == EINTR);
		if(poll_result < 0) {
			throw std::system_error(errno, std::generic_category(), "poll PAM verifier socket");
		}
		if(poll_result == 0)
			continue;
		if((descriptor.revents & POLLIN) == 0) {
			throw VerifierSocketError("PAM verifier connection closed without "
									  "a response");
		}

		VerifierMessage message = socket.receive();
		conversation =
			advance_verifier_conversation(conversation, VerifierMessageSender::pam_verifier, message);
		if(const auto* status = std::get_if<VerificationStatus>(&message)) {
			if(status_callback)
				status_callback(*status);
			continue;
		}
		if(const auto* required = std::get_if<SecretRequired>(&message)) {
			VerifierMessage response =
				SecretResponse{ .secret = secret_callback(*required) };
			if(stop.stop_requested()) {
				send_cancel();
				throw OperationCancelled{};
			}
			if(cancellation_requested && cancellation_requested()) {
				send_cancel();
				throw UserInteractionCancelled{};
			}
			socket.send(response);
			conversation =
				advance_verifier_conversation(conversation, VerifierMessageSender::daemon, response);
			continue;
		}
		if(const auto* complete = std::get_if<VerificationComplete>(&message))
			return complete->result;

		throw VerifierConversationError("PAM verifier sent a daemon-only "
										"message");
	}
}

} // namespace vauth::uv
