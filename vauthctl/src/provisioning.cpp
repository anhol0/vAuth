#include "provisioning.hpp"

#include "storage/authorization.hpp"

#include <cerrno>
#include <exception>
#include <fcntl.h>
#include <istream>
#include <limits>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <ostream>
#include <spawn.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

extern char** environ;

namespace vauthctl {
namespace {

constexpr std::size_t RANDOM_SIZE = 24;
constexpr std::size_t ENCODED_SIZE = 32;
constexpr std::string_view BASE64URL =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

class UniqueFd final {
public:
	explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}
	~UniqueFd() {
		if(fd_ >= 0)
			::close(fd_);
	}
	UniqueFd(const UniqueFd&) = delete;
	UniqueFd& operator=(const UniqueFd&) = delete;
	[[nodiscard]] int get() const noexcept { return fd_; }
	void close() noexcept {
		if(fd_ >= 0)
			::close(fd_);
		fd_ = -1;
	}

private:
	int fd_;
};

class TemporaryFile final {
public:
	explicit TemporaryFile(std::filesystem::path path)
		: path_(std::move(path)) {}
	~TemporaryFile() {
		if(!path_.empty())
			::unlink(path_.c_str());
	}
	TemporaryFile(const TemporaryFile&) = delete;
	TemporaryFile& operator=(const TemporaryFile&) = delete;
	[[nodiscard]] const std::filesystem::path& path() const noexcept {
		return path_;
	}
	void release() noexcept { path_.clear(); }

private:
	std::filesystem::path path_;
};

void require_success(int result, std::string_view operation) {
	if(result != 0)
		throw std::system_error(result, std::generic_category(), std::string(operation));
}

bool credential_exists(const std::filesystem::path& path) {
	struct stat status{};
	if(::lstat(path.c_str(), &status) == 0) {
		if(!S_ISREG(status.st_mode)) {
			throw std::runtime_error(
				"vauth-db-auth exists but is not a regular file"
			);
		}
		return true;
	}
	if(errno == ENOENT)
		return false;
	throw std::system_error(
		errno, std::generic_category(), "inspect vauth-db-auth"
	);
}

void ensure_credential_directory(const std::filesystem::path& path) {
	if(::mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) {
		throw std::system_error(
			errno, std::generic_category(), "create encrypted credential directory"
		);
	}
	struct stat status{};
	if(::lstat(path.c_str(), &status) != 0) {
		throw std::system_error(
			errno, std::generic_category(), "inspect encrypted credential directory"
		);
	}
	if(!S_ISDIR(status.st_mode) || status.st_uid != 0 ||
	   (status.st_mode & 0777) != 0700) {
		throw std::runtime_error(
			"Encrypted credential directory must be root-owned with mode 0700"
		);
	}
}

std::filesystem::path temporary_output_path(
	const std::filesystem::path& directory
) {
	std::string name = (directory / ".vauth-db-auth.XXXXXX").string();
	std::vector<char> writable(name.begin(), name.end());
	writable.push_back('\0');
	UniqueFd file(::mkstemp(writable.data()));
	if(file.get() < 0) {
		throw std::system_error(
			errno, std::generic_category(), "create encrypted credential temporary file"
		);
	}
	file.close();
	if(::unlink(writable.data()) != 0) {
		throw std::system_error(
			errno, std::generic_category(), "prepare encrypted credential temporary path"
		);
	}
	return writable.data();
}

void send_all(int fd, std::string_view value) {
	std::size_t offset = 0;
	while(offset < value.size()) {
		const ssize_t count = ::send(
			fd,
			value.data() + offset,
			value.size() - offset,
			MSG_NOSIGNAL
		);
		if(count < 0 && errno == EINTR)
			continue;
		if(count < 0) {
			throw std::system_error(
				errno, std::generic_category(), "send authorization to systemd-creds"
			);
		}
		if(count == 0)
			throw std::runtime_error("systemd-creds closed its input");
		offset += static_cast<std::size_t>(count);
	}
}

int wait_for(pid_t child) {
	int status = 0;
	while(::waitpid(child, &status, 0) < 0) {
		if(errno == EINTR)
			continue;
		throw std::system_error(
			errno, std::generic_category(), "wait for systemd-creds"
		);
	}
	if(WIFEXITED(status))
		return WEXITSTATUS(status);
	if(WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	throw std::runtime_error("systemd-creds ended unexpectedly");
}

void encrypt_authorization(
	const ProvisioningConfig& config,
	std::string_view authorization,
	const std::filesystem::path& outputPath
) {
	int sockets[2]{};
	if(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
		throw std::system_error(
			errno, std::generic_category(), "create systemd-creds input socket"
		);
	}
	UniqueFd childInput(sockets[0]);
	UniqueFd parentInput(sockets[1]);

	posix_spawn_file_actions_t actions{};
	bool actionsInitialized = false;
	require_success(
		::posix_spawn_file_actions_init(&actions),
		"initialize systemd-creds spawn actions"
	);
	actionsInitialized = true;
	try {
		require_success(
			::posix_spawn_file_actions_adddup2(
				&actions, childInput.get(), STDIN_FILENO
			),
			"configure systemd-creds input"
		);
		require_success(
			::posix_spawn_file_actions_addclose(&actions, parentInput.get()),
			"close systemd-creds parent socket"
		);

		std::vector<std::string> arguments{
			config.systemdCredsPath.string(),
			"encrypt",
			"--with-key=host+tpm2",
			"--name=" + std::string(CREDENTIAL_NAME),
			"-",
			outputPath.string(),
		};
		std::vector<char*> pointers;
		for(std::string& argument : arguments)
			pointers.push_back(argument.data());
		pointers.push_back(nullptr);

		pid_t child = -1;
		require_success(
			::posix_spawn(
				&child,
				config.systemdCredsPath.c_str(),
				&actions,
				nullptr,
				pointers.data(),
				environ
			),
			"start systemd-creds"
		);
		::posix_spawn_file_actions_destroy(&actions);
		actionsInitialized = false;
		childInput.close();

		std::exception_ptr sendError;
		try {
			send_all(parentInput.get(), authorization);
		} catch(...) {
			sendError = std::current_exception();
		}
		parentInput.close();
		const int result = wait_for(child);
		if(sendError)
			std::rethrow_exception(sendError);
		if(result != 0) {
			throw std::runtime_error(
				"systemd-creds failed with exit status " + std::to_string(result)
			);
		}
	} catch(...) {
		if(actionsInitialized)
			::posix_spawn_file_actions_destroy(&actions);
		throw;
	}
}

} // namespace

ProvisioningAuthorization::ProvisioningAuthorization() {
	static_assert(RANDOM_SIZE <= static_cast<std::size_t>(
		std::numeric_limits<int>::max()
	));
	std::array<unsigned char, RANDOM_SIZE> random{};
	if(RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
		OPENSSL_cleanse(random.data(), random.size());
		throw std::runtime_error("Could not generate vauth-db-auth");
	}

	std::size_t output = 0;
	for(std::size_t input = 0; input < random.size(); input += 3) {
		const unsigned int value =
			(static_cast<unsigned int>(random[input]) << 16) |
			(static_cast<unsigned int>(random[input + 1]) << 8) |
			static_cast<unsigned int>(random[input + 2]);
		bytes_[output++] = BASE64URL[(value >> 18) & 0x3f];
		bytes_[output++] = BASE64URL[(value >> 12) & 0x3f];
		bytes_[output++] = BASE64URL[(value >> 6) & 0x3f];
		bytes_[output++] = BASE64URL[value & 0x3f];
	}
	OPENSSL_cleanse(random.data(), random.size());
}

ProvisioningAuthorization::~ProvisioningAuthorization() {
	OPENSSL_cleanse(bytes_.data(), bytes_.size());
}

std::string_view ProvisioningAuthorization::view() const noexcept {
	return {bytes_.data(), ENCODED_SIZE};
}

void ensure_provisioning_authorization(
	const ProvisioningConfig& config,
	std::istream& input,
	std::ostream& output,
	bool interactive
) {
	if(::geteuid() != 0)
		throw std::runtime_error("Run provisioning as root with sudo");
	const std::filesystem::path directory =
		config.encryptedCredentialPath.parent_path();
	ensure_credential_directory(directory);
	if(credential_exists(config.encryptedCredentialPath))
		return;
	if(!interactive) {
		throw std::runtime_error(
			"First-time provisioning requires an interactive terminal"
		);
	}

	ProvisioningAuthorization authorization;
	output << "Save this vAuth authorization in a secure location:\n\n"
		   << authorization.view()
		   << "\n\nType SAVED after storing it securely: " << std::flush;
	std::array<char, 16> confirmation{};
	input.getline(confirmation.data(), confirmation.size());
	if(!input || std::string_view(confirmation.data()) != "SAVED")
		throw std::runtime_error("Provisioning cancelled");

	const std::filesystem::path temporaryPath = temporary_output_path(directory);
	TemporaryFile temporary(temporaryPath);
	encrypt_authorization(config, authorization.view(), temporaryPath);
	struct stat status{};
	if(::lstat(temporaryPath.c_str(), &status) != 0) {
		throw std::system_error(
			errno, std::generic_category(), "inspect encrypted vauth-db-auth"
		);
	}
	if(!S_ISREG(status.st_mode) || status.st_uid != 0 || status.st_nlink != 1 ||
	   status.st_size == 0) {
		throw std::runtime_error("systemd-creds produced an invalid credential file");
	}
	if(::chmod(temporaryPath.c_str(), 0600) != 0) {
		throw std::system_error(
			errno, std::generic_category(), "set vauth-db-auth permissions"
		);
	}
	if(::link(temporaryPath.c_str(), config.encryptedCredentialPath.c_str()) != 0) {
		if(errno == EEXIST)
			throw std::runtime_error("Refusing to replace existing vauth-db-auth");
		throw std::system_error(
			errno, std::generic_category(), "install vauth-db-auth"
		);
	}
	if(::unlink(temporaryPath.c_str()) != 0) {
		throw std::system_error(
			errno, std::generic_category(), "remove temporary vauth-db-auth"
		);
	}
	temporary.release();
}

} // namespace vauthctl
