#include "commands.hpp"
#include "const.hpp"
#include "credential_id.hpp"
#include "credentials/credential.hpp"
#include "cryptography/store_security.hpp"
#include "encoding/hex.hpp"
#include "log.hpp"
#include "storage/authorization.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sdbus-c++/Error.h>
#include <sdbus-c++/IConnection.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {

bool service_disappeared(const sdbus::Error& error) {
	return error.getName() == "org.freedesktop.DBus.Error.ServiceUnknown" ||
		error.getName() == "org.freedesktop.DBus.Error.NameHasNoOwner";
}

std::optional<SystemdServiceState> query_systemd_status(sdbus::IConnection& connection) {
	auto manager = sdbus::createProxy(
		connection,
		sdbus::ServiceName{ "org.freedesktop.systemd1" },
		sdbus::ObjectPath{ "/org/freedesktop/systemd1" }
	);
	sdbus::ObjectPath unitPath;
	try {
		manager->callMethod("GetUnit")
			.onInterface("org.freedesktop.systemd1.Manager")
			.withArguments(std::string{ "vauth.service" })
			.storeResultsTo(unitPath);
	} catch(const sdbus::Error& error) {
		if(error.getName() == "org.freedesktop.systemd1.NoSuchUnit")
			return std::nullopt;
		throw;
	}

	auto unit =
		sdbus::createProxy(connection, sdbus::ServiceName{ "org.freedesktop.systemd1" }, unitPath);

	return SystemdServiceState{
		.status = unit->getProperty("ActiveState")
					  .onInterface("org.freedesktop.systemd1.Unit")
					  .get<std::string>(),
		.sub = unit->getProperty("SubState")
				   .onInterface("org.freedesktop.systemd1.Unit")
				   .get<std::string>()
	};
}

bool query_daemon_status(sdbus::IConnection& connection) {
	auto proxy = sdbus::createProxy(
		connection,
		sdbus::ServiceName{ "org.freedesktop.DBus" },
		sdbus::ObjectPath{ "/org/freedesktop/DBus" }
	);

	bool has_owner = false;

	proxy->callMethod("NameHasOwner")
		.onInterface("org.freedesktop.DBus")
		.withArguments(std::string{ "org.lamellix.vAuth" })
		.storeResultsTo(has_owner);

	return has_owner;
}

std::optional<bool> query_agent_status(sdbus::IConnection& connection) {
	auto proxy =
		sdbus::createProxy(connection, sdbus::ServiceName{ "org.lamellix.vAuth" }, sdbus::ObjectPath{ "/org/lamellix/vAuth" });

	bool agent_connected = false;
	try {
		proxy->callMethod("HasAvailableAgent")
			.onInterface("org.lamellix.vAuth.Status1")
			.storeResultsTo(agent_connected);
	} catch(const sdbus::Error& error) {
		if(service_disappeared(error))
			return std::nullopt;
		throw;
	}
	return agent_connected;
}

vauth::log::Color systemd_status_color(const std::optional<SystemdServiceState>& status) {
	using vauth::log::Color;
	if(!status || status->status == "inactive")
		return Color::bright_black;
	if(status->status == "failed")
		return Color::red;
	if(status->status == "active" && status->sub == "running")
		return Color::green;
	return Color::yellow;
}

} // namespace

StatusReport collect_status(const StatusQueries& queries) {
	StatusReport report;
	report.daemonRunning  = queries.daemonRunning();
	report.systemdService = queries.systemdService();
	if(!report.daemonRunning)
		return report;

	const auto agent_available = queries.agentAvailable();
	if(!agent_available) {
		report.daemonRunning = false;
		return report;
	}
	report.agentAvailable = *agent_available;
	return report;
}

int print_status(const StatusReport& report, std::ostream& output) {
	using vauth::log::Color;

	output << "Daemon status:\n"
		   << vauth::log::colorize(
				  report.daemonRunning ? Color::green : Color::red,
				  report.daemonRunning ? "● running" : "● not running"
			  )
		   << "\nSystemd service status:\n";

	if(report.systemdService) {
		const auto& state = *report.systemdService;
		output << vauth::log::colorize(
			systemd_status_color(report.systemdService),
			"● " + state.status + " (" + state.sub + ")"
		);
	} else {
		output << vauth::log::colorize(Color::bright_black, "● unit not loaded");
	}

	output << "\nUI agent status:\n";
	if(!report.daemonRunning) {
		output << vauth::log::colorize(Color::red, "● unavailable (daemon not running)");
	} else if(!report.agentAvailable) {
		output << vauth::log::colorize(Color::red, "● status unavailable");
	} else {
		output << vauth::log::colorize(
			*report.agentAvailable ? Color::green : Color::red,
			*report.agentAvailable ? "● agent connected" : "● agent not connected"
		);
	}
	output << '\n';
	return report.daemonRunning ? 0 : 1;
}

int get_status(sdbus::IConnection& connection) {
	const StatusQueries queries{
		.daemonRunning =
			[&connection] { return query_daemon_status(connection); },
		.systemdService =
			[&connection] { return query_systemd_status(connection); },
		.agentAvailable =
			[&connection] { return query_agent_status(connection); },
	};
	return print_status(collect_status(queries), std::cout);
}

void provision(const std::optional<std::filesystem::path> authorizationPath) {
	StoreAuthorization authorization(store_authorization_path(authorizationPath));
	FapiStoreSecurity security(authorization.view());
	security.provision();
	std::cout << "Database key and rollback counter provisioned\n";
}

void store_clear(const std::optional<std::filesystem::path> authorizationPath) {
	store_clear(authorizationPath, STORE_PATH);
}

void store_clear(const std::optional<std::filesystem::path> authorizationPath, const std::filesystem::path& storePath) {
	StoreAuthorization authorization(store_authorization_path(authorizationPath));
	FapiStoreSecurity security(authorization.view());
	CredentialStoreLock store_lock(storePath);
	auto database_key = security.unseal_key();
	CredentialStore store(storePath, std::move(database_key), &security);
	store.load();
	store.clear();
	std::cout << "Credential store cleared; TPM security objects "
				 "preserved\n";
}

namespace {

constexpr int OWNER_WIDTH = 8;
constexpr int RP_WIDTH	  = 32;
constexpr int USER_WIDTH  = 24;
constexpr int TYPE_WIDTH  = 18;

std::string terminal_safe(std::string_view input) {
	std::string output;
	output.reserve(input.size());

	for(const unsigned char byte : input) {
		// Prevent newlines, tabs, ANSI escapes, and other controls.
		if(byte < 0x20 || byte == 0x7f)
			output.push_back('?');
		else
			output.push_back(static_cast<char>(byte));
	}

	return output;
}

std::string fit(std::string text, std::size_t width) {
	if(text.size() <= width)
		return text;

	if(width <= 3)
		return text.substr(0, width);

	text.resize(width - 3);
	text += "...";
	return text;
}

void print_header(std::ostream& output) {
	output << std::left << std::setw(OWNER_WIDTH) << "OWNER" << std::setw(RP_WIDTH)
		   << "RP ID" << std::setw(USER_WIDTH) << "USER" << std::setw(TYPE_WIDTH) << "TYPE"
		   << "CREDENTIAL ID\n";

	output << std::string(OWNER_WIDTH - 1, '-') << ' '
		   << std::string(RP_WIDTH - 1, '-') << ' ' << std::string(USER_WIDTH - 1, '-')
		   << ' ' << std::string(TYPE_WIDTH - 1, '-') << ' ' << "-------------\n";
}

} // namespace

void print_credentials(
	std::span<const CredentialSummary> credentials,
	const std::optional<uint32_t>& ownerUid,
	const std::optional<std::string>& rp,
	std::ostream& output
) {
	if(ownerUid)
		output << "Filtering by owner UID = " << *ownerUid << '\n';
	if(rp)
		output << "Filtering by Relying Party ID = " << terminal_safe(*rp) << '\n';

	std::size_t count = 0;
	for(const auto& credential : credentials) {
		if(rp && credential.rpId != *rp)
			continue;
		if(ownerUid && credential.ownerUid != *ownerUid)
			continue;

		if(count++ == 0)
			print_header(output);

		const std::string& user = credential.userDisplayName.empty() ?
			credential.userName :
			credential.userDisplayName;

		output << std::left << std::setw(OWNER_WIDTH) << credential.ownerUid
			   << std::setw(RP_WIDTH)
			   << fit(terminal_safe(credential.rpId), RP_WIDTH - 1)
			   << std::setw(USER_WIDTH)
			   << fit(terminal_safe(user), USER_WIDTH - 1) << std::setw(TYPE_WIDTH)
			   << (credential.discoverable ? "discoverable" : "non-discoverable")
			   << hex_encode(credential.id) << '\n';
	}

	if(count != 0)
		return;

	std::string message = "No credentials";
	if(rp)
		message += " with Relying Party ID: " + terminal_safe(*rp);
	if(ownerUid && rp)
		message += " and";
	if(ownerUid)
		message += " with Owner UID: " + std::to_string(*ownerUid);
	message += " available\n";
	output << vauth::log::colorize(vauth::log::Color::red, message);
}

std::vector<uint8_t> decode_credential_id(std::string_view credentialId) {
	if(!vauthctl::valid_credential_id_hex_length(credentialId.size())) {
		throw std::invalid_argument("Credential ID must contain between 32 and "
									"2048 hexadecimal "
									"characters and have an even length");
	}
	return hex_decode(credentialId);
}

void credential_list(
	const std::optional<std::filesystem::path> authorizationPath,
	const std::optional<uint32_t> ownerUid,
	const std::optional<std::string> rp
) {
	credential_list(authorizationPath, ownerUid, rp, STORE_PATH);
}

void credential_list(
	const std::optional<std::filesystem::path> authorizationPath,
	const std::optional<uint32_t> ownerUid,
	const std::optional<std::string> rp,
	const std::filesystem::path& storePath
) {
	StoreAuthorization authorization(store_authorization_path(authorizationPath));
	FapiStoreSecurity security(authorization.view());
	CredentialStoreLock store_lock(storePath);
	auto database_key = security.unseal_key();
	CredentialStore store(storePath, std::move(database_key), &security);
	store.load();
	const auto credentials = store.list_credentials();
	print_credentials(credentials, ownerUid, rp, std::cout);
}

void erase_credential(
	const std::optional<std::filesystem::path> authorizationPath,
	const uint32_t ownerUid,
	const std::string_view credentialId
) {
	erase_credential(authorizationPath, ownerUid, credentialId, STORE_PATH);
}

void erase_credential(
	const std::optional<std::filesystem::path> authorizationPath,
	const uint32_t ownerUid,
	const std::string_view credentialId,
	const std::filesystem::path& storePath
) {
	auto credId = decode_credential_id(credentialId);

	StoreAuthorization authorization(store_authorization_path(authorizationPath));
	FapiStoreSecurity security(authorization.view());
	CredentialStoreLock store_lock(storePath);
	auto database_key = security.unseal_key();
	CredentialStore store(storePath, std::move(database_key), &security);
	store.load();
	store.erase(credId, ownerUid);
	std::cout << "Credential " << credentialId << " for user id " << ownerUid
			  << " erased" << std::endl;
}
