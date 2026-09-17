#include "commands.hpp"
#include "const.hpp"
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
#include <string>
#include <string_view>

using sdbus::createProxy;

void check_systemd_status(sdbus::IConnection& connection) {
	std::optional<SystemdServiceState> status;
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
		if(error.getName() == "org.freedesktop.systemd1.NoSuchUnit") {
			std::cout << vauth::log::colorize(vauth::log::Color::bright_black, "● unit not loaded")
					  << '\n';
			return;
		} else
			throw;
	}

	auto unit =
		sdbus::createProxy(connection, sdbus::ServiceName{ "org.freedesktop.systemd1" }, unitPath);

	status = { .status = unit->getProperty("ActiveState")
							 .onInterface("org.freedesktop.systemd1.Unit")
							 .get<std::string>(),
			   .sub = unit->getProperty("SubState")
						  .onInterface("org.freedesktop.systemd1.Unit")
						  .get<std::string>() };

	vauth::log::Color color;

	if(status) {
		using namespace vauth::log;
		if(status->status == "failed")
			color = Color::red;
		else if(status->status == "active" && status->sub == "running")
			color = Color::green;
		else if(status->status == "inactive")
			color = Color::bright_black;
		else
			color = Color::yellow;
	} else {
		color = vauth::log::Color::red;
	}

	const std::string description =
		status ? status->status + " (" + status->sub + ")" : "unit not loaded";

	// Logging systemd status
	std::cout << vauth::log::colorize(color, std::string{ "● " } + description) << '\n';
}

bool check_unit_status(sdbus::IConnection& connection) {
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

	const auto color = has_owner ? vauth::log::Color::green : vauth::log::Color::red;

	std::cout << vauth::log::colorize(color, has_owner ? "● running" : "● not running")
			  << '\n';
	return has_owner;
}

void check_agent_connection(sdbus::IConnection& connection) {
	auto proxy =
		createProxy(connection, sdbus::ServiceName{ "org.lamellix.vAuth" }, sdbus::ObjectPath{ "/org/lamellix/vAuth" });

	bool agent_connected = false;
	try {
		proxy->callMethod("HasAvailableAgent")
			.onInterface("org.lamellix.vAuth.Status1")
			.storeResultsTo(agent_connected);
	} catch(const sdbus::Error& error) {
		if(error.getName() == "org.freedesktop.DBus.Error.ServiceUnknown") {
			std::cout << vauth::log::colorize(vauth::log::Color::red, "● daemon not running")
					  << '\n';
			return;
		} else
			throw;
	}

	const auto color = agent_connected ? vauth::log::Color::green : vauth::log::Color::red;
	std::cout << vauth::log::colorize(color, agent_connected ? "● agent connected" : "● agent not connected")
			  << "\n";
}

bool get_status(sdbus::IConnection& connection) {
	std::cout << "Daemon status: \n";
	bool running = check_unit_status(connection);
	std::cout << "SystemD service status: \n";
	check_systemd_status(connection);
	std::cout << "Agent connection status: \n";
	if(running) {
		check_agent_connection(connection);
	} else {
		std::cout << vauth::log::colorize(vauth::log::Color::red, "Daemon not running, skipping...")
				  << "\n";
	}
	return !running;
}

void provision(const std::optional<std::filesystem::path> authorizationPath) {
	StoreAuthorization authorization(store_authorization_path(authorizationPath));
	FapiStoreSecurity security(authorization.view());
	security.provision();
	std::cout << "Database key and rollback counter provisioned\n";
}

void store_clear(const std::optional<std::filesystem::path> authorizationPath) {
	StoreAuthorization authorization(store_authorization_path(authorizationPath));
	FapiStoreSecurity security(authorization.view());
	CredentialStoreLock store_lock(STORE_PATH);
	auto database_key = security.unseal_key();
	CredentialStore store(STORE_PATH, std::move(database_key), &security);
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
constexpr std::size_t CREDENTIAL_ID_HEX_SIZE = 64;

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

void print_header() {
	std::cout << std::left << std::setw(OWNER_WIDTH) << "OWNER"
			  << std::setw(RP_WIDTH) << "RP ID" << std::setw(USER_WIDTH)
			  << "USER" << std::setw(TYPE_WIDTH) << "TYPE"
			  << "CREDENTIAL ID\n";

	std::cout << std::string(OWNER_WIDTH - 1, '-') << ' '
			  << std::string(RP_WIDTH - 1, '-') << ' '
			  << std::string(USER_WIDTH - 1, '-') << ' '
			  << std::string(TYPE_WIDTH - 1, '-') << ' ' << "-------------\n";
}

} // namespace

void credential_list(
	const std::optional<std::filesystem::path> authorizationPath,
	const std::optional<uint32_t> ownerUid,
	const std::optional<std::string> rp
) {
	StoreAuthorization authorization(store_authorization_path(authorizationPath));
	FapiStoreSecurity security(authorization.view());
	CredentialStoreLock store_lock(STORE_PATH);
	auto database_key = security.unseal_key();
	CredentialStore store(STORE_PATH, std::move(database_key), &security);
	store.load();
	auto public_credential_data = store.list_credentials();

	if(ownerUid)
		std::cout << "Filtering by owner UID = " << ownerUid.value() << std::endl;
	if(rp)
		std::cout << "Filtering by Relying Party ID = " << rp.value() << std::endl;

	uint64_t counter = 0;

	for(const auto& credential : public_credential_data) {

		if(rp)
			if(credential.rpId != rp)
				continue;

		if(ownerUid)
			if(credential.ownerUid != ownerUid)
				continue;

		if(counter == 0)
			print_header();

		counter++;

		const std::string user = credential.userDisplayName.empty() ?
			credential.userName :
			credential.userDisplayName;

		std::cout
			<< std::left << std::setw(OWNER_WIDTH) << credential.ownerUid
			<< std::setw(RP_WIDTH)
			<< fit(terminal_safe(credential.rpId), RP_WIDTH - 1) << std::setw(USER_WIDTH)
			<< fit(terminal_safe(user), USER_WIDTH - 1) << std::setw(TYPE_WIDTH)
			<< (credential.discoverable ? "discoverable" : "non-discoverable")
			<< hex_encode(credential.id) << '\n';
	}
	if(counter == 0) {
		std::string message = "No credentials";
		if(rp)
			message += " with Relying Party ID: " + rp.value();
		if(ownerUid && rp)
			message += " and";
		if(ownerUid)
			message += " with Owner UID: " + std::to_string(ownerUid.value());

		message += " available\n";
		std::cout << vauth::log::colorize(vauth::log::Color::red, message);
	}
}

void erase_credential(
	const std::optional<std::filesystem::path> authorizationPath,
	const uint32_t ownerUid,
	const std::string_view credentialId
) {
	if(credentialId.size() != CREDENTIAL_ID_HEX_SIZE) {
		throw std::invalid_argument(
			"Credential ID must contain exactly 64 hexadecimal characters"
		);
	}
	auto credId = hex_decode(credentialId);

	StoreAuthorization authorization(store_authorization_path(authorizationPath));
	FapiStoreSecurity security(authorization.view());
	CredentialStoreLock store_lock(STORE_PATH);
	auto database_key = security.unseal_key();
	CredentialStore store(STORE_PATH, std::move(database_key), &security);
	store.load();
	store.erase(credId, ownerUid);
	std::cout << "Credential " << credentialId << " for user id " << ownerUid
			  << " erased" << std::endl;
}
