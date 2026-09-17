#include "options.hpp"
#include "credential_id.hpp"

#include <CLI/CLI.hpp>

#include <utility>

namespace {

constexpr int USAGE_ERROR_EXIT_CODE = 2;

bool is_hex_digit(char digit) {
	return (digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f') ||
		(digit >= 'A' && digit <= 'F');
}

CLI::Validator credential_id_validator() {
	return CLI::Validator{
		[](std::string& value) {
			if(!vauthctl::valid_credential_id_hex_length(value.size())) {
				return std::string{ "Credential ID must contain between 32 and "
									"2048 hexadecimal "
									"characters and have an even length" };
			}
			for(const char digit : value) {
				if(!is_hex_digit(digit))
					return std::string{ "Credential ID contains a "
										"non-hexadecimal character" };
			}
			return std::string{};
		},
		"32 to 2048 hexadecimal characters with an even length"
	};
}

} // namespace

ParseResult parse_options(int argc, char** argv) {
	CLI::App app{ "Manage the vAuth authenticator" };
	app.require_subcommand(1);
	app.fallthrough();

	Options options;

	auto* status = app.add_subcommand("status", "Check status of the vauth daemon");
	auto* provision =
		app.add_subcommand("provision", "Create the database key and rollback counter");
	provision->add_option("--auth-file", options.authorizationPath, "Database authorization file");

	auto* credentials = app.add_subcommand("credentials", "Manage stored credentials");
	credentials->require_subcommand(1);

	auto* list = credentials->add_subcommand("list", "List credential metadata");
	list->add_option("--owner", options.ownerUid, "Filter by owner UID");
	list->add_option("--rp", options.rpId, "Filter by relying-party ID");
	list->add_option("--auth-file", options.authorizationPath, "Database authorization file");

	auto* remove = credentials->add_subcommand("delete", "Delete one credential");
	remove->add_option("--owner", options.ownerUid, "Credential owner UID")->required();
	remove
		->add_option("--id", options.credentialId, "Credential ID in hexadecimal")
		->check(credential_id_validator())
		->required();
	remove->add_option("--auth-file", options.authorizationPath, "Database authorization file");

	auto* clear = credentials->add_subcommand("clear", "Delete every stored credential");
	clear
		->add_flag("--confirm-destroy-all", options.confirmedDestroyAll, "Confirm deletion of every stored credential")
		->required()
		->disable_flag_override();
	clear->add_option("--auth-file", options.authorizationPath, "Database authorization file");

	try {
		app.parse(argc, argv);
	} catch(const CLI::ParseError& error) {
		const int cliExitCode = app.exit(error);
		return ParseResult{
			.options  = std::nullopt,
			.exitCode = cliExitCode == 0 ? 0 : USAGE_ERROR_EXIT_CODE,
		};
	}

	if(*status) {
		options.command = Command::status;
	} else if(*provision) {
		options.command = Command::provision;
	} else if(*list) {
		options.command = Command::credentialsList;
	} else if(*remove) {
		options.command = Command::credentialsDelete;
	} else if(*clear) {
		options.command = Command::credentialsClear;
	}

	return ParseResult{
		.options  = std::move(options),
		.exitCode = 0,
	};
}
