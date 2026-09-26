#include "provisioning.hpp"
#include "test_runner.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>

namespace {

void test_generated_authorization() {
	constexpr std::string_view alphabet =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	std::unordered_set<std::string> generated;
	for(unsigned int index = 0; index < 128; ++index) {
		vauthctl::ProvisioningAuthorization authorization;
		if(authorization.view().size() != 32) {
			throw std::runtime_error("Generated authorization has the wrong size");
		}
		if(!std::all_of(
			   authorization.view().begin(),
			   authorization.view().end(),
			   [alphabet](char byte) {
				   return alphabet.find(byte) != std::string_view::npos;
			   }
		   )) {
			throw std::runtime_error("Generated authorization is not Base64URL");
		}
		generated.emplace(authorization.view());
	}
	if(generated.size() != 128)
		throw std::runtime_error("Generated duplicate authorizations");
}

} // namespace

int main() {
	test_support::Runner runner;
	runner.run("generated 192-bit authorization", test_generated_authorization);
	return runner.finish();
}
