#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <cerrno>
#include <sys/stat.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "commands.hpp"
#include "credentials/credential.hpp"
#include "cryptography/store_security.hpp"
#include "cryptography/tpm.hpp"
#include "encoding/hex.hpp"
#include "test_runner.hpp"

namespace {

constexpr uint32_t TEST_OWNER_UID = 1000;

struct PkeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept {
        EVP_PKEY_free(key);
    }
};

struct PkeyContextDeleter {
    void operator()(EVP_PKEY_CTX* context) const noexcept {
        EVP_PKEY_CTX_free(context);
    }
};

using Pkey = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using PkeyContext = std::unique_ptr<EVP_PKEY_CTX, PkeyContextDeleter>;

void write_authorization_file(
    const std::filesystem::path& path,
    std::string_view authorization
) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(
        authorization.data(),
        static_cast<std::streamsize>(authorization.size())
    );
    output.close();
    if(!output) {
        throw std::runtime_error("Could not write test authorization file");
    }
    if(::chmod(path.c_str(), 0400) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "chmod test authorization file"
        );
    }
}

std::vector<uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    const auto end = input.tellg();
    if(end < 0)
        throw std::runtime_error("Could not size test store file");
    std::vector<uint8_t> contents(static_cast<std::size_t>(end));
    input.seekg(0);
    input.read(
        reinterpret_cast<char*>(contents.data()),
        static_cast<std::streamsize>(contents.size())
    );
    if(!input)
        throw std::runtime_error("Could not read test store file");
    return contents;
}

void write_file(
    const std::filesystem::path& path,
    const std::vector<uint8_t>& contents
) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(
        reinterpret_cast<const char*>(contents.data()),
        static_cast<std::streamsize>(contents.size())
    );
    output.close();
    if(!output)
        throw std::runtime_error("Could not write test store file");
}

template<typename Function>
std::string capture_output(Function&& function) {
    std::ostringstream output;
    auto* previous = std::cout.rdbuf(output.rdbuf());
    try {
        function();
    } catch(...) {
        std::cout.rdbuf(previous);
        throw;
    }
    std::cout.rdbuf(previous);
    return output.str();
}

template<typename Exception, typename Function>
std::string expect_rejected(Function&& function, const char* message) {
    try {
        function();
    } catch(const Exception& error) {
        return error.what();
    }
    throw std::runtime_error(message);
}

void verify_signature(
    const CredentialKey& key,
    const std::array<uint8_t, 32>& digest,
    const std::vector<uint8_t>& signature_bytes
) {
    const auto coordinates = extractPublic(key.publicBlob);
    std::array<uint8_t, 65> encoded_point{};
    encoded_point[0] = 0x04;
    std::copy(
        coordinates[0].begin(),
        coordinates[0].end(),
        encoded_point.begin() + 33 - coordinates[0].size()
    );
    std::copy(
        coordinates[1].begin(),
        coordinates[1].end(),
        encoded_point.begin() + 65 - coordinates[1].size()
    );
    std::array<char, 11> group_name{
        'p', 'r', 'i', 'm', 'e', '2', '5', '6', 'v', '1', '\0'
    };
    OSSL_PARAM parameters[]{
        OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME,
            group_name.data(),
            0
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            encoded_point.data(),
            encoded_point.size()
        ),
        OSSL_PARAM_construct_end()
    };

    PkeyContext import_context(
        EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)
    );
    EVP_PKEY* public_key_raw = nullptr;
    if(
        !import_context ||
        EVP_PKEY_fromdata_init(import_context.get()) != 1 ||
        EVP_PKEY_fromdata(
            import_context.get(),
            &public_key_raw,
            EVP_PKEY_PUBLIC_KEY,
            parameters
        ) != 1
    ) {
        throw std::runtime_error("Could not import test credential public key");
    }
    Pkey public_key(public_key_raw);
    PkeyContext verify_context(EVP_PKEY_CTX_new(public_key.get(), nullptr));
    if(
        !verify_context ||
        EVP_PKEY_verify_init(verify_context.get()) != 1 ||
        EVP_PKEY_CTX_set_signature_md(
            verify_context.get(), EVP_sha256()
        ) != 1 ||
        EVP_PKEY_verify(
            verify_context.get(),
            signature_bytes.data(),
            signature_bytes.size(),
            digest.data(),
            digest.size()
        ) != 1
    ) {
        throw std::runtime_error("TPM credential signature verification failed");
    }
}

std::vector<TPM2_HANDLE> persistent_handles(TSS2_TCTI_CONTEXT* tcti) {
    TpmCtx context(tcti);
    TPMI_YES_NO more_data = TPM2_NO;
    TPMS_CAPABILITY_DATA* capability_raw = nullptr;
    const TSS2_RC result = Esys_GetCapability(
        context.ctx,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        TPM2_CAP_HANDLES,
        TPM2_PERSISTENT_FIRST,
        TPM2_MAX_CAP_HANDLES,
        &more_data,
        &capability_raw
    );
    EsysUniquePtr<TPMS_CAPABILITY_DATA> capability(capability_raw);
    if(result != TSS2_RC_SUCCESS || capability == nullptr) {
        throw std::runtime_error("Could not enumerate persistent TPM handles");
    }
    if(more_data != TPM2_NO) {
        throw std::runtime_error("Persistent TPM handle test result was truncated");
    }

    const auto& handles = capability->data.handles;
    return {
        handles.handle,
        handles.handle + handles.count
    };
}

void test_transient_credential_parent(
    FapiStoreSecurity& security,
    const std::vector<uint8_t>& master_key
) {
    const auto before = persistent_handles(security.tcti());
    const std::vector<uint8_t> credential_id(32, 0xA7);
    const std::array<uint8_t, 32> digest{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    CredentialKey key;

    {
        CredentialKeyProvider provider(security.tcti(), master_key);
        key = provider.create(credential_id);
        verify_signature(
            key,
            digest,
            provider.sign(
                credential_id,
                digest,
                key.publicBlob,
                key.privateBlob
            )
        );

        auto wrong_id = credential_id;
        wrong_id.back() ^= 0x01;
        bool wrong_authorization_rejected = false;
        try {
            (void)provider.sign(
                wrong_id,
                digest,
                key.publicBlob,
                key.privateBlob
            );
        } catch(const std::exception&) {
            wrong_authorization_rejected = true;
        }
        if(!wrong_authorization_rejected) {
            throw std::runtime_error(
                "Credential key accepted authorization for a different ID"
            );
        }

        const auto expect_rejected = [](auto&& operation, const char* message) {
            try {
                operation();
            } catch(const std::exception&) {
                return;
            }
            throw std::runtime_error(message);
        };
        auto malformed_public = key.publicBlob;
        malformed_public.push_back(0);
        expect_rejected(
            [&] {
                (void)provider.sign(
                    credential_id,
                    digest,
                    malformed_public,
                    key.privateBlob
                );
            },
            "Credential public blob trailing data was accepted"
        );
        auto malformed_private = key.privateBlob;
        malformed_private.push_back(0);
        expect_rejected(
            [&] {
                (void)provider.sign(
                    credential_id,
                    digest,
                    key.publicBlob,
                    malformed_private
                );
            },
            "Credential private blob trailing data was accepted"
        );
        const std::array<uint8_t, 31> short_digest{};
        expect_rejected(
            [&] {
                (void)provider.sign(
                    credential_id,
                    short_digest,
                    key.publicBlob,
                    key.privateBlob
                );
            },
            "Non-SHA-256 credential digest size was accepted"
        );
    }

    {
        CredentialKeyProvider restarted(security.tcti(), master_key);
        verify_signature(
            key,
            digest,
            restarted.sign(
                credential_id,
                digest,
                key.publicBlob,
                key.privateBlob
            )
        );
    }

    {
        auto wrong_master = master_key;
        wrong_master.front() ^= 0x01;
        CredentialKeyProvider wrong_provider(security.tcti(), wrong_master);
        bool wrong_parent_rejected = false;
        try {
            (void)wrong_provider.sign(
                credential_id,
                digest,
                key.publicBlob,
                key.privateBlob
            );
        } catch(const std::exception&) {
            wrong_parent_rejected = true;
        }
        if(!wrong_parent_rejected) {
            throw std::runtime_error(
                "Credential blob loaded under a different derived parent"
            );
        }
    }

    const auto after = persistent_handles(security.tcti());
    if(after != before) {
        throw std::runtime_error(
            "Credential provider changed the persistent TPM handle set"
        );
    }
}

StoredCredential make_credential() {
    return StoredCredential{
        .id = std::vector<uint8_t>(16, 0x71),
        .ownerUid = TEST_OWNER_UID,
        .rpId = "example.com",
        .userId = {0x01},
        .userName = "alice",
        .userDisplayName = "Alice",
        .alg = -7,
        .signCount = 0,
        .private_blob = {0x02},
        .public_blob = {0x03}
    };
}

void setup(
    const std::filesystem::path& store_path,
    const std::string& authorization,
    const std::string& wrong_authorization
) {
    const auto authorization_path = store_path.parent_path() / "authorization";
    const auto wrong_authorization_path =
        store_path.parent_path() / "wrong-authorization";
    write_authorization_file(authorization_path, authorization);
    write_authorization_file(wrong_authorization_path, wrong_authorization);

    capture_output([&] {
        provision(authorization_path, store_path);
    });
    expect_rejected<std::exception>(
        [&] { provision(authorization_path, store_path); },
        "Duplicate provisioning was accepted"
    );

    FapiStoreSecurity security(authorization);
    if(security.read() != 0) {
        throw std::runtime_error("New rollback counter is not zero");
    }

    const auto master_key = security.unseal_key();
    test_transient_credential_parent(security, master_key);

    {
        CredentialStore store(
            store_path,
            master_key,
            &security
        );
        store.load();
        store.put(make_credential(), TEST_OWNER_UID);
    }
    if(security.read() != 1) {
        throw std::runtime_error("Rollback counter did not advance");
    }

    const auto credential_id = hex_encode(make_credential().id);
    const std::string listed = capture_output([&] {
        credential_list(
            authorization_path,
            std::nullopt,
            std::nullopt,
            store_path
        );
    });
    if(
        listed.find("example.com") == std::string::npos ||
        listed.find(credential_id) == std::string::npos
    ) {
        throw std::runtime_error("vauthctl did not list the stored credential");
    }

    const std::string wrong_authorization_error =
        expect_rejected<std::exception>(
            [&] {
                credential_list(
                    wrong_authorization_path,
                    std::nullopt,
                    std::nullopt,
                    store_path
                );
            },
            "vauthctl accepted the wrong store authorization"
        );
    if(wrong_authorization_error.find(wrong_authorization) != std::string::npos) {
        throw std::runtime_error(
            "Store authorization was exposed in an error message"
        );
    }

    {
        CredentialStoreLock held_lock(store_path);
        expect_rejected<std::runtime_error>(
            [&] {
                credential_list(
                    authorization_path,
                    std::nullopt,
                    std::nullopt,
                    store_path
                );
            },
            "vauthctl ignored credential-store lock contention"
        );
    }

    expect_rejected<std::out_of_range>(
        [&] {
            erase_credential(
                authorization_path,
                TEST_OWNER_UID + 1,
                credential_id,
                store_path
            );
        },
        "vauthctl deleted a credential owned by a different user"
    );
    if(security.read() != 1) {
        throw std::runtime_error(
            "Wrong-owner deletion changed rollback counter"
        );
    }

    capture_output([&] {
        erase_credential(
            authorization_path,
            TEST_OWNER_UID,
            credential_id,
            store_path
        );
    });
    if(security.read() != 2) {
        throw std::runtime_error("Credential deletion did not advance rollback counter");
    }

    {
        CredentialStore reader(
            store_path,
            security.unseal_key(),
            &security
        );
        reader.load();
        if(reader.has(make_credential().id, TEST_OWNER_UID)) {
            throw std::runtime_error("Credential remained after vauthctl deletion");
        }
    }

    expect_rejected<std::out_of_range>(
        [&] {
            erase_credential(
                authorization_path,
                TEST_OWNER_UID,
                credential_id,
                store_path
            );
        },
        "vauthctl accepted deletion of a missing credential"
    );
    if(security.read() != 2) {
        throw std::runtime_error(
            "Failed credential deletion changed rollback counter"
        );
    }

    {
        CredentialStore writer(
            store_path,
            security.unseal_key(),
            &security
        );
        writer.load();
        writer.put(make_credential(), TEST_OWNER_UID);
    }
    if(security.read() != 3) {
        throw std::runtime_error("Credential replacement did not advance rollback counter");
    }

    capture_output([&] {
        store_clear(authorization_path, store_path);
    });
    if(security.read() != 4) {
        throw std::runtime_error("vauthctl clear did not advance rollback counter");
    }
    if(security.unseal_key() != master_key) {
        throw std::runtime_error("vauthctl clear replaced the sealed database key");
    }
    {
        CredentialStore reader(
            store_path,
            security.unseal_key(),
            &security
        );
        reader.load();
        if(reader.has(make_credential().id, TEST_OWNER_UID)) {
            throw std::runtime_error("Credential remained after vauthctl clear");
        }
    }

    const std::string empty_listing = capture_output([&] {
        credential_list(
            authorization_path,
            std::nullopt,
            std::nullopt,
            store_path
        );
    });
    if(empty_listing.find("No credentials available") == std::string::npos) {
        throw std::runtime_error("vauthctl did not report the cleared store as empty");
    }

    if(::chmod(store_path.c_str(), 0640) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "chmod test store file"
        );
    }
    expect_rejected<std::runtime_error>(
        [&] {
            credential_list(
                authorization_path,
                std::nullopt,
                std::nullopt,
                store_path
            );
        },
        "vauthctl accepted insecure credential-store permissions"
    );
    if(::chmod(store_path.c_str(), 0600) != 0) {
        throw std::system_error(
            errno,
            std::generic_category(),
            "restore test store permissions"
        );
    }

    const auto good_store = read_file(store_path);
    auto corrupt_store = good_store;
    corrupt_store.back() ^= 0x01;
    write_file(store_path, corrupt_store);
    expect_rejected<std::runtime_error>(
        [&] {
            credential_list(
                authorization_path,
                std::nullopt,
                std::nullopt,
                store_path
            );
        },
        "vauthctl accepted a corrupt credential store"
    );
    write_file(store_path, good_store);

    const auto missing_store_backup = store_path.string() + ".backup";
    std::filesystem::rename(store_path, missing_store_backup);
    expect_rejected<std::runtime_error>(
        [&] {
            credential_list(
                authorization_path,
                std::nullopt,
                std::nullopt,
                store_path
            );
        },
        "vauthctl accepted a missing store with a nonzero rollback counter"
    );
    std::filesystem::rename(missing_store_backup, store_path);

    capture_output([&] {
        credential_list(
            authorization_path,
            std::nullopt,
            std::nullopt,
            store_path
        );
    });
    if(security.read() != 4) {
        throw std::runtime_error("Failed vauthctl operations changed rollback counter");
    }
}

void verify_tpm_clear_is_rejected(const std::string& authorization) {
    bool rejected = false;
    try {
        FapiStoreSecurity security(authorization);
        (void)security.unseal_key();
    } catch(const std::exception&) {
        rejected = true;
    }
    if(!rejected) {
        throw std::runtime_error("TPM clear did not invalidate the sealed key");
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        if(argc < 3) {
            throw std::invalid_argument("Missing integration test arguments");
        }
        const std::string mode = argv[1];
        test_support::Runner runner;
        if(mode == "setup" && argc == 5) {
            runner.run("setup", [&] {
                setup(argv[2], argv[3], argv[4]);
            });
        } else if(mode == "verify-tpm-clear" && argc == 3) {
            runner.run("verify_tpm_clear_is_rejected", [&] {
                verify_tpm_clear_is_rejected(argv[2]);
            });
        } else {
            throw std::invalid_argument("Invalid integration test arguments");
        }
        return runner.finish();
    } catch(const std::exception& error) {
        std::cerr << "Test invocation failed: " << error.what() << '\n';
        return 1;
    }
}
