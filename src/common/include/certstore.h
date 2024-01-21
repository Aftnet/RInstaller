#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

class MbedtlsMgr;
struct mbedtls_entropy_context;
struct mbedtls_ctr_drbg_context;
struct mbedtls_pk_context;
struct mbedtls_x509write_cert;

class CertStore
{
public:
	CertStore(const MbedtlsMgr& mgr, const std::filesystem::path& backingDir);

private:
	const std::shared_ptr<mbedtls_entropy_context> MbedTLS_Entropy;
	const std::shared_ptr<mbedtls_ctr_drbg_context> MbedTLS_Ctr_Drdbg;
	const std::filesystem::path BackingDir;

	std::tuple<std::unique_ptr<mbedtls_pk_context, void(*)(mbedtls_pk_context*)>, std::unique_ptr<mbedtls_x509write_cert, void(*)(mbedtls_x509write_cert*)>> GenerateKeyAndCertificate();
	std::string GetSha1Thumbprint(const std::vector<unsigned char>& data);
};
