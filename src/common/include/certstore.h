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
struct mbedtls_x509_crt;

class CertStore
{
public:
	CertStore(const std::filesystem::path& backingDir);

private:
	const std::filesystem::path BackingDir;
	std::unique_ptr<mbedtls_pk_context, void(*)(mbedtls_pk_context*)> PrivateKey;
	std::unique_ptr<mbedtls_x509_crt, void(*)(mbedtls_x509_crt*)> Certificate;

    static mbedtls_pk_context* NewMbedTlsPkContext();
	static void FreeMbedTlsPkContext(mbedtls_pk_context*);
	static mbedtls_x509_crt* NewMbedTlsCertContext();
	static void FreeMbedTlsCertContext(mbedtls_x509_crt*);

	static std::tuple<std::vector<unsigned char>, std::vector<unsigned char>> GenerateKeyAndCertificateDer();
	void LoadPrivateKey(const std::vector<unsigned char>&);
	void LoadCertificate(const std::vector<unsigned char>&);
	std::string GetSha1Thumbprint(const std::vector<unsigned char>&);
};
