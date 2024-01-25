#pragma once

#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <unordered_set>
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
	CertStore(const std::filesystem::path&);

	inline mbedtls_pk_context* GetPrivateKey() { return PrivateKey.get(); }
	inline mbedtls_x509_crt* GetCertificate() { return Certificate.get(); }

	void AddAllowedCertificate(mbedtls_x509_crt*);
	void AddDeniedCertificate(mbedtls_x509_crt*);
	bool CertificateIsAllowed(mbedtls_x509_crt*);
	bool CertificateIsDenied(mbedtls_x509_crt*);
	void ClearKnownCertificates();

private:
	class ThumbprintStore
	{
	public:
		ThumbprintStore(const std::filesystem::path&);
		bool Contains(const std::string& thumbprint) const;
		void Add(const std::string& thumbprint);
		void Clear();

	private:
		const std::filesystem::path BackingFile;
		std::unordered_set<std::string> Store;
	};

	const std::filesystem::path BackingDir;
	std::unique_ptr<mbedtls_pk_context, void(*)(mbedtls_pk_context*)> PrivateKey;
	std::unique_ptr<mbedtls_x509_crt, void(*)(mbedtls_x509_crt*)> Certificate;
	ThumbprintStore AllowedCertificates;
	ThumbprintStore DeniedCertificates;

    static mbedtls_pk_context* NewMbedTlsPkContext();
	static void FreeMbedTlsPkContext(mbedtls_pk_context*);
	static mbedtls_x509_crt* NewMbedTlsCertContext();
	static void FreeMbedTlsCertContext(mbedtls_x509_crt*);

	static std::tuple<std::vector<unsigned char>, std::vector<unsigned char>> GenerateKeyAndCertificateDer();
	void LoadPrivateKey(const std::vector<unsigned char>&);
	void LoadCertificate(const std::vector<unsigned char>&);
	static std::string GetSha1Thumbprint(const std::span<unsigned char>&);
};
