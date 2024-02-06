#pragma once

#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

class MbedtlsMgr;
struct mbedtls_entropy_context;
struct mbedtls_ctr_drbg_context;
struct mbedtls_pk_context;
struct mbedtls_ssl_config;
struct mbedtls_x509write_cert;
struct mbedtls_x509_crt;

namespace RInstaller
{
	class CertificateStore
	{
	public:
		static const std::string_view HostName;

		CertificateStore(const std::filesystem::path&);

		inline mbedtls_pk_context* GetPrivateKey() const { return PrivateKey.get(); }
		inline mbedtls_x509_crt* GetCertificate() const { return Certificate.get(); }
		inline const std::string& GetCertificateTumbprint() const { return CertificateThumbprint; }

		void ClearKnownCertificates();

		void SetupSslConfig(mbedtls_ssl_config* config, bool forServer) const;

		static int MbedTlsIOStreamInteractiveCertVerification(void*, mbedtls_x509_crt*, int, uint32_t*);
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

		static const std::string_view CaKey;
		static const std::string_view CaCert;
		std::unique_ptr<mbedtls_pk_context, void(*)(mbedtls_pk_context*)> CaPrivateKey;
		std::unique_ptr<mbedtls_x509_crt, void(*)(mbedtls_x509_crt*)> CaCertificate;
		std::string CaCertificateThumbprint;

		const std::filesystem::path BackingDir;
		std::unique_ptr<mbedtls_pk_context, void(*)(mbedtls_pk_context*)> PrivateKey;
		std::unique_ptr<mbedtls_x509_crt, void(*)(mbedtls_x509_crt*)> Certificate;
		std::string CertificateThumbprint;
		ThumbprintStore AllowedCertificates;
		ThumbprintStore DeniedCertificates;

		static mbedtls_pk_context* NewMbedTlsPkContext();
		static void FreeMbedTlsPkContext(mbedtls_pk_context*);
		static mbedtls_x509_crt* NewMbedTlsCertContext();
		static void FreeMbedTlsCertContext(mbedtls_x509_crt*);

		void LoadPrivateKey(const std::vector<unsigned char>&);
		void LoadCertificate(const std::vector<unsigned char>&);

		static std::tuple<std::vector<unsigned char>, std::vector<unsigned char>> GenerateKeyAndCertificateDer(mbedtls_pk_context*, mbedtls_x509_crt*);
		static std::string GetSha1Thumbprint(mbedtls_x509_crt*);
		static std::string GetSha1Thumbprint(const std::span<unsigned char>&);
	};
}
