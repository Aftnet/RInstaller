#pragma once

struct mbedtls_ctr_drbg_context;
struct mbedtls_entropy_context;
struct mbedtls_pk_context;
struct mbedtls_ssl_config;
struct mbedtls_x509write_cert;
struct mbedtls_x509_crt;

namespace RInstaller
{
	namespace MbedtlsMem
	{
		class CtrDrdbgContext
		{
		private:
			mbedtls_ctr_drbg_context* p;

		public:
			CtrDrdbgContext();
			~CtrDrdbgContext();
			CtrDrdbgContext(const CtrDrdbgContext&) = delete;
			CtrDrdbgContext(CtrDrdbgContext&& other) noexcept;
			inline mbedtls_ctr_drbg_context* get() { return p; }
		};
	}
}

