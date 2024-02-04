#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtlsmgr.h"
#include <format>
#include <iostream>
#include <stdexcept>

namespace
{
	constexpr int MbedTLSDebugLevel = 1;
}

MbedtlsMgr::MbedtlsMgr():
	MbedTLS_Entropy(new mbedtls_entropy_context, [](auto d) { mbedtls_entropy_free(d); delete(d); }),
	MbedTLS_Ctr_Drdbg(new mbedtls_ctr_drbg_context, [](auto d) { mbedtls_ctr_drbg_free(d); delete(d); })
{
	mbedtls_debug_set_threshold(MbedTLSDebugLevel);
	mbedtls_entropy_init(MbedTLS_Entropy.get());
	mbedtls_ctr_drbg_init(MbedTLS_Ctr_Drdbg.get());
	if (auto ret = mbedtls_ctr_drbg_seed(MbedTLS_Ctr_Drdbg.get(), mbedtls_entropy_func, MbedTLS_Entropy.get(), (const unsigned char*)"RANDOM_GEN", 10); ret != 0)
	{
		throw std::runtime_error("Failed initializing drdbg");
	}

#if defined(MBEDTLS_USE_PSA_CRYPTO)
	if (auto ret = sa_crypto_init(); ret != 0)
	{
		throw std::runtime_error("Failed initializing PSA crypto");
	}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

}

void MbedtlsMgr::DebugPrint(void* ctx, int level, const char* file, int line, const char* str)
{
	std::cout << file << line << str << std::endl;
}
