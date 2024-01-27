#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtlsmgr.h"
#include <format>
#include <stdexcept>

MbedtlsMgr::MbedtlsMgr():
	MbedTLS_Entropy(new mbedtls_entropy_context, [](auto d) { mbedtls_entropy_free(d); delete(d); }),
	MbedTLS_Ctr_Drdbg(new mbedtls_ctr_drbg_context, [](auto d) { mbedtls_ctr_drbg_free(d); delete(d); })
{
	mbedtls_entropy_init(MbedTLS_Entropy.get());
	mbedtls_ctr_drbg_init(MbedTLS_Ctr_Drdbg.get());
	if (auto ret = mbedtls_ctr_drbg_seed(MbedTLS_Ctr_Drdbg.get(), mbedtls_entropy_func, MbedTLS_Entropy.get(), (const unsigned char*)"RANDOM_GEN", 10); ret != 0)
	{
		throw std::runtime_error("Failed initializing drdbg");
	}
}
