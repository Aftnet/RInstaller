#include "mbedtlsmgr.h"

#include <stdexcept>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

MbedtlsMgr::MbedtlsMgr()
{
	MbedTLS_Entropy = std::shared_ptr<mbedtls_entropy_context>(new mbedtls_entropy_context, [](auto d) { mbedtls_entropy_free(d); });
	mbedtls_entropy_init(MbedTLS_Entropy.get());

	MbedTLS_Ctr_Drdbg = std::shared_ptr<mbedtls_ctr_drbg_context>(new mbedtls_ctr_drbg_context, [](auto d) { mbedtls_ctr_drbg_free(d); });
	mbedtls_ctr_drbg_init(MbedTLS_Ctr_Drdbg.get());
	if (mbedtls_ctr_drbg_seed(MbedTLS_Ctr_Drdbg.get(), mbedtls_entropy_func, MbedTLS_Entropy.get(), (const unsigned char*)"RANDOM_GEN", 10))
	{
		throw std::runtime_error("Failed initializing drdbg");
	}
}
