#include "mbedtlsmem.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

using namespace RInstaller::MbedtlsMem;

CtrDrdbgContext::CtrDrdbgContext() :
	p(new mbedtls_ctr_drbg_context)
{
	mbedtls_ctr_drbg_init(p);
}

CtrDrdbgContext::~CtrDrdbgContext()
{
	mbedtls_ctr_drbg_free(p);
	delete p;
}

CtrDrdbgContext::CtrDrdbgContext(CtrDrdbgContext&& other) noexcept
{
	auto tmp = p;
	p = other.p;
	other.p = tmp;
}
