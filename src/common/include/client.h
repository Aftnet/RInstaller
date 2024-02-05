#pragma once

#ifdef __cplusplus

#include "certstore.h"
#include <filesystem>

namespace RInstaller
{
	class MbedtlsMgr;

	class Client
	{
	private:
		MbedtlsMgr& TlsMgr;
		CertificateStore CertStore;

	public:
		Client(const std::filesystem::path&);
	};
}
#endif

#ifdef __cplusplus
extern "C"
{
#endif
	class rinst_client_c;
	typedef rinst_client_c* rinst_client;

	rinst_client rinst_client_get(const char*);

	void rinst_client_free(rinst_client);

#ifdef __cplusplus
}
#endif
