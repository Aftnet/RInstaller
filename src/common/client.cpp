#include "client.h"

#include "certstore.h"
#include "mbedtlsmgr.h"

using namespace RInstaller;

Client::Client(const std::filesystem::path& appDataPath) :
	TlsMgr(MbedtlsMgr::GetInstance()),
	CertStore(appDataPath)
{

}

rinst_client rinst_client_get(const char* appDataPath)
{
	return reinterpret_cast<rinst_client>(new Client(std::filesystem::path(appDataPath)));
}

void rinst_client_free(rinst_client c)
{
	auto client = reinterpret_cast<Client*>(c);
	delete client;
}
