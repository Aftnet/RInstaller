#include "client.h"

#include "certstore.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtlsmgr.h"
#include "protocol.h"

using namespace RInstaller;
using namespace std;

Client::Client(const filesystem::path& appDataPath) :
    Busy(false),
    CancelRequested(false),
	TlsMgr(MbedtlsMgr::GetInstance()),
	CertStore(appDataPath),
    Socket(nullptr, [](mbedtls_net_context* d) { mbedtls_net_close(d); mbedtls_net_free(d); delete d; })
{

}

Client::Result Client::Connect(const string& hostname, const std::chrono::milliseconds& timeoutMs)
{
    if (Socket.get() != nullptr)
    {
        return Result::AlreadyConnected;
    }
    if (Busy)
    {
        return Result::Busy;
    }

    Socket.reset(new mbedtls_net_context);
    mbedtls_net_init(Socket.get());

    TimeoutBase = chrono::steady_clock::now();
    for (;;)
    {
        switch (mbedtls_net_connect(Socket.get(), hostname.c_str(), to_string(PortNumber).c_str(), MBEDTLS_NET_PROTO_TCP))
        {
        case MbedTlsOk:
        {
            return Result::Ok;
        }
        case MBEDTLS_ERR_NET_UNKNOWN_HOST:
        {
            Socket.reset();
            return Result::HostNotResolvable;
        }
        case MBEDTLS_ERR_NET_CONNECT_FAILED:
        {
            auto now = chrono::steady_clock::now();
            auto lol = now - TimeoutBase;
            if (now - TimeoutBase > timeoutMs || CancelRequested)
            {
                Socket.reset();
                return Result::HostNotConnectable;
            }

            continue;
        }
        default:
        {
            break;
        }
        }
    }

    Socket.reset();
    return Result::OtherError;
}

Client::Result Client::Disconnect()
{
    if (Busy)
    {
        return Result::Busy;
    }

    Socket.reset();
    return Result::Ok;
}
