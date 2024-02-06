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

Client::Client(const filesystem::path& appDataPath, std::function<CertificateValidationAction(const std::string&)>& certValidationCB) :
    CertValidationCB(certValidationCB),
    Busy(false),
    CancelRequested(false),
	TlsMgr(MbedtlsMgr::GetInstance()),
	CertStore(appDataPath),
    Socket(nullptr, [](auto d) { mbedtls_net_close(d); mbedtls_net_free(d); delete d; }),
    SslContext(nullptr, [](auto d) { mbedtls_ssl_free(d); delete d; }),
    SslConfig(new mbedtls_ssl_config, [](auto d) { mbedtls_ssl_config_free(d); delete d; })
{
    mbedtls_ssl_config_init(SslConfig.get());
    CertStore.SetupSslConfig(SslConfig.get(), false);
}

Client::Result Client::Connect(const string& hostname, const std::chrono::milliseconds& timeoutMs)
{
    if (Busy)
    {
        return Result::Busy;
    }
    Busy = true;

    Socket.reset(new mbedtls_net_context);
    mbedtls_net_init(Socket.get());

    TimeoutBase = chrono::steady_clock::now();
    for (;;)
    {
        switch (mbedtls_net_connect(Socket.get(), hostname.c_str(), to_string(PortNumber).c_str(), MBEDTLS_NET_PROTO_TCP))
        {
        case MbedTlsOk:
        {
            break;
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
            Socket.reset();
            return Result::OtherError;
        }
        }
    }

    SslContext.reset(new mbedtls_ssl_context);
    mbedtls_ssl_init(SslContext.get());
    mbedtls_ssl_set_bio(SslContext.get(), Socket.get(), mbedtls_net_send, mbedtls_net_recv, nullptr);
    if (auto ret = mbedtls_ssl_set_hostname(SslContext.get(), RInstaller::CertificateStore::HostName.data()); ret != 0)
    {
        throw runtime_error("Failed setting hostname");
    }
    if (auto ret = mbedtls_ssl_setup(SslContext.get(), SslConfig.get()); ret != 0)
    {
        throw runtime_error("Failed setting up ssl context");
    }

    for (;;)
    {
        switch (mbedtls_ssl_handshake(SslContext.get()))
        {
            case MbedTlsOk:
            {
                break;
            }
            case MBEDTLS_ERR_SSL_WANT_READ:
            {
            }
            case MBEDTLS_ERR_SSL_WANT_WRITE:
            {
            }
            default:
            {
                Socket.reset();
                return Result::OtherError;
            }
        }
    }

    Busy = false;
    return Result::Ok;
}

Client::Result Client::Disconnect()
{
    if (Busy)
    {
        return Result::Busy;
    }
    Busy = true;

    Socket.reset();
    Busy = false;
    return Result::Ok;
}
