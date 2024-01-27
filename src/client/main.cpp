#include "certstore.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtlsmgr.h"
#include "protocol.h"
#include <chrono>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace std;

int main()
{
    auto& mbedtlsMgr = MbedtlsMgr::GetInstance();
    CertStore certStore(filesystem::current_path());

    unique_ptr<mbedtls_net_context, void(*)(mbedtls_net_context*)> socket(new mbedtls_net_context, [](auto d) { mbedtls_net_free(d); delete d; });
    mbedtls_net_init(socket.get());

    unique_ptr<mbedtls_ssl_context, void(*)(mbedtls_ssl_context*)> sslCtx(new mbedtls_ssl_context, [](auto d) { mbedtls_ssl_free(d); delete d; });
    mbedtls_ssl_init(sslCtx.get());
    unique_ptr<mbedtls_ssl_config, void(*)(mbedtls_ssl_config*)> sslConfig(new mbedtls_ssl_config, [](auto d) { mbedtls_ssl_config_free(d); delete d; });
    mbedtls_ssl_config_init(sslConfig.get());

    cout << "Connecting to server" << endl;
    for (;;)
    {
        if (auto ret = mbedtls_net_connect(socket.get(), "localhost", PortNumber.c_str(), MBEDTLS_NET_PROTO_TCP); ret == MBEDTLS_ERR_NET_CONNECT_FAILED)
        {
            continue;
        }
        else if (ret == MBEDTLS_ERR_NET_UNKNOWN_HOST)
        {
            cout << "Unable to resolve host";
            break;
        }
        else if (ret == MBEDTLS_ERR_NET_SOCKET_FAILED)
        {
            throw std::runtime_error("Unable to connect: socket error");
        }
        else if (ret != 0)
        {
            throw runtime_error(std::format("Failed connecting. Err code: {}", ret));
        }

        break;
    }

    cout << "Connected to server" << endl;
    if (auto ret = mbedtls_net_set_nonblock(socket.get()); ret != 0)
    {
        throw runtime_error(std::format("Failed setting socket to non blocking. Err code: {}", ret));
    }

    if (auto ret = mbedtls_ssl_config_defaults(sslConfig.get(), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT); ret != 0)
    {
        throw runtime_error(std::format("Failed setting ssl defaults. Err code: {}", ret));
    }
    mbedtls_ssl_conf_authmode(sslConfig.get(), MBEDTLS_SSL_VERIFY_REQUIRED);

    if (auto ret = mbedtls_ssl_set_hs_own_cert(sslCtx.get(), certStore.GetCertificate(), certStore.GetPrivateKey()); ret != 0)
    {
        throw runtime_error(std::format("Failed sssl certificate. Err code: {}", ret));
    }

    return 0;
}
