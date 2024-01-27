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
using namespace std::chrono_literals;

int main()
{
    auto& mbedtlsMgr = MbedtlsMgr::GetInstance();
    CertStore certStore(filesystem::current_path());

    unique_ptr<mbedtls_net_context, void(*)(mbedtls_net_context*)> listenSocket(new mbedtls_net_context, [](auto d) { mbedtls_net_free(d); delete d; });
    mbedtls_net_init(listenSocket.get());
    unique_ptr<mbedtls_net_context, void(*)(mbedtls_net_context*)> clientSocket(new mbedtls_net_context, [](auto d) { mbedtls_net_free(d); delete d; });
    mbedtls_net_init(clientSocket.get());

    unique_ptr<mbedtls_ssl_context, void(*)(mbedtls_ssl_context*)> sslCtx(new mbedtls_ssl_context, [](auto d) { mbedtls_ssl_free(d); delete d; });
    mbedtls_ssl_init(sslCtx.get());
    unique_ptr<mbedtls_ssl_config, void(*)(mbedtls_ssl_config*)> sslConfig(new mbedtls_ssl_config, [](auto d) { mbedtls_ssl_config_free(d); delete d; });
    mbedtls_ssl_config_init(sslConfig.get());

    if (auto ret = mbedtls_net_bind(listenSocket.get(), nullptr, PortNumber.c_str(), MBEDTLS_NET_PROTO_TCP); ret != 0)
    {
        throw runtime_error(std::format("Failed listening on network interface. Err code: {}", ret));
    }

    if (auto ret = mbedtls_net_set_nonblock(listenSocket.get()); ret != 0)
    {
        throw runtime_error(std::format("Failed setting socket to non blocking. Err code: {}", ret));
    }

    cout << "Waiting for client connection" << endl;

    vector<char> clientIpBuf(130);
    size_t clientIpLen;
    for (;;)
    {
        if (auto ret = mbedtls_net_accept(listenSocket.get(), clientSocket.get(), clientIpBuf.data(), clientIpBuf.size(), &clientIpLen); ret == MBEDTLS_ERR_SSL_WANT_READ)
        {
            this_thread::sleep_for(1s);
            continue;
        }
        else if (ret != 0)
        {
            throw runtime_error(std::format("Failed accepting client connection. Err code: {}", ret));
        }

        break;
    }

    cout << "Client connected" << endl;

    if (auto ret = mbedtls_net_set_nonblock(listenSocket.get()); ret != 0)
    {
        throw runtime_error(std::format("Failed setting socket to non blocking. Err code: {}", ret));
    }

    if (auto ret = mbedtls_ssl_config_defaults(sslConfig.get(), MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT); ret != 0)
    {
        throw runtime_error(std::format("Failed setting ssl defaults. Err code: {}", ret));
    }
    mbedtls_ssl_conf_authmode(sslConfig.get(), MBEDTLS_SSL_VERIFY_REQUIRED);

    if (auto ret = mbedtls_ssl_setup(sslCtx.get(), sslConfig.get()); ret != 0)
    {
        throw runtime_error(std::format("Failed setting up ssl context. Err code: {}", ret));
    }
    if (auto ret = mbedtls_ssl_set_hs_own_cert(sslCtx.get(), certStore.GetCertificate(), certStore.GetPrivateKey()); ret != 0)
    {
        throw runtime_error(std::format("Failed setting ssl certificate. Err code: {}", ret));
    }

    return 0;
}
