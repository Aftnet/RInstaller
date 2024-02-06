#include "certstore.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
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

#include "client.h"

using namespace std;

int main()
{
    auto& mbedtlsMgr = RInstaller::MbedtlsMgr::GetInstance();
    RInstaller::CertificateStore certStore(filesystem::current_path());
    cout << "Local cert thumbprint: " << certStore.GetCertificateTumbprint() << endl;

    unique_ptr<mbedtls_net_context, void(*)(mbedtls_net_context*)> socket(new mbedtls_net_context, [](auto d) { mbedtls_net_free(d); delete d; });
    mbedtls_net_init(socket.get());

    cout << "Connecting to server" << endl;
    for (;;)
    {
        if (auto ret = mbedtls_net_connect(socket.get(), "localhost", std::to_string(RInstaller::PortNumber).c_str(), MBEDTLS_NET_PROTO_TCP); ret == MBEDTLS_ERR_NET_CONNECT_FAILED)
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
    
    unique_ptr<mbedtls_ssl_context, void(*)(mbedtls_ssl_context*)> sslCtx(new mbedtls_ssl_context, [](auto d) { mbedtls_ssl_free(d); delete d; });
    mbedtls_ssl_init(sslCtx.get());
    unique_ptr<mbedtls_ssl_config, void(*)(mbedtls_ssl_config*)> sslConfig(new mbedtls_ssl_config, [](auto d) { mbedtls_ssl_config_free(d); delete d; });
    mbedtls_ssl_config_init(sslConfig.get());
    certStore.SetupSslConfig(sslConfig.get(), false);
    mbedtls_ssl_set_bio(sslCtx.get(), socket.get(), mbedtls_net_send, mbedtls_net_recv, nullptr);
    if (auto ret = mbedtls_ssl_set_hostname(sslCtx.get(), RInstaller::CertificateStore::HostName.data()); ret != 0)
    {
        throw runtime_error(std::format("Failed setting hostname. Err code: {}", ret));
    }
    if (auto ret = mbedtls_ssl_setup(sslCtx.get(), sslConfig.get()); ret != 0)
    {
        throw runtime_error(std::format("Failed setting up ssl context. Err code: {}", ret));
    }

    for (int ret; (ret = mbedtls_ssl_handshake(sslCtx.get())) != 0;)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            throw runtime_error(std::format("ssl handshake failed. Err code: {}", ret));
        }
    }

    std::vector<unsigned char> lol(128);
    for(size_t written = 0; written< lol.size();)
    {
        auto ret = mbedtls_ssl_write(sslCtx.get(), lol.data(), lol.size());
        if (ret > 0)
        {
            written += ret;
        }
        else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret != MBEDTLS_ERR_SSL_WANT_WRITE || ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
        {
            this_thread::sleep_for(1s);
            continue;
        }
        else
        {
            throw runtime_error(std::format("Failed writing. Err code: {:x}", ret));
            break;
        }
    }

    return 0;
}
