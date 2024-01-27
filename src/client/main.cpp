#include "certstore.h"
#include "mbedtls/net_sockets.h"
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
    auto& mbedtlsmgr = MbedtlsMgr::GetInstance();
    CertStore store(filesystem::current_path());

    cout << "Connecting to server" << endl;

    unique_ptr<mbedtls_net_context, void(*)(mbedtls_net_context*)> socket(new mbedtls_net_context, [](auto d) { mbedtls_net_free(d); delete d; });
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

    return 0;
}
