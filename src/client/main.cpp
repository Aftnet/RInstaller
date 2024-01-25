#include <iostream>

#include "protocol.h"
#include "certstore.h"
#include "mbedtlsmgr.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

int main()
{
    auto& mbedtlsmgr = MbedtlsMgr::GetInstance();
    CertStore store(std::filesystem::current_path());

    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    //mbedtls_x509_crt_init(&cacert);
    //mbedtls_ctr_drbg_init(&ctr_drbg);

    //if (auto ret = mbedtls_net_connect(&server_fd, "localhost", PortNumber.c_str(), MBEDTLS_NET_PROTO_TCP)) != 0)
    //{
    //    cout << "Unable to connect: " << ret;
    //}


    return 0;
}
