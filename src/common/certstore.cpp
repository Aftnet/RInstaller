#include "certstore.h"

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include <mbedtls/ctr_drbg.h>
#include <array>
#include <string>
#include <iostream>

void CertStore::Init()
{
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)"RANDOM_GEN", 10))
    {
        throw;
    }

    mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF);

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    if (mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)))
    {
        throw;
    }

    if (mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537))
    {
        throw;
    }

    std::array<unsigned char, 8192> privkey, pubkey;
    if (mbedtls_pk_write_key_pem(&key, privkey.data(), privkey.size()))
    {
        throw;
    }
    if (mbedtls_pk_write_pubkey_pem(&key, pubkey.data(), pubkey.size()))
    {
        throw;
    }

    std::cout << privkey.data();
    std::cout << pubkey.data();

	mbedtls_x509write_cert cert;
	mbedtls_x509write_crt_init(&cert);
}
