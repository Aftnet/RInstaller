#include "certstore.h"

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include <mbedtls/ctr_drbg.h>
#include <string>
#include <iostream>
#include <vector>
#include <span>
#include <iomanip>
#include <memory>
#include <format>

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

    std::vector<unsigned char> privkey(4096), pubkey(4096);
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

	mbedtls_x509write_cert crt;
	mbedtls_x509write_crt_init(&crt);

    auto subjName = "CN=RInstaller";

    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &key);

    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    mbedtls_mpi_lset(&serial, 1);
    if (mbedtls_x509write_crt_set_serial(&crt, &serial))
    {
        throw;
    }
    mbedtls_mpi_free(&serial);

    if (mbedtls_x509write_crt_set_subject_name(&crt, subjName))
    {
        throw;
    }
    if (mbedtls_x509write_crt_set_issuer_name(&crt, subjName))
    {
        throw;
    }
    if (mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1))
    {
        throw;
    }
    if (mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_KEY_AGREEMENT))
    {
        throw;
    }
    if (mbedtls_x509write_crt_set_validity(&crt, "19000101000000", "22000101000000"))
    {
        throw;
    }

    std::vector<unsigned char> crtBuf(8192);
    if (mbedtls_x509write_crt_pem(&crt, crtBuf.data(), crtBuf.size(), mbedtls_ctr_drbg_random, &ctr_drbg))
    {
        throw;
    }

    std::cout << crtBuf.data();

    auto crtLen = mbedtls_x509write_crt_der(&crt, crtBuf.data(), crtBuf.size(), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (crtLen < 0)
    {
        throw;
    }

    std::vector<unsigned char>(crtBuf.begin() + (crtBuf.size() - crtLen), crtBuf.end()).swap(crtBuf);
    std::cout << "Fingerprint: " << GetSha1Thumbprint(crtBuf);
}

struct mbedtls_sha1_context_deleter
{
    void operator()(mbedtls_sha1_context* d) const
    {
        mbedtls_sha1_free(d);
    }
};

std::string CertStore::GetSha1Thumbprint(const std::vector<unsigned char>& input)
{
    std::unique_ptr<mbedtls_sha1_context> sha1(new mbedtls_sha1_context);
    mbedtls_sha1_init(sha1.get());
    if (mbedtls_sha1_starts(sha1.get()))
    {
        throw std::runtime_error("Failied initializing sha1");
    }

    if (mbedtls_sha1_update(sha1.get(), input.data(), input.size()))
    {
        throw std::runtime_error("Failied updating sha1");
    }

    constexpr int shaBufLen = 20;
    std::vector<unsigned char> shaBuf(shaBufLen);
    if (mbedtls_sha1_finish(sha1.get(), shaBuf.data()))
    {
        throw std::runtime_error("Failied computing sha1");;
    }

    std::string outStr;
    for (auto i : shaBuf)
    {
        std::format_to(std::back_inserter(outStr), "{:02x}", i);
    }

    return outStr;
}
