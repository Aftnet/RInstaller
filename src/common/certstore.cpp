#include "certstore.h"

#include "mbedtlsmgr.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

CertStore::CertStore(const std::filesystem::path& backingDir) :
    BackingDir(backingDir)
{

}

std::tuple<std::unique_ptr<mbedtls_pk_context, void(*)(mbedtls_pk_context*)>, std::unique_ptr<mbedtls_x509write_cert, void(*)(mbedtls_x509write_cert*)>> CertStore::GenerateKeyAndCertificate()
{
    constexpr unsigned int RsaKeySize = 2048;

    std::unique_ptr<mbedtls_pk_context, void(*)(mbedtls_pk_context*)> key(new mbedtls_pk_context, [](mbedtls_pk_context* d) { mbedtls_pk_free(d); delete d; });
    mbedtls_pk_init(key.get());
    if (mbedtls_pk_setup(key.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)))
    {
        throw std::runtime_error("Unable to generate key pair");
    }

    if (mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key.get()), mbedtls_ctr_drbg_random, MbedtlsMgr::GetInstance().Ctr_Drdbg(), RsaKeySize, 65537))
    {
        throw std::runtime_error("Unable to generate key pair");
    }

    std::unique_ptr<mbedtls_x509write_cert, void(*)(mbedtls_x509write_cert*)> crt(new mbedtls_x509write_cert, [](mbedtls_x509write_cert* d) { mbedtls_x509write_crt_free(d); delete d; });
    mbedtls_x509write_crt_init(crt.get());

    auto subjName = "CN=RInstaller";
    mbedtls_x509write_crt_set_md_alg(crt.get(), MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(crt.get(), key.get());
    mbedtls_x509write_crt_set_issuer_key(crt.get(), key.get());

    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    mbedtls_mpi_lset(&serial, 1);
    if (mbedtls_x509write_crt_set_serial(crt.get(), &serial))
    {
        throw std::runtime_error("Unable to generate certificate");
    }
    mbedtls_mpi_free(&serial);

    if (mbedtls_x509write_crt_set_subject_name(crt.get(), subjName))
    {
        throw std::runtime_error("Unable to generate certificate");
    }
    if (mbedtls_x509write_crt_set_issuer_name(crt.get(), subjName))
    {
        throw std::runtime_error("Unable to generate certificate");
    }
    if (mbedtls_x509write_crt_set_basic_constraints(crt.get(), 0, -1))
    {
        throw std::runtime_error("Unable to generate certificate");
    }
    if (mbedtls_x509write_crt_set_key_usage(crt.get(), MBEDTLS_X509_KU_KEY_AGREEMENT))
    {
        throw std::runtime_error("Unable to generate certificate");
    }
    if (mbedtls_x509write_crt_set_validity(crt.get(), "19000101000000", "22000101000000"))
    {
        throw std::runtime_error("Unable to generate certificate");
    }

    return std::make_tuple(std::move(key), std::move(crt));
}

std::string CertStore::GetSha1Thumbprint(const std::vector<unsigned char>& input)
{
    std::unique_ptr<mbedtls_sha1_context, void(*)(mbedtls_sha1_context*)> sha1(new mbedtls_sha1_context, [](mbedtls_sha1_context* d) { mbedtls_sha1_free(d); });

    mbedtls_sha1_init(sha1.get());
    if (mbedtls_sha1_starts(sha1.get()))
    {
        throw std::runtime_error("Unable to initialize sha1");
    }

    if (mbedtls_sha1_update(sha1.get(), input.data(), input.size()))
    {
        throw std::runtime_error("Unable to update sha1");
    }

    constexpr int shaBufLen = 20;
    std::vector<unsigned char> shaBuf(shaBufLen);
    if (mbedtls_sha1_finish(sha1.get(), shaBuf.data()))
    {
        throw std::runtime_error("Unable to finalize sha1");
    }

    std::string outStr;
    for (auto i : shaBuf)
    {
        std::format_to(std::back_inserter(outStr), "{:02x}", i);
    }

    return outStr;
}
