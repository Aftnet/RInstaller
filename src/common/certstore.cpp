#include "certstore.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtlsmgr.h"

#include <fstream>
#include <format>

mbedtls_pk_context* CertStore::NewMbedTlsPkContext()
{
    auto ctx = new mbedtls_pk_context;
    mbedtls_pk_init(ctx);
    return ctx;
}

void CertStore::FreeMbedTlsPkContext(mbedtls_pk_context* ctx)
{
    mbedtls_pk_free(ctx);
    delete ctx;
}

mbedtls_x509_crt* CertStore::NewMbedTlsCertContext()
{
    auto ctx = new mbedtls_x509_crt;
    mbedtls_x509_crt_init(ctx);
    return ctx;
}

void CertStore::FreeMbedTlsCertContext(mbedtls_x509_crt* ctx)
{
    mbedtls_x509_crt_free(ctx);
    delete ctx;
}

CertStore::CertStore(const std::filesystem::path& backingDir) :
    BackingDir(backingDir),
    PrivateKey(NewMbedTlsPkContext(), FreeMbedTlsPkContext),
    Certificate(NewMbedTlsCertContext(), FreeMbedTlsCertContext)
{
    auto keyPath = backingDir;
    keyPath.append("key.der");
    auto certPath = backingDir;
    certPath.append("crt.der");

    bool loadSuccess = false;
    {
        std::ifstream keyFile(keyPath, std::ios::in | std::ios::binary | std::ios::ate);
        std::ifstream certFile(certPath, std::ios::in | std::ios::binary | std::ios::ate);
        if (keyFile.is_open() && certFile.is_open())
        {
            try
            {
                std::vector<unsigned char> buffer(keyFile.tellg());
                keyFile.seekg(0, std::ios::beg);
                keyFile.read((char*)buffer.data(), buffer.size());
                if (mbedtls_pk_parse_key(PrivateKey.get(), buffer.data(), buffer.size(), nullptr, 0, mbedtls_ctr_drbg_random, MbedtlsMgr::GetInstance().Ctr_Drdbg()))
                {
                    throw std::runtime_error("Unable to import key file");
                }

                buffer.resize(certFile.tellg());
                certFile.seekg(std::ios::beg);
                certFile.read((char*)buffer.data(), buffer.size());
                if(mbedtls_x509_crt_parse_der(Certificate.get(), buffer.data(), buffer.size()))
                {
                    throw std::runtime_error("Unable to import cert file");
                }

                loadSuccess = true;
            }
            catch(std::exception)
            {}
        }
    }
    
    if (!loadSuccess)
    {
        auto generated = GenerateKeyAndCertificate();
        std::vector<char> buffer(4096);
        std::ofstream outFile;

        outFile.open(keyPath, std::ofstream::binary | std::ofstream::trunc);
        if (outFile.bad())
        {
            throw std::runtime_error("Unable to open key file for writing");
        }
        auto dataLen = mbedtls_pk_write_key_der(std::get<0>(generated).get(), (unsigned char*)buffer.data(), buffer.size());
        if (dataLen < 1)
        {
            throw std::runtime_error("Unable to convert cert to DER");
        }
        outFile.write(buffer.data() + (buffer.size() - dataLen), dataLen);
        outFile.close();

        outFile.open(certPath, std::ofstream::binary | std::ofstream::trunc);
        if (outFile.bad())
        {
            throw std::runtime_error("Unable to open cert file for writing");
        }
        dataLen = mbedtls_x509write_crt_der(std::get<1>(generated).get(), (unsigned char*)buffer.data(), buffer.size(), mbedtls_ctr_drbg_random, MbedtlsMgr::GetInstance().Ctr_Drdbg());
        if (dataLen < 1)
        {
            throw std::runtime_error("Unable to convert cert to DER");
        }
        outFile.write(buffer.data() + (buffer.size() - dataLen), dataLen);
        outFile.close();
    }
}

std::tuple<std::unique_ptr<mbedtls_pk_context, void(*)(mbedtls_pk_context*)>, std::unique_ptr<mbedtls_x509write_cert, void(*)(mbedtls_x509write_cert*)>> CertStore::GenerateKeyAndCertificate()
{
    constexpr unsigned int RsaKeySize = 2048;

    std::unique_ptr<mbedtls_pk_context, void(*)(mbedtls_pk_context*)> key(new mbedtls_pk_context, [](mbedtls_pk_context* d) {  });
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
