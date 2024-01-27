#include "certstore.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtlsmgr.h"
#include <format>
#include <fstream>

namespace
{
    const std::string AllowedCertificatesFileName("allowed_certs.txt");
    const std::string DeniedCertificatesFileName("denied_certs.txt");
    const std::string HostKeyFileName("host_key.der");
    const std::string HostCertificateFileName("host_cert.der");

    constexpr unsigned int RsaKeySize = 2048;
}

CertStore::ThumbprintStore::ThumbprintStore(const std::filesystem::path& backingFile) :
    BackingFile(backingFile)
{
    std::ifstream storeFile(BackingFile);
    if (storeFile.is_open())
    {
        std::string thumbPrint;
        while (storeFile >> thumbPrint)
        {
            Store.insert(thumbPrint);
        }
    }
}

bool CertStore::ThumbprintStore::Contains(const std::string& thumbprint) const
{
    return Store.contains(thumbprint);
}

void CertStore::ThumbprintStore::Add(const std::string& thumbprint)
{
    if (Store.contains(thumbprint))
    {
        return;
    }

    Store.insert(thumbprint);
    std::ofstream storeFile(BackingFile, std::ios::ate | std::ios::app);
    storeFile << thumbprint << std::endl;
}

void CertStore::ThumbprintStore::Clear()
{
    Store.clear();
    std::ofstream storeFile(BackingFile, std::ios::trunc);
}

CertStore::CertStore(const std::filesystem::path& backingDir) :
    BackingDir(backingDir),
    PrivateKey(NewMbedTlsPkContext(), FreeMbedTlsPkContext),
    Certificate(NewMbedTlsCertContext(), FreeMbedTlsCertContext),
    AllowedCertificates(std::filesystem::path(backingDir).append(AllowedCertificatesFileName)),
    DeniedCertificates(std::filesystem::path(backingDir).append(DeniedCertificatesFileName))
{
    auto keyPath = backingDir;
    keyPath.append(HostKeyFileName);
    auto certPath = backingDir;
    certPath.append(HostCertificateFileName);

    bool loadSuccess = false;
    {
        std::ifstream keyFile(keyPath, std::ios::binary | std::ios::ate);
        std::ifstream certFile(certPath, std::ios::binary | std::ios::ate);
        if (keyFile.is_open() && certFile.is_open())
        {
            try
            {
                std::vector<unsigned char> keyBuffer(keyFile.tellg()), certBuffer(certFile.tellg());

                keyFile.seekg(0, std::ios::beg);
                keyFile.read((char*)keyBuffer.data(), keyBuffer.size());
                LoadPrivateKey(keyBuffer);

                certFile.seekg(std::ios::beg);
                certFile.read((char*)certBuffer.data(), certBuffer.size());
                LoadCertificate(certBuffer);

                loadSuccess = true;
            }
            catch (std::exception)
            {
            }
        }
    }
    
    if (!loadSuccess)
    {
        auto generated = GenerateKeyAndCertificateDer();
        auto& keyBuffer = std::get<0>(generated);
        auto& certBuffer = std::get<1>(generated);
        LoadPrivateKey(keyBuffer);
        LoadCertificate(certBuffer);

        std::ofstream keyFile(keyPath, std::ios::binary | std::ios::trunc);
        std::ofstream certFile(certPath, std::ios::binary | std::ios::trunc);

        if (!keyFile.is_open())
        {
            throw std::runtime_error("Unable to open key file for writing");
        }
        keyFile.write((const char*)keyBuffer.data(), keyBuffer.size());

        if (!certFile.is_open())
        {
            throw std::runtime_error("Unable to open cert file for writing");
        }
        certFile.write((const char*)certBuffer.data(), certBuffer.size());
    }
}

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

void CertStore::AddAllowedCertificate(mbedtls_x509_crt* cert)
{
    auto hash = GetSha1Thumbprint(std::span(cert->raw.p, cert->raw.p + cert->raw.len));
    AllowedCertificates.Add(hash);
}

void CertStore::AddDeniedCertificate(mbedtls_x509_crt* cert)
{
    auto hash = GetSha1Thumbprint(std::span(cert->raw.p, cert->raw.p + cert->raw.len));
    DeniedCertificates.Add(hash);
}

bool CertStore::CertificateIsAllowed(mbedtls_x509_crt* cert)
{
    auto hash = GetSha1Thumbprint(std::span(cert->raw.p, cert->raw.p + cert->raw.len));
    return AllowedCertificates.Contains(hash);
}

bool CertStore::CertificateIsDenied(mbedtls_x509_crt* cert)
{
    auto hash = GetSha1Thumbprint(std::span(cert->raw.p, cert->raw.p + cert->raw.len));
    return DeniedCertificates.Contains(hash);
}

void CertStore::ClearKnownCertificates()
{
    AllowedCertificates.Clear();
    DeniedCertificates.Clear();
}

std::tuple<std::vector<unsigned char>, std::vector<unsigned char>> CertStore::GenerateKeyAndCertificateDer()
{
    std::unique_ptr<mbedtls_pk_context, void(*)(mbedtls_pk_context*)> key(NewMbedTlsPkContext(), FreeMbedTlsPkContext);
    if (auto ret = mbedtls_pk_setup(key.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to generate key pair. Err code: {}", ret));
    }

    if (auto ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key.get()), mbedtls_ctr_drbg_random, MbedtlsMgr::GetInstance().Ctr_Drdbg(), RsaKeySize, 65537); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to generate key pair. Err code: {}", ret));
    }

    std::vector<unsigned char> keyBuffer(RsaKeySize);
    if (auto ret = mbedtls_pk_write_key_der(key.get(), (unsigned char*)keyBuffer.data(), keyBuffer.size()); ret < 1)
    {
        throw std::runtime_error(std::format("Unable to convert cert to DER. Err code: {}", ret));
    }
    else
    {
        auto tmpBuffer = std::vector(keyBuffer.end() - ret, keyBuffer.end());
        keyBuffer.swap(tmpBuffer);
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
    if (auto ret = mbedtls_x509write_crt_set_serial(crt.get(), &serial); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to generate certificate. Err code: {}", ret));
    }
    mbedtls_mpi_free(&serial);

    if (auto ret = mbedtls_x509write_crt_set_subject_name(crt.get(), subjName); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to generate certificate. Err code: {}", ret));
    }
    if (auto ret = mbedtls_x509write_crt_set_issuer_name(crt.get(), subjName); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to generate certificate. Err code: {}", ret));
    }
    if (auto ret = mbedtls_x509write_crt_set_basic_constraints(crt.get(), 0, -1); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to generate certificate. Err code: {}", ret));
    }
    if (auto ret = mbedtls_x509write_crt_set_key_usage(crt.get(), MBEDTLS_X509_KU_KEY_AGREEMENT); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to generate certificate. Err code: {}", ret));
    }
    if (auto ret = mbedtls_x509write_crt_set_validity(crt.get(), "19000101000000", "22000101000000"); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to generate certificate. Err code: {}", ret));
    }

    std::vector<unsigned char> certBuffer(RsaKeySize);
    if (auto ret = mbedtls_x509write_crt_der(crt.get(), certBuffer.data(), certBuffer.size(), mbedtls_ctr_drbg_random, MbedtlsMgr::GetInstance().Ctr_Drdbg()); ret < 1)
    {
        throw std::runtime_error(std::format("Unable to convert cert to DER. Err code: {}", ret));
    }
    else
    {
        auto tmpBuffer = std::vector(certBuffer.end() - ret, certBuffer.end());
        certBuffer.swap(tmpBuffer);
    }

    return std::make_tuple(std::move(keyBuffer), std::move(certBuffer));
}

void CertStore::LoadPrivateKey(const std::vector<unsigned char>& buffer)
{
    if (auto ret = mbedtls_pk_parse_key(PrivateKey.get(), buffer.data(), buffer.size(), nullptr, 0, mbedtls_ctr_drbg_random, MbedtlsMgr::GetInstance().Ctr_Drdbg()); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to import key from der. Err code: {}", ret));
    }
}

void CertStore::LoadCertificate(const std::vector<unsigned char>& buffer)
{
    if (auto ret = mbedtls_x509_crt_parse_der(Certificate.get(), buffer.data(), buffer.size()); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to import cert from der. Err code: {}", ret));
    }
}

std::string CertStore::GetSha1Thumbprint(const std::span<unsigned char>& input)
{
    std::unique_ptr<mbedtls_sha1_context, void(*)(mbedtls_sha1_context*)> sha1(new mbedtls_sha1_context, [](mbedtls_sha1_context* d) { mbedtls_sha1_free(d); });

    mbedtls_sha1_init(sha1.get());
    if (auto ret = mbedtls_sha1_starts(sha1.get()); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to initialize sha1. Err code: {}", ret));
    }

    if (auto ret = mbedtls_sha1_update(sha1.get(), input.data(), input.size()); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to update sha1. Err code: {}", ret));
    }

    constexpr int shaBufLen = 20;
    std::vector<unsigned char> shaBuf(shaBufLen);
    if (auto ret = mbedtls_sha1_finish(sha1.get(), shaBuf.data()); ret != 0)
    {
        throw std::runtime_error(std::format("Unable to finalize sha1. Err code: {}", ret));
    }

    std::string outStr;
    for (auto i : shaBuf)
    {
        std::format_to(std::back_inserter(outStr), "{:02x}", i);
    }

    return outStr;
}
