#include "certstore.h"
#include "mbedtls/asn1.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/oid.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtlsmgr.h"
#include <array>
#include <format>
#include <fstream>

using namespace std;

namespace
{
    const string AllowedCertificatesFileName("allowed_certs.txt");
    const string DeniedCertificatesFileName("denied_certs.txt");
    const string HostKeyFileName("host_key.der");
    const string HostCertificateFileName("host_cert.der");

    constexpr unsigned int RsaKeySize = 2048;
    constexpr bool ForceCertRegeneration = false;
}

string CertStore::HostName("RInstaller Instance");

CertStore::ThumbprintStore::ThumbprintStore(const filesystem::path& backingFile) :
    BackingFile(backingFile)
{
    ifstream storeFile(BackingFile);
    if (storeFile.is_open())
    {
        string thumbPrint;
        while (storeFile >> thumbPrint)
        {
            Store.insert(thumbPrint);
        }
    }
}

bool CertStore::ThumbprintStore::Contains(const string& thumbprint) const
{
    return Store.contains(thumbprint);
}

void CertStore::ThumbprintStore::Add(const string& thumbprint)
{
    if (Store.contains(thumbprint))
    {
        return;
    }

    Store.insert(thumbprint);
    ofstream storeFile(BackingFile, ios::ate | ios::app);
    storeFile << thumbprint << endl;
}

void CertStore::ThumbprintStore::Clear()
{
    Store.clear();
    ofstream storeFile(BackingFile, ios::trunc);
}

CertStore::CertStore(const filesystem::path& backingDir) :
    BackingDir(backingDir),
    PrivateKey(NewMbedTlsPkContext(), FreeMbedTlsPkContext),
    Certificate(NewMbedTlsCertContext(), FreeMbedTlsCertContext),
    AllowedCertificates(filesystem::path(backingDir).append(AllowedCertificatesFileName)),
    DeniedCertificates(filesystem::path(backingDir).append(DeniedCertificatesFileName))
{
    auto keyPath = backingDir;
    keyPath.append(HostKeyFileName);
    auto certPath = backingDir;
    certPath.append(HostCertificateFileName);

    bool loadSuccess = false;
    if(!ForceCertRegeneration)
    {
        ifstream keyFile(keyPath, ios::binary | ios::ate);
        ifstream certFile(certPath, ios::binary | ios::ate);
        if (keyFile.is_open() && certFile.is_open())
        {
            try
            {
                vector<unsigned char> keyBuffer(keyFile.tellg()), certBuffer(certFile.tellg());

                keyFile.seekg(0, ios::beg);
                keyFile.read((char*)keyBuffer.data(), keyBuffer.size());
                LoadPrivateKey(keyBuffer);

                certFile.seekg(ios::beg);
                certFile.read((char*)certBuffer.data(), certBuffer.size());
                LoadCertificate(certBuffer);

                loadSuccess = true;
            }
            catch (exception)
            {
            }
        }
    }

    if (!loadSuccess)
    {
        auto generated = GenerateKeyAndCertificateDer();
        auto& keyBuffer = get<0>(generated);
        auto& certBuffer = get<1>(generated);
        LoadPrivateKey(keyBuffer);
        LoadCertificate(certBuffer);

        ofstream keyFile(keyPath, ios::binary | ios::trunc);
        ofstream certFile(certPath, ios::binary | ios::trunc);

        if (!keyFile.is_open())
        {
            throw runtime_error("Unable to open key file for writing");
        }
        keyFile.write((const char*)keyBuffer.data(), keyBuffer.size());

        if (!certFile.is_open())
        {
            throw runtime_error("Unable to open cert file for writing");
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
    auto hash = GetSha1Thumbprint(span(cert->raw.p, cert->raw.p + cert->raw.len));
    AllowedCertificates.Add(hash);
}

void CertStore::AddDeniedCertificate(mbedtls_x509_crt* cert)
{
    auto hash = GetSha1Thumbprint(span(cert->raw.p, cert->raw.p + cert->raw.len));
    DeniedCertificates.Add(hash);
}

bool CertStore::CertificateIsAllowed(mbedtls_x509_crt* cert)
{
    auto hash = GetSha1Thumbprint(span(cert->raw.p, cert->raw.p + cert->raw.len));
    return AllowedCertificates.Contains(hash);
}

bool CertStore::CertificateIsDenied(mbedtls_x509_crt* cert)
{
    auto hash = GetSha1Thumbprint(span(cert->raw.p, cert->raw.p + cert->raw.len));
    return DeniedCertificates.Contains(hash);
}

void CertStore::ClearKnownCertificates()
{
    AllowedCertificates.Clear();
    DeniedCertificates.Clear();
}

unique_ptr<mbedtls_ssl_config, void(*)(mbedtls_ssl_config*)>CertStore::GenerateConfig(bool configForServer) const
{
    unique_ptr<mbedtls_ssl_config, void(*)(mbedtls_ssl_config*)> sslConfig(new mbedtls_ssl_config, [](auto d) { mbedtls_ssl_config_free(d); delete d; });
    mbedtls_ssl_config_init(sslConfig.get());

    if (auto ret = mbedtls_ssl_config_defaults(sslConfig.get(), configForServer ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT); ret != 0)
    {
        throw runtime_error(format("Failed setting ssl defaults. Err code: {}", ret));
    }
    mbedtls_ssl_conf_min_version(sslConfig.get(), MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    mbedtls_ssl_conf_rng(sslConfig.get(), mbedtls_ctr_drbg_random, MbedtlsMgr::GetInstance().Ctr_Drdbg());
    mbedtls_ssl_conf_dbg(sslConfig.get(), &MbedtlsMgr::DebugPrint, nullptr);
    mbedtls_ssl_conf_preference_order(sslConfig.get(), configForServer ? MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_SERVER : MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_CLIENT);
    mbedtls_debug_set_threshold(4);
    mbedtls_ssl_conf_authmode(sslConfig.get(), MBEDTLS_SSL_VERIFY_REQUIRED);
    if (auto ret = mbedtls_ssl_conf_own_cert(sslConfig.get(), GetCertificate(), GetPrivateKey()); ret != 0)
    {
        throw runtime_error(format("Failed setting ssl certificate. Err code: {}", ret));
    }

    return sslConfig;
}

tuple<vector<unsigned char>, vector<unsigned char>> CertStore::GenerateKeyAndCertificateDer()
{
    unique_ptr<mbedtls_pk_context, void(*)(mbedtls_pk_context*)> key(NewMbedTlsPkContext(), FreeMbedTlsPkContext);
    if (auto ret = mbedtls_pk_setup(key.get(), mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)); ret != 0)
    {
        throw runtime_error(format("Unable to generate key pair. Err code: {}", ret));
    }

    if (auto ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key.get()), mbedtls_ctr_drbg_random, MbedtlsMgr::GetInstance().Ctr_Drdbg(), RsaKeySize, 65537); ret != 0)
    {
        throw runtime_error(format("Unable to generate key pair. Err code: {}", ret));
    }

    vector<unsigned char> keyBuffer(RsaKeySize);
    if (auto ret = mbedtls_pk_write_key_der(key.get(), (unsigned char*)keyBuffer.data(), keyBuffer.size()); ret < 1)
    {
        throw runtime_error(format("Unable to convert cert to DER. Err code: {}", ret));
    }
    else
    {
        auto tmpBuffer = vector(keyBuffer.end() - ret, keyBuffer.end());
        keyBuffer.swap(tmpBuffer);
    }

    unique_ptr<mbedtls_x509write_cert, void(*)(mbedtls_x509write_cert*)> crt(new mbedtls_x509write_cert, [](mbedtls_x509write_cert* d) { mbedtls_x509write_crt_free(d); delete d; });
    mbedtls_x509write_crt_init(crt.get());

    const string subjName(string("CN=").append(CertStore::HostName));
    mbedtls_x509write_crt_set_md_alg(crt.get(), MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(crt.get(), key.get());
    mbedtls_x509write_crt_set_issuer_key(crt.get(), key.get());

    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    mbedtls_mpi_lset(&serial, 1);
    if (auto ret = mbedtls_x509write_crt_set_serial(crt.get(), &serial); ret != 0)
    {
        throw runtime_error(format("Unable to generate certificate. Err code: {}", ret));
    }
    mbedtls_mpi_free(&serial);

    if (auto ret = mbedtls_x509write_crt_set_subject_name(crt.get(), subjName.c_str()); ret != 0)
    {
        throw runtime_error(format("Unable to generate certificate. Err code: {}", ret));
    }
    if (auto ret = mbedtls_x509write_crt_set_issuer_name(crt.get(), subjName.c_str()); ret != 0)
    {
        throw runtime_error(format("Unable to generate certificate. Err code: {}", ret));
    }
    if (auto ret = mbedtls_x509write_crt_set_basic_constraints(crt.get(), 0, -1); ret != 0)
    {
        throw runtime_error(format("Unable to generate certificate. Err code: {}", ret));
    }
    if (auto ret = mbedtls_x509write_crt_set_key_usage(crt.get(), MBEDTLS_X509_KU_DIGITAL_SIGNATURE); ret != 0)
    {
        throw runtime_error(format("Unable to generate certificate. Err code: {}", ret));
    }

    array<mbedtls_asn1_sequence, 2> certEkus
    {
        mbedtls_asn1_sequence
        {
            mbedtls_asn1_buf
            {
                MBEDTLS_ASN1_OID,
                strlen(MBEDTLS_OID_SERVER_AUTH),
                (unsigned char*)MBEDTLS_OID_SERVER_AUTH
            },
            &(certEkus.at(1))
        },
        mbedtls_asn1_sequence
        {
            mbedtls_asn1_buf
            {
                MBEDTLS_ASN1_OID,
                strlen(MBEDTLS_OID_SERVER_AUTH),
                (unsigned char*)MBEDTLS_OID_CLIENT_AUTH
            },
            nullptr,
        }
    };
    if (auto ret = mbedtls_x509write_crt_set_ext_key_usage(crt.get(), certEkus.data()); ret != 0)
    {
        throw runtime_error(format("Unable to generate certificate. Err code: {}", ret));
    }
    if (auto ret = mbedtls_x509write_crt_set_validity(crt.get(), "19000101000000", "22000101000000"); ret != 0)
    {
        throw runtime_error(format("Unable to generate certificate. Err code: {}", ret));
    }

    vector<unsigned char> certBuffer(RsaKeySize);
    if (auto ret = mbedtls_x509write_crt_der(crt.get(), certBuffer.data(), certBuffer.size(), mbedtls_ctr_drbg_random, MbedtlsMgr::GetInstance().Ctr_Drdbg()); ret < 1)
    {
        throw runtime_error(format("Unable to convert cert to DER. Err code: {}", ret));
    }
    else
    {
        auto tmpBuffer = vector(certBuffer.end() - ret, certBuffer.end());
        certBuffer.swap(tmpBuffer);
    }

    return make_tuple(move(keyBuffer), move(certBuffer));
}

void CertStore::LoadPrivateKey(const vector<unsigned char>& buffer)
{
    if (auto ret = mbedtls_pk_parse_key(PrivateKey.get(), buffer.data(), buffer.size(), nullptr, 0, mbedtls_ctr_drbg_random, MbedtlsMgr::GetInstance().Ctr_Drdbg()); ret != 0)
    {
        throw runtime_error(format("Unable to import key from der. Err code: {}", ret));
    }
}

void CertStore::LoadCertificate(const vector<unsigned char>& buffer)
{
    if (auto ret = mbedtls_x509_crt_parse_der(Certificate.get(), buffer.data(), buffer.size()); ret != 0)
    {
        throw runtime_error(format("Unable to import cert from der. Err code: {}", ret));
    }
}

string CertStore::GetSha1Thumbprint(const span<unsigned char>& input)
{
    unique_ptr<mbedtls_sha1_context, void(*)(mbedtls_sha1_context*)> sha1(new mbedtls_sha1_context, [](mbedtls_sha1_context* d) { mbedtls_sha1_free(d); });

    mbedtls_sha1_init(sha1.get());
    if (auto ret = mbedtls_sha1_starts(sha1.get()); ret != 0)
    {
        throw runtime_error(format("Unable to initialize sha1. Err code: {}", ret));
    }

    if (auto ret = mbedtls_sha1_update(sha1.get(), input.data(), input.size()); ret != 0)
    {
        throw runtime_error(format("Unable to update sha1. Err code: {}", ret));
    }

    constexpr int shaBufLen = 20;
    vector<unsigned char> shaBuf(shaBufLen);
    if (auto ret = mbedtls_sha1_finish(sha1.get(), shaBuf.data()); ret != 0)
    {
        throw runtime_error(format("Unable to finalize sha1. Err code: {}", ret));
    }

    string outStr;
    for (auto i : shaBuf)
    {
        format_to(back_inserter(outStr), "{:02x}", i);
    }

    return outStr;
}

int CertStore::MbedTlsIOStreamInteractiveCertVerification(void* pCertStore, mbedtls_x509_crt* pCertChain, int, uint32_t* chainLength)
{
    auto certStore = reinterpret_cast<CertStore*>(pCertStore);
    return 0;
}
