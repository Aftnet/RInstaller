#include "certstore.h"
#include "mbedtls/asn1.h"
#include "mbedtls/ctr_drbg.h"
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

const string CertStore::HostName("RInstaller Instance");

const string CertStore::CaKey("-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCzms3awwiSmROT\n\
+76hxFHDjUmxQRnJ5gd9dai3ay0GzUItwpio3nFZBorDjsLYaAsAWQgKx9444LIK\n\
qDk/9umiPKWiOuT03kZIexcJlWj79adsmNYMjJC5VIPpHnFq+8NMD+obGZmCv1T7\n\
akKsK1YgDeDdwNhteWKsLbmipmcy5tan3sJ5hxxw8QsQgsZgGRgUVu5+nk57pRDX\n\
Qp+rliRiI6hTe8+u4aQZAGyb+SK1+39IB7Wo73sUGdV8iulKK+mMwdJKLCjyI9DO\n\
p/nz4st/9BiiC5mPtIlGNr4Km3Tyyu0EwxfU48QICED0ZIlIk81h9tBiGazy2aE2\n\
MOY1TskrAgMBAAECggEAGnC/vWTY7jv61d5JwibUoqU6JA4hbcefcqjPnbD5f/bX\n\
t0TelH2q0iBUbVWm+ZTXicWRmYSzAkyR6V+6jeAbpPaoq6lf62yNjD4StiZ4vh77\n\
9tDJMi+/XolCoh8JM2a86YWuQS8TmlvwdtK93frDQxTH9d1d/z/PdumEWp2Es8lo\n\
xGutvNaubg+apUdEe/rzE9sQ3TI2Sxeu7/dHer7yna7xupYECvNzqO8eNbwJbaDB\n\
onqah7bxTlONSUdQhx47yGkK9OLOj3CTytLvqWkCMaA8T2ASHIHDhrzN2YAQovKX\n\
Zw7eYiBgk947s16GgIpt2geOGPlhn39jd9jQi+ojAQKBgQDPKd8jvlzH6p7a1F3x\n\
ZylNB5jQe11CYrVZeI1twlD2JVGvHCDdUVnVJLy2Xs7lJA3+NzF43Q6T5KcUoUfI\n\
dKtAaAYGCOh4olkIrgbCZP2UOBndflj05em/QyY3gz0EfXQ2jNPzp30SFnEncLKM\n\
iSqh7xa9SHSJw832btbPtq59EwKBgQDd8cfykJf88Vu4zvw9v6Nmdu2Kegt2Tg7d\n\
zOyc17GCYvzeN5MF3mSbriQbJtEbxk0LzkiE6EitTrxQ3GntFMrhAcr9+0YlAGzf\n\
LMNTrM7U7cjhJX3114pB7q18LCW0uuDW5v+N3MVL8MXPmey8qpVdbTZ3R0wgZqJN\n\
L+Nq2nf+iQKBgAQbLVwVAtvHj7yApxgI1m27b9D6EQAm2rdaR1tclaQ7WyIgaZpZ\n\
aXFrF/55ZJpwG4LlbyqZHxfZWWJ0S+ryPQ66wRvPg2QYu7ELWgDyZYBRmFmmjnbU\n\
M8zhtNk21bfIEMyf//d9Y2I/ZaDFgBR/B4RMK+Q2knDEm8l9qu5VDaJXAoGAGRdJ\n\
ZHnGRPlARk9YIt70aRQO3LXZb+F5Osf9A+o6jiQEtFaSD3rJ4vO37z3fLAWqFiiW\n\
+DeOZ9Fb5sRUUVIlcXSTb00l6+71X/Gej2oc4+OR7yoe6Fkar0N9Z2lSRfFOk9z/\n\
jRklUOWCZ2reYaHjSvGa07dCuvL/bDx6uEzEfgkCgYAsNGlD4pegebSmdEsOduKK\n\
/C5ZpQYyzUxDr8yOktiwNk9b7LmuqO3MPXBxd4yeuplFXS/7qLZMHSl5lqfQJN6K\n\
necC1NhrKysGZiYJdI59/RZ5Nlzy1hufipFlwwKXOTE6vjtbARGR9LsfFi1o0PFm\n\
HGqo2n13BWKoeOrRg5AmlQ==\n\
-----END PRIVATE KEY-----");

const std::string CertStore::CaCert("-----BEGIN CERTIFICATE-----\n\
MIIDnTCCAoWgAwIBAgIUOfPCYQQmB4rDP3iLfXqc1dSLAJ8wDQYJKoZIhvcNAQEL\n\
BQAwXTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\n\
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEWMBQGA1UEAwwNUkluc3RhbGxlciBD\n\
QTAgFw0yNDAyMDQwNzEwMTNaGA8yMTI0MDExMTA3MTAxM1owXTELMAkGA1UEBhMC\n\
VVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp\n\
dHMgUHR5IEx0ZDEWMBQGA1UEAwwNUkluc3RhbGxlciBDQTCCASIwDQYJKoZIhvcN\n\
AQEBBQADggEPADCCAQoCggEBALOazdrDCJKZE5P7vqHEUcONSbFBGcnmB311qLdr\n\
LQbNQi3CmKjecVkGisOOwthoCwBZCArH3jjgsgqoOT/26aI8paI65PTeRkh7FwmV\n\
aPv1p2yY1gyMkLlUg+kecWr7w0wP6hsZmYK/VPtqQqwrViAN4N3A2G15YqwtuaKm\n\
ZzLm1qfewnmHHHDxCxCCxmAZGBRW7n6eTnulENdCn6uWJGIjqFN7z67hpBkAbJv5\n\
IrX7f0gHtajvexQZ1XyK6Uor6YzB0kosKPIj0M6n+fPiy3/0GKILmY+0iUY2vgqb\n\
dPLK7QTDF9TjxAgIQPRkiUiTzWH20GIZrPLZoTYw5jVOySsCAwEAAaNTMFEwHQYD\n\
VR0OBBYEFPxVU6ZQWXlYhYH1OD2Amq5W3k5UMB8GA1UdIwQYMBaAFPxVU6ZQWXlY\n\
hYH1OD2Amq5W3k5UMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\n\
AInSH8k/GAw/FhigMoYJZMQLcqQYG7jDLlbsDJrTM9Y71JxfsMEwfY6rVQRM0Xwp\n\
cXpqYKEPcZhHd12yj73NqZd7yt++6OqlIp5y52sJeYpuEkX2Se+il9E2WRwSHxYc\n\
su1cnKf8uj6Vqdmr8Ek272QwuE9Qcf0/qXfFuw/LfV3c2tgzTHAY81JWNsBUHHMC\n\
ih2l9ZhaHCHOJRkQzstg5sTRLHvuzT7NxvfNbQcqX2ERyLO7e02LzM2tPn+8sywv\n\
xjxLrdGTYt58hx/a9qw0/RVTuCG74DEhyiBfvASFRsQjN9EWWOs3rF9kRrJoNDkc\n\
uR38HomSTm2EWe+M1sP4rAA=\n\
-----END CERTIFICATE-----");

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
    CaPrivateKey(NewMbedTlsPkContext(), FreeMbedTlsPkContext),
    CaCertificate(NewMbedTlsCertContext(), FreeMbedTlsCertContext),
    BackingDir(backingDir),
    PrivateKey(NewMbedTlsPkContext(), FreeMbedTlsPkContext),
    Certificate(NewMbedTlsCertContext(), FreeMbedTlsCertContext),
    AllowedCertificates(filesystem::path(backingDir).append(AllowedCertificatesFileName)),
    DeniedCertificates(filesystem::path(backingDir).append(DeniedCertificatesFileName))
{
    if (auto ret = mbedtls_pk_parse_key(CaPrivateKey.get(), (const unsigned char*)CaKey.data(), CaKey.length() + 1, nullptr, 0, mbedtls_ctr_drbg_random, MbedtlsMgr::GetInstance().Ctr_Drdbg()); ret != 0)
    {
        throw runtime_error(format("Unable to load CA key. Err code: {}", ret));
    }
    if (auto ret = mbedtls_x509_crt_parse(CaCertificate.get(), (const unsigned char*)CaCert.data(), CaCert.length() + 1); ret != 0)
    {
        throw runtime_error(format("Unable to load CA certificate. Err code: {}", ret));
    }

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
        auto generated = GenerateKeyAndCertificateDer(CaPrivateKey.get(), CaCertificate.get());
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
    mbedtls_ssl_conf_authmode(sslConfig.get(), MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(sslConfig.get(), CaCertificate.get(), nullptr);

    mbedtls_ssl_conf_verify(sslConfig.get(), &MbedTlsIOStreamInteractiveCertVerification, (void*)this);
    if (auto ret = mbedtls_ssl_conf_own_cert(sslConfig.get(), GetCertificate(), GetPrivateKey()); ret != 0)
    {
        throw runtime_error(format("Failed setting ssl certificate. Err code: {}", ret));
    }

    return sslConfig;
}

tuple<vector<unsigned char>, vector<unsigned char>> CertStore::GenerateKeyAndCertificateDer(mbedtls_pk_context* caKey, mbedtls_x509_crt* caCert)
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

    
    mbedtls_x509write_crt_set_md_alg(crt.get(), MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(crt.get(), key.get());
    mbedtls_x509write_crt_set_issuer_key(crt.get(), caKey);
    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);
    mbedtls_mpi_lset(&serial, 1);
    if (auto ret = mbedtls_x509write_crt_set_serial(crt.get(), &serial); ret != 0)
    {
        throw runtime_error(format("Unable to generate certificate. Err code: {}", ret));
    }
    mbedtls_mpi_free(&serial);

    const string subjName(string("CN=").append(CertStore::HostName));
    if (auto ret = mbedtls_x509write_crt_set_subject_name(crt.get(), subjName.c_str()); ret != 0)
    {
        throw runtime_error(format("Unable to generate certificate. Err code: {}", ret));
    }

    vector<char> buffer(128);
    mbedtls_x509_dn_gets(buffer.data(), buffer.size(), &caCert->subject);
    if (auto ret = mbedtls_x509write_crt_set_issuer_name(crt.get(), buffer.data()); ret != 0)
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
    return -1;
}
