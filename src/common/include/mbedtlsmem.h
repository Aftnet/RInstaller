#pragma once

struct mbedtls_ctr_drbg_context;
struct mbedtls_entropy_context;
struct mbedtls_pk_context;
struct mbedtls_ssl_config;
struct mbedtls_x509write_cert;
struct mbedtls_x509_crt;

class MbedtlsCtrDrdbgContext
{
	mbedtls_ctr_drbg_context* p;
};
