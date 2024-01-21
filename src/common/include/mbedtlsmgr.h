#pragma once

#include <memory>

struct mbedtls_entropy_context;
struct mbedtls_ctr_drbg_context;

class MbedtlsMgr
{
private:
    std::shared_ptr<mbedtls_entropy_context> MbedTLS_Entropy;
    std::shared_ptr<mbedtls_ctr_drbg_context> MbedTLS_Ctr_Drdbg;

    MbedtlsMgr();
    ~MbedtlsMgr() {};

public:
    static MbedtlsMgr& GetInstance()
    {
        static MbedtlsMgr instance;
        return instance;
    }

    inline std::shared_ptr<mbedtls_entropy_context> Entropy() const { return MbedTLS_Entropy; }
    inline std::shared_ptr<mbedtls_ctr_drbg_context> Ctr_Drdbg() const { return MbedTLS_Ctr_Drdbg; }

    MbedtlsMgr(const MbedtlsMgr&) = delete;
    void operator=(const MbedtlsMgr&) = delete;
};
