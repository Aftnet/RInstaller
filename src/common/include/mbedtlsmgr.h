#pragma once

#include <memory>

struct mbedtls_entropy_context;
struct mbedtls_ctr_drbg_context;

namespace RInstaller
{
    class MbedtlsMgr
    {
    private:
        std::unique_ptr<mbedtls_entropy_context, void(*)(mbedtls_entropy_context*)> MbedTLS_Entropy;
        std::unique_ptr<mbedtls_ctr_drbg_context, void(*)(mbedtls_ctr_drbg_context*)> MbedTLS_Ctr_Drdbg;

        MbedtlsMgr();
        ~MbedtlsMgr() {};

    public:
        static MbedtlsMgr& GetInstance()
        {
            static MbedtlsMgr instance;
            return instance;
        }

        inline mbedtls_entropy_context* Entropy() const { return MbedTLS_Entropy.get(); }
        inline mbedtls_ctr_drbg_context* Ctr_Drdbg() const { return MbedTLS_Ctr_Drdbg.get(); }

        MbedtlsMgr(const MbedtlsMgr&) = delete;
        void operator=(const MbedtlsMgr&) = delete;

        static void DebugPrint(void* ctx, int level, const char* file, int line, const char* str);
    };
}
