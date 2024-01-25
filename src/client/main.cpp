#include <iostream>

#include "certstore.h"
#include "mbedtlsmgr.h"

int main()
{
    auto& mbedtlsmgr = MbedtlsMgr::GetInstance();
    CertStore store(std::filesystem::current_path());

    return 0;
}
