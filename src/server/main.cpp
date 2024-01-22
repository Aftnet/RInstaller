#include <ctime>
#include <iostream>
#include <string>
#include <filesystem>

#include "certstore.h"
#include "mbedtlsmgr.h"

int main()
{
    auto& mbedtlsmgr = MbedtlsMgr::GetInstance();
    CertStore store(mbedtlsmgr, std::filesystem::current_path());

    return 0;
}
