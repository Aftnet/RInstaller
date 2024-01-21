#include <ctime>
#include <iostream>
#include <string>

#include "certstore.h"
#include "mbedtlsmgr.h"

int main()
{
    auto& mbedtlsmgr = MbedtlsMgr::GetInstance();

    CertStore store(mbedtlsmgr);

    return 0;
}
