#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"

    const int RINST_PORT_NUMBER = 42743;

    enum rinst_message_type
    {
        CONNECT,
    };

    struct rinst_message
    {
        uint8_t type;
        uint32_t length;
    };

#ifdef __cplusplus
}
#endif
