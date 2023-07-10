#include <ctime>
#include <iostream>
#include <string>

#include "globals.hpp"
#include "mongoose.h"

static void fn(struct mg_connection* c, int ev, void* ev_data, void* fn_data)
{
    if (ev == MG_EV_HTTP_MSG)
    {
        mg_http_reply(c, 200, "", "{%m:%d}\n", MG_ESC("status"), 1);
    }
}

int main()
{
    struct mg_mgr mgr;
    mg_mgr_init(&mgr);                                      // Init manager
    mg_http_listen(&mgr, "http://0.0.0.0:8000", fn, NULL);  // Setup listener
    for (;;) mg_mgr_poll(&mgr, 1000);                       // Infinite event loop

    return 0;
}
