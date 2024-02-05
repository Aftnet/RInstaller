add_library(common STATIC)

target_include_directories(common
PUBLIC
    include
PRIVATE
)

target_sources(common
PUBLIC
    include/certstore.h
    include/client.h
    include/mbedtlsmgr.h
    include/protocol.h
    include/server.h
PRIVATE
    certstore.cpp
    client.cpp
    mbedtlsmgr.cpp
    server.cpp
)

target_link_libraries(common
PUBLIC
    mbedtls
)
