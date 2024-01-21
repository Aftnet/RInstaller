add_library(common STATIC)

target_include_directories(common
PUBLIC
    include
PRIVATE
)

target_sources(common
PUBLIC
    include/certstore.h
    include/mbedtlsmgr.h
    include/protocol.h
PRIVATE
    certstore.cpp
    mbedtlsmgr.cpp
)

target_link_libraries(common
PUBLIC
    mbedtls
)
