set(MBEDTLS_AS_SUBPROJECT ON CACHE BOOL "")
set(ENABLE_PROGRAMS OFF CACHE BOOL "")
set(ENABLE_TESTING OFF CACHE BOOL "")
set(INSTALL_MBEDTLS_HEADERS OFF CACHE BOOL "")

add_subdirectory(src)

set(CURRENT_TARGET_PLATFORM_DEFINES "")

if(CMAKE_TOOLCHAIN_FILE)
    get_filename_component(CMAKE_TOOLCHAIN_FILENAME ${CMAKE_TOOLCHAIN_FILE} NAME)

    if(CMAKE_TOOLCHAIN_FILENAME STREQUAL "Switch.cmake")
        list(APPEND CURRENT_TARGET_PLATFORM_DEFINES
            unix
            _POSIX_VERSION=199309L
        )
    endif()
endif()


target_compile_definitions(mbedcrypto
PUBLIC
    ${CURRENT_TARGET_PLATFORM_DEFINES}
)

target_compile_definitions(mbedx509
PUBLIC
    ${CURRENT_TARGET_PLATFORM_DEFINES}
)

target_compile_definitions(mbedtls
PUBLIC
    ${CURRENT_TARGET_PLATFORM_DEFINES}
)
