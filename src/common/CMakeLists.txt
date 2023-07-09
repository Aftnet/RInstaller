add_library(common STATIC)

target_include_directories(deps
PUBLIC
    interface
PRIVATE
)

target_sources(common
PUBLIC
    interface/globals.hpp
PRIVATE
    empty.cpp
)

target_link_libraries(common
PUBLIC
    asio
)
