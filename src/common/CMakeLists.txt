add_library(common STATIC)

target_include_directories(common
PUBLIC
    include
PRIVATE
)

target_sources(common
PUBLIC
    include/protocol.h
PRIVATE
    empty.cpp
)

target_link_libraries(common
PUBLIC
    mongoose
)
