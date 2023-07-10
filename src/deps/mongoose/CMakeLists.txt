set(CURRENT_TARGET_NAME mongoose)
add_library(${CURRENT_TARGET_NAME} STATIC)

target_include_directories(${CURRENT_TARGET_NAME}
PUBLIC
    src
PRIVATE
)

set(CURRENT_TARGET_SOURCES
    src/mongoose.h
    src/mongoose.c
)

target_sources(${CURRENT_TARGET_NAME}
PRIVATE
    ${CURRENT_TARGET_SOURCES}
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${CURRENT_TARGET_SOURCES})
