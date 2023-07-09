add_executable(server)

target_sources(server
PRIVATE
    main.cpp
)

target_link_libraries(server
PUBLIC
    common
)
