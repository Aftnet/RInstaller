add_executable(client)

target_sources(client
PRIVATE
    main.cpp
)

target_link_libraries(client
PUBLIC
    common
)
