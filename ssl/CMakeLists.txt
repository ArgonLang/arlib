project(ssl VERSION ${PROJECT_VERSION})

set(SSL_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ssl")

# *** Find OpenSSL ***
find_package(OpenSSL REQUIRED)

add_library(${PROJECT_NAME} SHARED
        context.cpp
        socket.cpp
        ssl.cpp
        winssl.cpp)

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "_")

set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${SSL_OUTPUT_DIRECTORY})

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE Argon::ArgonVM OpenSSL::SSL crypt32.lib)
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE Argon::ArgonVM OpenSSL::SSL)
endif ()

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/ssl.ar" ${SSL_OUTPUT_DIRECTORY})