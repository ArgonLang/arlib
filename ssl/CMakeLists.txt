project(ssl VERSION ${PROJECT_VERSION})

set(SSL_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ssl")

# *** Find OpenSSL ***
find_package(OpenSSL REQUIRED)

add_library(${PROJECT_NAME} SHARED
        context.cpp
        ssl.cpp)

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "_")

set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${SSL_OUTPUT_DIRECTORY})

target_link_libraries(${PROJECT_NAME} PRIVATE Argon::ArgonVM OpenSSL::SSL)
