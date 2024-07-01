project(hashlib VERSION ${PROJECT_VERSION})

set(HASHLIB_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/hashlib")

# *** Find OpenSSL ***
find_package(OpenSSL REQUIRED)

add_library(${PROJECT_NAME} SHARED hashlib.cpp)

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "_")

set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${HASHLIB_OUTPUT_DIRECTORY})
set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${HASHLIB_OUTPUT_DIRECTORY})

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE Argon::ArgonVM OpenSSL::SSL)
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE Argon::ArgonVM OpenSSL::SSL)
endif ()

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/hashlib.ar" ${HASHLIB_OUTPUT_DIRECTORY}/hashlib.ar)