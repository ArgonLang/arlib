project(regex VERSION ${PROJECT_VERSION})

set(REGEX_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/regex")

# *** Find PCRE2 ***
find_library(PCRE2_LIB pcre2-8)

find_path(PCRE2_INCLUDE "pcre2.h")

add_library(${PROJECT_NAME} SHARED
        match.cpp
        pattern.cpp
        regex.cpp)

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "_")

set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${REGEX_OUTPUT_DIRECTORY})

target_include_directories(${PROJECT_NAME} PRIVATE ${PCRE2_INCLUDE})

target_link_libraries(${PROJECT_NAME} PRIVATE Argon::ArgonVM ${PCRE2_LIB})

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/regex.ar" ${REGEX_OUTPUT_DIRECTORY})