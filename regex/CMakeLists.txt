project(regex VERSION ${PROJECT_VERSION})

add_library(${PROJECT_NAME} SHARED
        match.cpp
        pattern.cpp
        regex.cpp)

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")

target_link_libraries(${PROJECT_NAME} PRIVATE Argon::ArgonVM pcre2-8)
