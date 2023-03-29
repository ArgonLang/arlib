project(regex VERSION ${PROJECT_VERSION})

add_library(${PROJECT_NAME} SHARED
        src/regex.cpp)

set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_NAME "regex")

target_link_libraries(regex Argon::ArgonVM)
