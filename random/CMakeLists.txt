project(random VERSION ${PROJECT_VERSION})

set(RANDOM_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/random")

add_library(${PROJECT_NAME} SHARED random.cpp)

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "_")

set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${RANDOM_OUTPUT_DIRECTORY})

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE Argon::ArgonVM bcrypt.lib)
else ()
    target_link_libraries(${PROJECT_NAME} PRIVATE Argon::ArgonVM)
endif ()

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/random.ar" ${RANDOM_OUTPUT_DIRECTORY})