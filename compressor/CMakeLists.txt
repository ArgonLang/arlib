project(compressor VERSION ${PROJECT_VERSION})

set(COMPRESSOR_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/compressor")

set(MODULE_LZMA lzma)

# *** Find libLZMA ***
find_package(LibLZMA CONFIG REQUIRED)

add_library(${PROJECT_NAME} SHARED compressor.cpp)
add_library(${MODULE_LZMA} SHARED lzma.cpp)

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")

# LZMA
set_target_properties(${MODULE_LZMA} PROPERTIES PREFIX "_")

set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${COMPRESSOR_OUTPUT_DIRECTORY})
set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${COMPRESSOR_OUTPUT_DIRECTORY})

# LZMA
set_target_properties(${MODULE_LZMA} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${COMPRESSOR_OUTPUT_DIRECTORY})
set_target_properties(${MODULE_LZMA} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${COMPRESSOR_OUTPUT_DIRECTORY})

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE Argon::ArgonVM)

    # LZMA
    target_link_libraries(${MODULE_LZMA} PRIVATE Argon::ArgonVM liblzma::liblzma)
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE Argon::ArgonVM)

    # LZMA
    target_link_libraries(${MODULE_LZMA} PRIVATE Argon::ArgonVM liblzma::liblzma)
endif ()

add_custom_command(TARGET ${MODULE_LZMA} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/lzma.ar" ${COMPRESSOR_OUTPUT_DIRECTORY}/lzma.ar)