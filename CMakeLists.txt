cmake_minimum_required(VERSION 3.15)
project(ARLib VERSION 0.1.0)

set(BASE_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BASE_OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BASE_OUTPUT_DIRECTORY})

set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)

if (MSVC)
    set(CMAKE_CXX_STANDARD 20)
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif ()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.h.in" "${CMAKE_CURRENT_SOURCE_DIR}/version.h")

find_package(Stratum REQUIRED)
find_package(Argon REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# *** Configure Argon scripts ***

set(SCRIPTS_DIRECTORY "${PROJECT_SOURCE_DIR}/scripts")

file(GLOB_RECURSE SCRIPTS "${SCRIPTS_DIRECTORY}/*.ar")
foreach(SCRIPT ${SCRIPTS})
    string(REPLACE ${SCRIPTS_DIRECTORY} ${BASE_OUTPUT_DIRECTORY} SCRIPT_DEST ${SCRIPT})
    configure_file(${SCRIPT} ${SCRIPT_DEST})
endforeach()

# *** Native modules ***

add_subdirectory(random)
add_subdirectory(regex)
add_subdirectory(ssl)
