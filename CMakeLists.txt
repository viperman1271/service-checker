cmake_minimum_required (VERSION 2.6)
project (service-checker)

set (service-checker_VERSION_MAJOR 1)
set (service-checker_VERSION_MINOR 0)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/service-checker.hxx"
  "${PROJECT_BINARY_DIR}/service-checker.generated.h"
  )
  
# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/service-checker.hxx"
  "${PROJECT_BINARY_DIR}/service-checker.generated.h"
  )

add_executable(service-checker main.cpp queryAnswerType.h queryDnsType.h objectmodel/queryInfo.h objectmodel/queryResult.h)

include_directories(${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR})

if(WIN32)
    find_package(libssh REQUIRED)
    target_link_libraries(service-checker libssh)
    target_include_directories(service-checker PRIVATE libssh)
endif()

if(UNIX)
    include(~/vcpkg/scripts/buildsystems/vcpkg.cmake)
    find_package(libssh REQUIRED)
    target_link_libraries(libssh)
    target_include_directories(service-checker PRIVATE libssh)
endif()
