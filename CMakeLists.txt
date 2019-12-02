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

add_executable(service-checker main.cpp)

include_directories(${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR})

if(WIN32)
    target_link_libraries(service-checker libssh2)
endif()

if(UNIX)
    include(~/vcpkg/scripts/buildsystems/vcpkg.cmake)
    
    set_property(TARGET service-checker PROPERTY CXX_STANDARD 11)
    
    find_package(libssh CONFIG REQUIRED)
    find_package(CLI11 CONFIG REQUIRED)
    
    target_link_libraries(service-checker PRIVATE ${LIBSSH_LIBRARIES} CLI11::CLI11)
    target_include_directories(service-checker PRIVATE ${LIBSSH_INCLUDE_DIRS})
endif()
