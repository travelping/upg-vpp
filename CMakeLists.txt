# TBD: license (udpi etc.)

project(upf-plugin)

cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
include(cmake/misc.cmake)
include(cmake/Packager.cmake)

find_package(VPP REQUIRED)

# Standard installation directories.
include(GNUInstallDirs)

# Control where libraries and executables are placed during the build.
set(VPP_LIBRARY_DIR ${CMAKE_INSTALL_LIBDIR})

if (CMAKE_BUILD_TYPE STREQUAL "Release")
   set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall -O3 -g")
elseif (CMAKE_BUILD_TYPE STREQUAL "Debug")
   set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g")
   add_definitions(-DCLIB_DEBUG -DVLIB_BUFFER_TRACE_TRAJECTORY -fPIC -fstack-protector-all)
endif()

add_subdirectory(upf)

make_packages()

##############################################################################
# print configuration
##############################################################################
message(STATUS "Configuration:")
pr("Build type" ${CMAKE_BUILD_TYPE})
pr("C compiler" "${CMAKE_C_COMPILER} (${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION})")
pr("C flags" ${CMAKE_C_FLAGS}${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UC}})
pr("Linker flags (apps)" ${CMAKE_EXE_LINKER_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UC}})
pr("Linker flags (libs)" ${CMAKE_SHARED_LINKER_FLAGS} ${CMAKE_SHARED_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UC}})
pr("Host processor" ${CMAKE_HOST_SYSTEM_PROCESSOR})
pr("Target processor" ${CMAKE_SYSTEM_PROCESSOR})
pr("Prefix path" ${CMAKE_PREFIX_PATH})
pr("Install prefix" ${CMAKE_INSTALL_PREFIX})
pr("Library dir" ${VPP_LIBRARY_DIR})
