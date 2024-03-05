# TBD: license (udpi etc.)

cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

set(CMAKE_C_COMPILER_NAMES
    clang-13
    clang-12
    clang-11
    clang-10
    clang-9
    gcc-10
    gcc-9
    cc)

project(upf-plugin)

# rm
set(CMAKE_VERBOSE_MAKEFILE ON)

include(GNUInstallDirs)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)

# Check for memfd_create syscall
include(CheckSymbolExists)
check_symbol_exists("__NR_memfd_create" "sys/syscall.h" HAVE_MEMFD_CREATE)
if(HAVE_MEMFD_CREATE)
  add_definitions(-DHAVE_MEMFD_CREATE)
endif()

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(UPF_PLUGIN upf-plugin)
endif()

include(Packager)

# Dependencies
message(STATUS "Looking for Hyperscan")
find_path(HYPERSCAN_INCLUDE_DIR NAMES hs/hs.h)
find_library(HYPERSCAN_LIB1 NAMES hs)
find_library(HYPERSCAN_LIB2 NAMES hs_runtime)
set(HYPERSCAN_LIB ${HYPERSCAN_LIB1} ${HYPERSCAN_LIB2})
if(HYPERSCAN_INCLUDE_DIR AND HYPERSCAN_LIB)
  include_directories(${HYPERSCAN_INCLUDE_DIR})
  message(STATUS "Found Hyperscan in ${HYPERSCAN_INCLUDE_DIR}")
else()
  message(WARNING "-- Hyperscan not found")
endif()

find_package(VPP REQUIRED)

include_directories(${VPP_INCLUDE_DIR})

# sources
set(DEST_DIR "${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/upf")

set(UPF_PLUGIN_SOURCES
    upf/upf.c
    upf/upf_api.c
    upf/upf_cli.c
    upf/upf_gtpu_encap.c
    upf/upf_gtpu_decap.c
    upf/upf_flow_node.c
    upf/upf_classify.c
    upf/upf_adf.c
    upf/upf_input.c
    upf/upf_forward.c
    upf/upf_session_dpo.c
    upf/pfcp.c
    upf/upf_pfcp.c
    upf/upf_pfcp_api.c
    upf/upf_pfcp_server.c
    upf/upf_pfcp_session_server.c
    upf/upf_proxy_accept.c
    upf/upf_proxy_input.c
    upf/upf_proxy_output.c
    upf/upf_tcp_forward.c
    upf/upf_proxy.c
    upf/upf_app_db.c
    upf/upf_ipfilter.c
    upf/upf_app_dpo.c
    upf/upf_ipfix.c
    upf/upf_ipfix_templates.c
    upf/flowtable_init.c
    upf/flowtable.c
    upf/unittest.c
    upf/upf_gtpu_encap.c
    upf/upf_gtpu_decap.c
    upf/upf_flow_node.c
    upf/upf_classify.c
    upf/upf_proxy_accept.c
    upf/upf_proxy_input.c
    upf/upf_proxy_output.c
    upf/upf_tcp_forward.c
    upf/upf_input.c
    upf/upf_forward.c
    upf/upf_session_dpo.c)

set(UPF_PLUGIN_HEADER_FILES
    upf/upf.h
    upf/pfcp.h
    upf/upf_pfcp.h
    upf/upf_pfcp_api.h
    upf/upf_pfcp_server.h
    upf/upf_proxy.h
    upf/upf_app_db.h
    upf/upf_ipfilter.h
    upf/upf_app_dpo.h
    upf/upf_app_db.h
    upf/flowtable.h
    upf/flowtable_tcp.h
    upf/upf_buffer_opaque.h
    upf/upf_ipfix.h
    upf/upf_ipfix_templates.h
    upf/upf_gtpu_error.def
    upf/version.h
    upf/llist.h)

set(UPF_API_GENERATED_FILES ${DEST_DIR}/upf.api.h ${DEST_DIR}/upf.api_types.h
                            ${DEST_DIR}/upf.api_enum.h)

set(UPF_VAPI_GENERATED_FILES ${DEST_DIR}/upf.api.vapi.h
                             ${DEST_DIR}/upf.api.vapi.hpp)

if(NOT VPP_HOME)
  set(VPP_HOME /usr)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
endif(NOT CMAKE_BUILD_TYPE)

set(UPF_INSTALL_PREFIX
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
    CACHE STRING "upf_install_prefix")

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(CMAKE_C_FLAGS_RELEASE
      "${CMAKE_C_FLAGS_RELEASE} -Wall -Wno-address-of-packed-member -march=corei7 -mtune=corei7-avx -O3 -g"
  )
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_C_FLAGS_DEBUG
      "${CMAKE_C_FLAGS_DEBUG} -Wall -Wno-address-of-packed-member -march=corei7 -mtune=corei7-avx -O0 -g"
  )
  add_definitions(-DCLIB_DEBUG -DVLIB_BUFFER_TRACE_TRAJECTORY -fPIC
                  -fstack-protector-all)
endif()

execute_process(COMMAND mkdir -p ${DEST_DIR})

add_custom_command(
  OUTPUT ${DEST_DIR}/upf.api.h ${DEST_DIR}/upf.api_types.h
         ${DEST_DIR}/upf.api_enum.h
  COMMAND
    ${VPP_HOME}/bin/vppapigen ARGS --includedir ${VPP_HOME}/include --input
    ${CMAKE_CURRENT_SOURCE_DIR}/upf/upf.api --output ${DEST_DIR}/upf.api.h
    --outputdir ${DEST_DIR}/
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/upf/upf.api
  OUTPUT ${DEST_DIR}/upf.api.json
  COMMAND
    ${VPP_HOME}/bin/vppapigen ARGS JSON --includedir ${VPP_HOME}/include --input
    ${CMAKE_CURRENT_SOURCE_DIR}/upf/upf.api --output ${DEST_DIR}/upf.api.json
    --outputdir ${CMAKE_CURRENT_BINARY_DIR}/vapi/
  OUTPUT ${DEST_DIR}/upf.api.vapi.h
  COMMAND python3 ${VPP_HOME}/share/vpp/vapi_c_gen.py ARGS
          ${DEST_DIR}/upf.api.json
  OUTPUT ${DEST_DIR}/upf.api.vapi.hpp
  COMMAND python3 ${VPP_HOME}/share/vpp/vapi_cpp_gen.py ARGS
          ${DEST_DIR}/upf.api.json)

include_directories(SYSTEM)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${DEST_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUPF_VPP_PLUGIN=1")
add_library(upf_plugin SHARED ${UPF_PLUGIN_SOURCES} ${UPF_API_GENERATED_FILES}
                              ${UPF_VAPI_GENERATED_FILES})
target_link_libraries(upf_plugin ${HYPERSCAN_LIB})

file(MAKE_DIRECTORY ${DEST_DIR}/upf)

# Copy header files
foreach(FILE ${UPF_PLUGIN_HEADER_FILES})
  # Get the path of the file relative to the source directory
  get_filename_component(DIR "${FILE}" DIRECTORY)

  # Make sure the destination directory exists
  file(MAKE_DIRECTORY "${DEST_DIR}/${DIR}")

  configure_file("${FILE}" "${DEST_DIR}/${DIR}" COPYONLY)
endforeach()

set(VPP_INSTALL_PLUGIN ${UPF_INSTALL_PREFIX}/vpp_plugins)

set_target_properties(
  upf_plugin
  PROPERTIES LINKER_LANGUAGE C
             INSTALL_RPATH ${VPP_INSTALL_PLUGIN}
             PREFIX "")

install(
  DIRECTORY
  DESTINATION ${VPP_INSTALL_PLUGIN}
  COMPONENT ${UPF_PLUGIN})

install(
  TARGETS upf_plugin
  DESTINATION ${VPP_INSTALL_PLUGIN}
  COMPONENT ${UPF_PLUGIN})

install(
  FILES ${DEST_DIR}/upf.api.json
  DESTINATION ${CMAKE_INSTALL_PREFIX}/share/vpp/api/plugins
  COMPONENT ${UPF_PLUGIN}-dev)

install(
  FILES ${UPF_API_HEADER_FILES} ${UPF_API_GENERATED_FILES}
  DESTINATION
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/vpp_plugins/upf
  COMPONENT ${UPF_PLUGIN}-dev)

install(
  FILES ${UPF_VAPI_GENERATED_FILES}
  DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/vapi
  COMPONENT ${UPF_PLUGIN}-dev)

make_packages()
