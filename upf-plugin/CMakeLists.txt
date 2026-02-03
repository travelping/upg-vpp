# TBD: license (udpi etc.)

cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

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
include_directories(${VPP_INCLUDE_DIR}/vpp_plugins)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-route-3.0)

# Include the directories for libnl
include_directories(${LIBNL_INCLUDE_DIRS})

# sources
set(DEST_DIR "${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/upf")

set(UPF_PLUGIN_SOURCES
    upf/adf/adf.c
    upf/adf/cli.c
    upf/adf/dpi.c
    upf/adf/matcher.c
    upf/core/upf_types.c
    upf/flow/flowtable_init.c
    upf/flow/flowtable.c
    upf/flow/upf_flow_classify_node.c
    upf/flow/upf_flow_node.c
    upf/integrations/upf_ipfix_templates.c
    upf/integrations/upf_ipfix.c
    upf/integrations/upf_netcap_node.c
    upf/integrations/upf_netcap.c
    upf/integrations/upf_ueip_export.c
    upf/nat/nat_cli.c
    upf/nat/nat_dpo_node.c
    upf/nat/nat_dpo.c
    upf/nat/nat_flow.c
    upf/nat/nat_format.c
    upf/nat/nat_forward_node.c
    upf/nat/nat_icmp_flow.c
    upf/nat/nat.c
    upf/pfcp/pfcp_proto.c
    upf/pfcp/upf_nwi.c
    upf/pfcp/upf_pfcp_assoc.c
    upf/pfcp/upf_pfcp_handlers_mt.c
    upf/pfcp/upf_pfcp_handlers.c
    upf/pfcp/upf_pfcp_server.c
    upf/pfcp/upf_pfcp_session_server.c
    upf/pfcp/upf_session.c
    upf/proxy/upf_proxy_accept_node.c
    upf/proxy/upf_proxy_input_node.c
    upf/proxy/upf_proxy_output_node.c
    upf/proxy/upf_proxy_reset_node.c
    upf/proxy/upf_proxy_tcp_bypass_node.c
    upf/proxy/upf_proxy.c
    upf/rules/upf_acl.c
    upf/rules/upf_classify.c
    upf/rules/upf_flowless_node.c
    upf/rules/upf_forward_node.c
    upf/rules/upf_forwarding_policy.c
    upf/rules/upf_gtpu_decap_node.c
    upf/rules/upf_gtpu_echo_req_node.c
    upf/rules/upf_gtpu_encap_node.c
    upf/rules/upf_gtpu_error_ind_node.c
    upf/rules/upf_gtpu.c
    upf/rules/upf_ipfilter.c
    upf/rules/upf_rules.c
    upf/rules/upf_session_dpo_node.c
    upf/rules/upf_session_dpo.c
    upf/sxu/upf_session_update.c
    upf/sxu/upf_sxu_1_provide_actions.c
    upf/sxu/upf_sxu_2_update_dynamic.c
    upf/sxu/upf_sxu_3_compile_rules.c
    upf/sxu/upf_sxu_45_rpc.c
    upf/sxu/upf_sxu_format.c
    upf/sxu/upf_sxu_meta.c
    upf/unittest.c
    upf/upf_api.c
    upf/upf_cli.c
    upf/upf_stats_periodic.c
    upf/upf_stats.c
    upf/upf.c
    upf/utils/ip_helpers.c
    upf/utils/upf_handoff_template.c
    upf/utils/upf_localids.c
    upf/utils/upf_mt.c
    upf/utils/upf_timer.c
    )

set(UPF_PLUGIN_HEADER_FILES
    upf/adf/adf.h
    upf/adf/matcher.h
    upf/core/upf_buffer_opaque.h
    upf/core/upf_types.h
    upf/external/netcap.h
    upf/flow/flowtable_inlines.h
    upf/flow/flowtable_tcp.h
    upf/flow/flowtable.h
    upf/integrations/upf_ipfix_templates.h
    upf/integrations/upf_ipfix.h
    upf/integrations/upf_netcap.h
    upf/integrations/upf_ueip_export.h
    upf/nat/nat_dpo.h
    upf/nat/nat_node_inlines.h
    upf/nat/nat_private.h
    upf/nat/nat.h
    upf/pfcp/pfcp_proto.h
    upf/pfcp/upf_nwi.h
    upf/pfcp/upf_pfcp_assoc.h
    upf/pfcp/upf_pfcp_handlers.h
    upf/pfcp/upf_pfcp_server.h
    upf/pfcp/upf_session_report.h
    upf/pfcp/upf_session.h
    upf/proxy/upf_proxy.h
    upf/rules/upf_acl.h
    upf/rules/upf_classify_inlines.h
    upf/rules/upf_classify.h
    upf/rules/upf_forwarding_policy.h
    upf/rules/upf_gtpu_proto.h
    upf/rules/upf_gtpu.h
    upf/rules/upf_ipfilter.h
    upf/rules/upf_rules.h
    upf/rules/upf_session_dpo.h
    upf/sxu/upf_session_update.h
    upf/sxu/upf_sxu_inlines.h
    upf/upf_limits.h
    upf/upf_stats.h
    upf/upf_wk.h
    upf/upf.h
    upf/utils/common.h
    upf/utils/heap_handle.h
    upf/utils/ip_helpers.h
    upf/utils/ip_mask.h
    upf/utils/llist.h
    upf/utils/pool_claim.h
    upf/utils/ratelimit_atomic.h
    upf/utils/worker_pool.h
    upf/utils/tokenbucket.h
    upf/utils/upf_handoff_template.h
    upf/utils/upf_localids.h
    upf/utils/upf_mt.h
    upf/utils/upf_timer.h
    upf/version.h
    )

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

add_compile_options(-Wall -Wno-address-of-packed-member)
add_compile_options(-march=corei7 -mtune=corei7-avx)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_compile_options(-g -O3)
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_options(-g -O0 -fsanitize=address -ftrivial-auto-var-init=pattern -fPIC -fstack-protector-all)
  add_link_options(-fsanitize=address)

  add_definitions(-DCLIB_DEBUG -DVLIB_BUFFER_TRACE_TRAJECTORY)
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
target_link_libraries(upf_plugin ${LIBNL_LIBRARIES})

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
