# TBD: license (udpi etc.)

include_directories(${CMAKE_SOURCE_DIR})

# for generated API headers:
include_directories(${CMAKE_BINARY_DIR})

# Dependencies

message(STATUS "Looking for hyperscan")
find_package(PkgConfig REQUIRED)
pkg_check_modules(HS libhs)

if(HS_FOUND)
  include_directories(${HS_INCLUDE_DIRS})
  message(STATUS "Found Hyperscan in ${HYPERSCAN_INCLUDE_DIRS}")
else()
  message(WARNING "-- Hyperscan not found")
endif()

message(STATUS "Looking for Hyperscan")
find_path(HYPERSCAN_INCLUDE_DIR NAMES hs/hs.h)
find_library(HYPERSCAN_LIB1 NAMES hs)
find_library(HYPERSCAN_LIB2 NAMES hs_runtime)
set (HYPERSCAN_LIB ${HYPERSCAN_LIB1} ${HYPERSCAN_LIB2})
if(HYPERSCAN_INCLUDE_DIR AND HYPERSCAN_LIB)
  include_directories(${HYPERSCAN_INCLUDE_DIR})
  message(STATUS "Found Hyperscan in ${HYPERSCAN_INCLUDE_DIR}")
else()
  message(WARNING "-- Hyperscan not found")
endif()

add_vpp_plugin(upf
  SOURCES
  upf.c
  upf_api.c
  upf_cli.c
  upf_gtpu_encap.c
  upf_gtpu_decap.c
  upf_flow_node.c
  upf_classify.c
  upf_adf.c
  upf_input.c
  upf_forward.c
  upf_session_dpo.c
  pfcp.c
  upf_pfcp.c
  upf_pfcp_api.c
  upf_pfcp_server.c
  upf_pfcp_session_server.c
  upf_proxy_accept.c
  upf_proxy_input.c
  upf_proxy_output.c
  upf_tcp_forward.c
  upf_proxy.c
  upf_app_db.c
  upf_ipfilter.c
  upf_app_dpo.c
  upf_ipfix.c
  upf_ipfix_templates.c
  upf_tw_timer_1t_3w_1024sl_ov.c
  upf_tw_timer_2t_1w_2048sl.c
  flowtable_init.c
  flowtable.c
  unittest.c

  # MULTIARCH_SOURCES
  upf_gtpu_encap.c
  upf_gtpu_decap.c
  upf_flow_node.c
  upf_classify.c
  upf_proxy_accept.c
  upf_proxy_input.c
  upf_proxy_output.c
  upf_tcp_forward.c
  upf_input.c
  upf_forward.c
  upf_session_dpo.c

  INSTALL_HEADERS
  upf.h
  pfcp.h
  upf_pfcp.h
  upf_pfcp_api.h
  upf_pfcp_server.h
  upf_proxy.h
  upf_app_db.h
  upf_ipfilter.h
  upf_app_dpo.h
  upf_app_db.h
  flowtable.h
  flowtable_tcp.h
  upf_ipfix.h
  upf_ipfix_templates.h
  upf_tw_timer_1t_3w_1024sl_ov.h
  upf_tw_timer_2t_1w_2048sl.h
  upf_tw_timer_template.h
  upf_gtpu_error.def
  version.h

  API_FILES
  upf.api

  LINK_LIBRARIES
  ${HYPERSCAN_LIB}

  COMPONENT upf-plugin
)
