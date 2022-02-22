#ifndef __included_upf_ipfix_h__
#define __included_upf_ipfix_h__


#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vnet/ipfix-export/flow_report.h>
#include <vnet/ipfix-export/flow_report_classify.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#include "flowtable.h"

/* Default timers in seconds */
#define UPF_IPFIX_TIMER_ACTIVE   (5) // FIXME: use different value

typedef enum
  {
    FLOW_RECORD_L2 = 1 << 0,
    FLOW_RECORD_L3 = 1 << 1,
    FLOW_RECORD_L4 = 1 << 2,
    FLOW_RECORD_L2_IP4 = 1 << 3,
    FLOW_RECORD_L2_IP6 = 1 << 4,
    FLOW_N_RECORDS = 1 << 5,
  } upf_ipfix_record_t;

/* *INDENT-OFF* */
typedef enum __attribute__ ((__packed__))
  {
    FLOW_VARIANT_IP4,
    FLOW_VARIANT_IP6,
    FLOW_VARIANT_L2,
    FLOW_VARIANT_L2_IP4,
    FLOW_VARIANT_L2_IP6,
    FLOW_N_VARIANTS,
  } upf_ipfix_variant_t;
/* *INDENT-ON* */

STATIC_ASSERT (sizeof (upf_ipfix_variant_t) == 1,
	       "upf_ipfix_variant_t is expected to be 1 byte, "
	       "revisit padding in upf_ipfix_key_t");

#define FLOW_MAXIMUM_EXPORT_ENTRIES	(1024)

typedef struct
{
  /* what to collect per variant */
  upf_ipfix_record_t flags;
  /** ipfix buffers under construction, per-worker thread */
  vlib_buffer_t **buffers_per_worker;
  /** frames containing ipfix buffers, per-worker thread */
  vlib_frame_t **frames_per_worker;
  /** next record offset, per worker thread */
  u16 *next_record_offset_per_worker;
} upf_ipfix_protocol_context_t;

/**
 * @file
 * @brief flow-per-packet plugin header file
 */
typedef struct
{
  upf_ipfix_protocol_context_t context[FLOW_N_VARIANTS];
  u16 template_reports[FLOW_N_RECORDS];
  u16 template_size[FLOW_N_RECORDS];

  u32 vlib_time_0;

  upf_ipfix_record_t record;
  u32 active_timer;

  bool initialized;
  bool disabled;

  u16 template_per_flow[FLOW_N_VARIANTS];
  u8 *flow_per_interface;

  /** convenience vlib_main_t pointer */
  vlib_main_t *vlib_main;
  /** convenience vnet_main_t pointer */
  vnet_main_t *vnet_main;
} upf_ipfix_main_t;

u8 *format_upf_ipfix_entry (u8 * s, va_list * args);

clib_error_t * upf_ipfix_init (vlib_main_t * vm);

#endif
