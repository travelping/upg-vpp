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

#define FLOW_MAXIMUM_EXPORT_ENTRIES	(1024)

typedef struct
{
  /** ipfix buffers under construction, per-worker thread */
  vlib_buffer_t **buffers_per_worker;
  /** frames containing ipfix buffers, per-worker thread */
  vlib_frame_t **frames_per_worker;
  /** next record offset, per worker thread */
  u16 *next_record_offset_per_worker;
  /** record size **/
  u16 rec_size;
  /** IPFIX template id **/
  u16 template_id;
} upf_ipfix_protocol_context_t;

typedef struct
{
  upf_ipfix_protocol_context_t context_ip4;
  upf_ipfix_protocol_context_t context_ip6;
} upf_ipfix_runtime_template_t;

/**
 * @file
 * @brief flow-per-packet plugin header file
 */
typedef struct
{
  upf_ipfix_runtime_template_t runtime_templates[UPF_IPFIX_N_POLICIES];

  u32 vlib_time_0;

  u32 active_timer;

  bool initialized;
  bool disabled;

  u8 *flow_per_interface;

  /** convenience vlib_main_t pointer */
  vlib_main_t *vlib_main;
  /** convenience vnet_main_t pointer */
  vnet_main_t *vnet_main;
} upf_ipfix_main_t;

u8 *format_upf_ipfix_entry (u8 * s, va_list * args);

clib_error_t * upf_ipfix_init (vlib_main_t * vm);

typedef ipfix_field_specifier_t * (*upf_ipfix_field_func_t) (ipfix_field_specifier_t *);
typedef u32 (*upf_ipfix_value_func_t) (vlib_buffer_t * to_b,
				       flow_entry_t * f,
				       flow_direction_t direction,
				       u16 offset,
				       upf_session_t *sx);

typedef struct
{
  char * name;
  u16 field_count;
  upf_ipfix_field_func_t add_ip4_fields;
  upf_ipfix_field_func_t add_ip6_fields;
  upf_ipfix_value_func_t add_ip4_values;
  upf_ipfix_value_func_t add_ip6_values;
} upf_ipfix_template_t;

extern upf_ipfix_template_t upf_ipfix_templates[];

always_inline upf_ipfix_protocol_context_t *
upf_ipfix_context (upf_ipfix_main_t * fm, bool ip6, upf_ipfix_policy_t policy)
{
  return ip6 ?
    &fm->runtime_templates[policy].context_ip6 :
    &fm->runtime_templates[policy].context_ip4;
}

upf_ipfix_policy_t upf_ipfix_lookup_policy (u8 * name, bool * ok);
uword unformat_ipfix_policy (unformat_input_t * i, va_list * args);
u8 *format_upf_ipfix_policy (u8 * s, va_list * args);

#endif
