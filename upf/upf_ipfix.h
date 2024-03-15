#ifndef __included_upf_ipfix_h__
#define __included_upf_ipfix_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_24_8.h>
#include <vnet/ipfix-export/flow_report.h>
#include <vnet/ipfix-export/flow_report_classify.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#include "upf.h"
#include "flowtable.h"

#define FLOW_MAXIMUM_EXPORT_ENTRIES (1024)

typedef struct
{
  union
  {
    struct
    {
      ip_address_t collector_ip;
      upf_ipfix_policy_t policy;
      bool is_ip4;
      u32 observation_domain_id;
    };
    u64 key[3];
  };
} upf_ipfix_context_key_t;

STATIC_ASSERT_SIZEOF (upf_ipfix_context_key_t, 24);

typedef struct
{
  /** Context key */
  upf_ipfix_context_key_t key;

  /** ipfix buffers under construction, per-worker thread */
  vlib_buffer_t **buffers_per_worker;
  /** frames containing ipfix buffers, per-worker thread */
  vlib_frame_t **frames_per_worker;
  /** next record offset, per worker thread */
  u16 *next_record_offset_per_worker;

  /** current record size **/
  u16 rec_size; // TODO: follow and document
  u16 template_id;
  u32 exporter_index;
} upf_ipfix_context_t;

typedef struct
{
  u8 *vrf_name;
  u8 *sw_if_name;
} upf_ipfix_report_info_t;

/**
 * @file
 * @brief flow-per-packet plugin header file
 */
typedef struct
{
  upf_ipfix_context_t *contexts;     // pool of contexts
  clib_bihash_24_8_t context_by_key; // reusing of contexts by key

  u16 template_id;
  u32 vlib_time_0;

  vlib_log_class_t log_failure_class; // rate limited log class

  /** convenience vlib_main_t pointer */
  vlib_main_t *vlib_main;
} upf_ipfix_main_t;

typedef ipfix_field_specifier_t *(*upf_ipfix_field_func_t) (
  ipfix_field_specifier_t *);
typedef u32 (*upf_ipfix_value_func_t) (vlib_buffer_t *to_b, u16 offset,
                                       upf_session_t *sx, flow_entry_t *f,
                                       flow_direction_t uplink_direction,
                                       upf_nwi_t *uplink_nwi,
                                       upf_ipfix_report_info_t *info,
                                       bool last);

typedef struct
{
  u16 field_count;
  upf_ipfix_field_func_t add_fields;
  upf_ipfix_value_func_t add_values;
} upf_ipfix_template_proto_t;

typedef struct
{
  char *name;
  char *alt_name;
  upf_ipfix_template_proto_t per_ip[FIB_PROTOCOL_IP_MAX];
} upf_ipfix_template_t;

extern upf_ipfix_template_t upf_ipfix_templates[];

clib_error_t *upf_ipfix_init (vlib_main_t *vm);

u32 upf_ipfix_ensure_context (const upf_ipfix_context_key_t *key);

upf_ipfix_policy_t upf_ipfix_lookup_policy (u8 *name, bool *ok);
uword unformat_ipfix_policy (unformat_input_t *i, va_list *args);
u8 *format_upf_ipfix_policy (u8 *s, va_list *args);
u8 *format_upf_ipfix_entry (u8 *s, va_list *args);

#endif
