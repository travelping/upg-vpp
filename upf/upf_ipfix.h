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
      ip46_address_t collector_ip;
      u32 observation_domain_id;
      upf_ipfix_policy_t policy;
      u8 is_ip4;
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
  /** record size */
  u16 rec_size;
  /** IPFIX template id */
  u16 template_id;
  /** Exporter index */
  u32 exporter_index;
  /** Reference count */
  u32 refcnt;
} upf_ipfix_protocol_context_t;

typedef struct
{
  u32 protocol_context_id[FIB_PROTOCOL_IP_MAX];
  u32 refcnt;
  upf_ipfix_context_key_t key;
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
  clib_spinlock_t lock;
  clib_bihash_24_8_t proto_context_by_key;
  clib_bihash_24_8_t cached_context_by_key;
  clib_bihash_24_8_t info_by_key;
  upf_ipfix_protocol_context_t *proto_contexts;
  upf_ipfix_context_t *cached_contexts;
  u16 template_id;
  upf_ipfix_policy_t policy;

  u32 vlib_time_0;

  bool initialized;
  bool disabled;

  u8 *flow_per_interface;

  /** convenience vlib_main_t pointer */
  vlib_main_t *vlib_main;
  /** convenience vnet_main_t pointer */
  vnet_main_t *vnet_main;
} upf_ipfix_main_t;

u8 *format_upf_ipfix_entry (u8 *s, va_list *args);

clib_error_t *upf_ipfix_init (vlib_main_t *vm);

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
  char *name;
  u16 field_count_ipv4;
  u16 field_count_ipv6;
  upf_ipfix_field_func_t add_ip4_fields;
  upf_ipfix_field_func_t add_ip6_fields;
  upf_ipfix_value_func_t add_ip4_values;
  upf_ipfix_value_func_t add_ip6_values;
} upf_ipfix_template_t;

extern upf_ipfix_template_t upf_ipfix_templates[];

u32 upf_ref_ipfix_proto_context (const upf_ipfix_context_key_t *key);
void upf_ref_ipfix_proto_context_by_index (u32 cidx);
void upf_unref_ipfix_proto_context_by_index (u32 cidx);

u32 upf_ref_ipfix_cached_context (const upf_ipfix_context_key_t *key);
void upf_unref_ipfix_cached_context_by_index (u32 cidx);

upf_ipfix_policy_t upf_ipfix_lookup_policy (u8 *name, bool *ok);
uword unformat_ipfix_policy (unformat_input_t *i, va_list *args);
u8 *format_upf_ipfix_policy (u8 *s, va_list *args);

#endif
