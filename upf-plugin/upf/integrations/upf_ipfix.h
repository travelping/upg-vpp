/*
 * Copyright (c) 2020-2025 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef UPF_INTEGRATIONS_UPF_IPFIX_H_
#define UPF_INTEGRATIONS_UPF_IPFIX_H_

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ipfix-export/flow_report.h>
#include <vnet/ipfix-export/flow_report_classify.h>

#include "upf/utils/common.h"
#include "upf/utils/upf_timer.h"
#include "upf/pfcp/upf_nwi.h"
#include "upf/flow/flowtable.h"

#define FLOW_MAXIMUM_EXPORT_ENTRIES (1024)

typedef union __key_packed
{
  struct __key_packed
  {
    u32 observation_domain_id;
    ip_address_t collector_ip;
    upf_ipfix_policy_t policy;
    u8 is_ip4;
    u8 _pad[1];
  };
  u64 key[3];
} upf_ipfix_context_key_t;
STATIC_ASSERT_SIZEOF (upf_ipfix_context_key_t, 24);

typedef struct
{
  /* ipfix buffers under construction */
  vlib_buffer_t *buffers;
  /* frames containing ipfix buffers */
  vlib_frame_t *frames;
  /* next record offset, per worker thread */
  u16 next_record_offset;
  /* records currently buffered */
  u16 n_data_records;
} upf_ipfix_wk_context_t;

typedef struct
{
  /* Context key */
  upf_ipfix_context_key_t key;

  /* per worker fields */
  upf_ipfix_wk_context_t *per_worker;

  // Save exporter index to check later if exporter was changed
  u32 exporter_index;

  /* single ipfix record size */
  u16 rec_size;

  u16 template_id;

  u32 flow_report_index;
} upf_ipfix_context_t;

typedef struct
{
  u8 *vrf_name;
  u8 *sw_if_name;
} upf_ipfix_report_info_t;

typedef struct
{
  upf_ipfix_context_t *contexts;     // pool of contexts
  clib_bihash_24_8_t context_by_key; // reusing of contexts by key

  u16 template_id;
  u32 vlib_time_0;

  upf_timer_id_t *timers_per_worker;

  vlib_log_class_t log_failure_class; // rate limited log class

  u8 is_timers_started : 1;
} upf_ipfix_main_t;

typedef ipfix_field_specifier_t *(*upf_ipfix_field_func_t) (
  ipfix_field_specifier_t *);
typedef u32 (*upf_ipfix_value_func_t) (u16 thread_id, vlib_buffer_t *to_b,
                                       u16 offset, u32 session_id,
                                       flow_entry_t *f,
                                       upf_interface_t *uplink_nwif,
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
extern upf_ipfix_main_t upf_ipfix_main;

clib_error_t *upf_ipfix_init (vlib_main_t *vm);

u16 upf_ipfix_ensure_context (const upf_ipfix_context_key_t *key);

upf_ipfix_policy_t upf_ipfix_lookup_policy (u8 *name, bool *ok);
uword unformat_ipfix_policy (unformat_input_t *i, va_list *args);
format_function_t format_upf_ipfix_policy;
format_function_t format_upf_ipfix_entry;

#endif // UPF_INTEGRATIONS_UPF_IPFIX_H_
