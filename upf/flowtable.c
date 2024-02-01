/*
 * Copyright (c) 2016 Qosmos and/or its affiliates.
 * Copyright (c) 2018 Travelping GmbH
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

#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vnet/ip/ip4_packet.h>

#include "upf.h"
#include "upf_app_db.h"
#include "flowtable.h"
#include "flowtable_tcp.h"

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)                                                        \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

always_inline void
flow_entry_free (flowtable_main_t *fm, flowtable_main_per_cpu_t *fmt,
                 flow_entry_t *f)
{
  /* timer should be already removed */
  ASSERT (!flow_timeout_list_el_is_part_of_list (f));
  ASSERT (f->timer_slot == (u16) ~0);

  ASSERT (f->cpu_index == os_get_thread_index ());

  if (f->app_uri)
    vec_free (f->app_uri);

  pool_put (fm->flows, f);
}

int upf_ipfix_flow_remove_handler (flow_entry_t *f, u32 now);
int upf_proxy_flow_remove_handler (flow_entry_t *flow);
int flow_remove_counter_handler (flowtable_main_t *fm, flow_entry_t *flow);
int session_flow_unlink_handler (flowtable_main_t *fm, flow_entry_t *flow);

void
flowtable_entry_remove_internal (flowtable_main_t *fm,
                                 flowtable_main_per_cpu_t *fmt,
                                 flow_entry_t *f, u32 now)
{
  clib_bihash_kv_48_8_t kv;

  upf_debug ("Flow Remove %d", f - fm->flows);

  upf_ipfix_flow_remove_handler (f, now);
  upf_proxy_flow_remove_handler (f);
  flow_remove_counter_handler (fm, f);

  /* session unlink */
  session_flow_unlink_handler (fm, f);

  /* timer unlink */
  flowtable_timeout_stop_entry (fm, fmt, f);

  /* hashtable unlink */
  clib_memcpy (kv.key, f->key.key, sizeof (kv.key));
  clib_bihash_add_del_48_8 (&fmt->flows_ht, &kv, 0 /* is_add */);

  flow_entry_free (fm, fmt, f);
}

static inline u16
flowtable_lifetime_calculate (flowtable_main_t *fm, flow_key_t const *key)
{
  switch (key->proto)
    {
    case IP_PROTOCOL_ICMP:
      return fm->timer_lifetime[FT_TIMEOUT_TYPE_ICMP];

    case IP_PROTOCOL_UDP:
      return fm->timer_lifetime[FT_TIMEOUT_TYPE_UDP];

    case IP_PROTOCOL_TCP:
      return fm->timer_lifetime[FT_TIMEOUT_TYPE_TCP];

    default:
      return ip46_address_is_ip4 (&key->ip[FT_FORWARD]) ?
               fm->timer_lifetime[FT_TIMEOUT_TYPE_IPV4] :
               fm->timer_lifetime[FT_TIMEOUT_TYPE_IPV6];
    }

  return fm->timer_lifetime[FT_TIMEOUT_TYPE_UNKNOWN];
}

void
flowtable_entry_remove (flowtable_main_t *fm, flow_entry_t *f, u32 now)
{
  flowtable_main_per_cpu_t *fmt = &fm->per_cpu[f->cpu_index];
  flowtable_entry_remove_internal (fm, fmt, f, now);
}

always_inline void
flowtable_entry_init_side (flow_side_t *side, u32 now)
{
  side->pdr_id = ~0;
  // TODO: check if it better to 0 teid instead, since ~0 is
  // valid teid, but not 0
  side->teid = ~0;
  side->next = FT_NEXT_CLASSIFY;
  side->ipfix.last_exported = now;
  side->ipfix.info_index = ~0;
  side->tcp.conn_index = ~0;
  side->tcp.thread_index = ~0;
}

/* TODO: replace with a more appropriate hashtable */
u32
flowtable_entry_lookup_create (flowtable_main_t *fm,
                               flowtable_main_per_cpu_t *fmt,
                               clib_bihash_kv_48_8_t *kv, u64 timestamp_ns,
                               u32 const now,
                               flow_key_direction_t flow_key_direction,
                               u16 generation, u32 session_index, int *created)
{
  flow_entry_t *f;
  upf_main_t *gtm = &upf_main;

  if (PREDICT_FALSE (clib_bihash_search_inline_48_8 (&fmt->flows_ht, kv) == 0))
    {
      return kv->value;
    }

  /* create new flow */
  if (fm->current_flows_count >= fm->flows_max)
    {
      return ~0;
    }

  *created = 1;

  pool_get_zero (fm->flows, f);

  clib_memcpy (f->key.key, kv->key, sizeof (f->key.key));
  f->flow_key_direction = flow_key_direction;
  f->lifetime = flowtable_lifetime_calculate (fm, &f->key);
  f->active = now;
  f->flow_start_time = timestamp_ns;
  f->flow_end_time = timestamp_ns;
  f->application_id = ~0;
  f->cpu_index = os_get_thread_index ();
  f->generation = generation;
  f->ps_index = ~0;
  f->timer_slot = ~0;

  flowtable_entry_init_side (flow_side (f, FT_INITIATOR), now);
  flowtable_entry_init_side (flow_side (f, FT_RESPONDER), now);

  session_flows_list_anchor_init (f);
  flow_timeout_list_anchor_init (f);

  /* insert in timer list */
  flowtable_timeout_start_entry (fm, fmt, f, now);

  upf_debug ("Flow Created: fidx %d timer_slot %d", f - fm->flows,
             f->timer_slot);

  fm->current_flows_count += 1;
  vlib_increment_simple_counter (&gtm->upf_simple_counters[UPF_FLOW_COUNTER],
                                 vlib_get_thread_index (), 0, 1);

  /* insert in hash */
  kv->value = f - fm->flows;
  clib_bihash_add_del_48_8 (&fmt->flows_ht, kv, 1 /* is_add */);

  return kv->value;
}

void
flowtable_timer_wheel_index_update (flowtable_main_t *fm,
                                    flowtable_main_per_cpu_t *fmt, u32 now)
{
  fmt->time_index = now % FLOW_TIMER_MAX_LIFETIME;
}

u8 *
format_flow_key (u8 *s, va_list *args)
{
  flow_key_t *key = va_arg (*args, flow_key_t *);

  return format (s, "proto 0x%x, %U:%u <-> %U:%u, seid 0x%016llx", key->proto,
                 format_ip46_address, &key->ip[FT_FORWARD], IP46_TYPE_ANY,
                 clib_net_to_host_u16 (key->port[FT_FORWARD]),
                 format_ip46_address, &key->ip[FT_REVERSE], IP46_TYPE_ANY,
                 clib_net_to_host_u16 (key->port[FT_REVERSE]), key->up_seid);
}

u8 *
format_flow (u8 *s, va_list *args)
{
  flow_entry_t *flow = va_arg (*args, flow_entry_t *);
  upf_main_t *sm = &upf_main;
#if CLIB_DEBUG > 0
  flowtable_main_t *fm = &flowtable_main;
#endif
  u8 *app_name = NULL;

  if (flow->application_id != ~0)
    {
      upf_adf_app_t *app =
        pool_elt_at_index (sm->upf_apps, flow->application_id);
      app_name = format (0, "%v", app->name);
    }
  else
    app_name = format (0, "%s", "None");
#if CLIB_DEBUG > 0
  s = format (s, "Flow %d: ", flow - fm->flows);
#endif
  s = format (s,
              "%U, UL pkt %u, DL pkt %u, "
              "Forward PDR %u, Reverse PDR %u, "
              "app %v, lifetime %u, proxy %d, spliced %d nat port %d",
              format_flow_key, &flow->key,
              flow_side (flow, FT_INITIATOR)->stats.pkts,
              flow_side (flow, FT_RESPONDER)->stats.pkts,
              flow_side (flow, FT_INITIATOR)->pdr_id,
              flow_side (flow, FT_RESPONDER)->pdr_id, app_name, flow->lifetime,
              flow->is_l3_proxy, flow->is_spliced, flow->nat_sport);
#if CLIB_DEBUG > 0
  s = format (s, ", dont_splice %d", flow->dont_splice);
#endif
#if CLIB_DEBUG > 1
  /* TODO: when we have multicore support, always show CPU */
  s = format (s, ", cpu %u", flow->cpu_index);
#endif

  vec_free (app_name);
  return s;
}

static clib_error_t *
vnet_upf_flow_timeout_update (flowtable_timeout_type_t type, u16 timeout)
{
  return flowtable_lifetime_update (type, timeout);
}

int
upf_flow_timeout_update (flowtable_timeout_type_t type, u16 timeout)
{
  int rv = 0;

  vnet_upf_flow_timeout_update (type, timeout);

  return rv;
}

static u16
vnet_upf_get_flow_timeout (flowtable_timeout_type_t type)
{
  return flowtable_lifetime_get (type);
}

static clib_error_t *
upf_flow_timeout_command_fn (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u16 timeout = 0;
  clib_error_t *error = NULL;
  flowtable_timeout_type_t type = FT_TIMEOUT_TYPE_UNKNOWN;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "ip4 %u", &timeout))
        {
          type = FT_TIMEOUT_TYPE_IPV4;
          break;
        }
      if (unformat (line_input, "ip6 %u", &timeout))
        {
          type = FT_TIMEOUT_TYPE_IPV6;
          break;
        }
      if (unformat (line_input, "icmp %u", &timeout))
        {
          type = FT_TIMEOUT_TYPE_ICMP;
          break;
        }
      if (unformat (line_input, "udp %u", &timeout))
        {
          type = FT_TIMEOUT_TYPE_UDP;
          break;
        }
      if (unformat (line_input, "tcp %u", &timeout))
        {
          type = FT_TIMEOUT_TYPE_TCP;
          break;
        }
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  error = vnet_upf_flow_timeout_update (type, timeout);

done:
  unformat_free (line_input);

  return error;
}

/* clang-format off */
VLIB_CLI_COMMAND (upf_flow_timeout_command, static) =
{
  .path = "upf flow timeout",
  .short_help = "upf flow timeout (default | ip4 | ip6 | icmp | udp | tcp) <seconds>",
  .function = upf_flow_timeout_command_fn,
};
/* clang-format on */

static clib_error_t *
upf_show_flow_timeout_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u16 timeout = 0;
  clib_error_t *error = NULL;
  flowtable_timeout_type_t type = FT_TIMEOUT_TYPE_UNKNOWN;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "ip4"))
        {
          type = FT_TIMEOUT_TYPE_IPV4;
          break;
        }
      if (unformat (line_input, "ip6"))
        {
          type = FT_TIMEOUT_TYPE_IPV6;
          break;
        }
      if (unformat (line_input, "icmp"))
        {
          type = FT_TIMEOUT_TYPE_ICMP;
          break;
        }
      if (unformat (line_input, "udp"))
        {
          type = FT_TIMEOUT_TYPE_UDP;
          break;
        }
      if (unformat (line_input, "tcp"))
        {
          type = FT_TIMEOUT_TYPE_TCP;
          break;
        }
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  timeout = vnet_upf_get_flow_timeout (type);
  vlib_cli_output (vm, "%u", timeout);

done:
  unformat_free (line_input);

  return error;
}

/* clang-format off */
VLIB_CLI_COMMAND (upf_show_flow_timeout_command, static) =
{
  .path = "show upf flow timeout",
  .short_help = "upf flow timeout (default | ip4 | ip6 | icmp | udp | tcp)",
  .function = upf_show_flow_timeout_command_fn,
};
/* clang-format on */
