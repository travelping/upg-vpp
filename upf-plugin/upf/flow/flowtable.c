/*
 * Copyright (c) 2016 Qosmos and/or its affiliates
 * Copyright (c) 2018-2025 Travelping GmbH
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

#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vnet/ip/ip4_packet.h>

#include "upf/upf.h"
#include "upf/upf_stats.h"
#include "upf/flow/flowtable.h"
#include "upf/flow/flowtable_tcp.h"
#include "upf/adf/adf.h"
#include "upf/nat/nat.h"
#include "upf/proxy/upf_proxy.h"

#define UPF_DEBUG_ENABLE 0

void upf_ipfix_flow_remove_handler (flow_entry_t *f, u32 now);
int upf_proxy_flow_remove_handler (u16 thread_id, flow_entry_t *f);

void
flowtable_flow_expiration_handler (u16 thread_id, upf_timer_kind_t kind,
                                   u32 opaque, u16 opaque2)
{
  flowtable_main_t *fm = &flowtable_main;
  upf_timer_main_t *utm = &upf_timer_main;
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, thread_id);
  upf_timer_wk_t *utw = vec_elt_at_index (utm->workers, thread_id);

  u32 flow_index = opaque;

  flow_entry_t *f = pool_elt_at_index (fwk->flows, flow_index);

  upf_timer_stop_safe (thread_id, &f->timer_id);

  u32 expires_at_tick = f->last_packet_tick + f->lifetime_ticks;
  i32 expires_in_ticks = (i32) (expires_at_tick - utw->now_tick);
  if (expires_in_ticks > 0)
    {
      // Flow had recent activity, reschedule for remaining time
      u32 remaining_ticks =
        clib_min ((u32) expires_in_ticks, f->lifetime_ticks);

      f->timer_id =
        upf_timer_start_ticks (thread_id, remaining_ticks,
                               UPF_TIMER_KIND_FLOW_EXPIRATION, flow_index, 0);
    }
  else
    {
      // Flow expired, delete it
      flowtable_entry_delete (fwk, f, utw->now_tick);
    }
}

void
flowtable_entry_delete (flowtable_wk_t *fwk, flow_entry_t *f, u32 now)
{
  flowtable_main_t *fm = &flowtable_main;

  u16 thread_id = fwk - fm->workers;
  u32 fid = f - fwk->flows;

  ASSERT (thread_id == os_get_thread_index ());

  upf_dp_session_t *dsx = upf_wk_get_dp_session (thread_id, f->session_id);

  if (CLIB_DEBUG)
    {
      ELOG_TYPE_DECLARE (e) = {
        .format = "upf-flow[%d]: flow delete sx-%d flow-%d[%d] "
                  "ps-%d nat-%d",
        .format_args = "i2i4i4i2i4i4",
      };
      struct __clib_packed
      {
        u16 thread_id;
        u32 session_id;
        u32 flow_id;
        u16 flow_generation;
        u32 ps_id;
        u32 nat_id;
      } * ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, e);
      ed->thread_id = thread_id;
      ed->session_id = f->session_id;
      ed->flow_id = fid;
      ed->flow_generation = f->generation;
      ed->ps_id = f->ps_index;
      ed->nat_id = f->nat_flow_id;
    }

  upf_debug ("Flow Remove t%d %d", thread_id, f - fwk->flows);

  upf_ipfix_flow_remove_handler (f, now);
  if (is_valid_id (f->ps_index))
    {
      upf_proxy_flow_remove_handler (thread_id, f);
      f->ps_index = ~0;
    }

  if (is_valid_id (f->nat_flow_id))
    upf_nat_flow_delete (thread_id, f->nat_flow_id);

  session_flows_list_remove (fwk->flows, &dsx->flows, f);

  upf_timer_stop_safe (thread_id, &f->timer_id);

  int birv;

  // hashtable unlink
  if (f->is_ip4)
    {
      clib_bihash_kv_16_8_t kv4 = {};
      flow_hashmap_key4_16_t *key4 = (flow_hashmap_key4_16_t *) &kv4.key;

      key4->session_id = f->session_id;
      key4->ip[UPF_EL_UL_SRC] = f->ip[UPF_EL_UL_SRC].ip4;
      key4->ip[UPF_EL_UL_DST] = f->ip[UPF_EL_UL_DST].ip4;
      key4->port[UPF_EL_UL_SRC] = f->port[UPF_EL_UL_SRC];
      key4->port[UPF_EL_UL_DST] = f->port[UPF_EL_UL_DST];
      key4->proto = f->proto;

      upf_debug ("removing %U", format_flow_hashmap_key4_16, key4);
      birv = clib_bihash_add_del_16_8 (&fwk->flows_ht4, &kv4, 0 /* is_add */);
    }
  else
    {
      clib_bihash_kv_40_8_t kv6 = {};
      flow_hashmap_key6_40_t *key6 = (flow_hashmap_key6_40_t *) &kv6.key;

      key6->session_id = f->session_id;
      key6->ip[UPF_EL_UL_SRC] = f->ip[UPF_EL_UL_SRC].ip6;
      key6->ip[UPF_EL_UL_DST] = f->ip[UPF_EL_UL_DST].ip6;
      key6->port[UPF_EL_UL_SRC] = f->port[UPF_EL_UL_SRC];
      key6->port[UPF_EL_UL_DST] = f->port[UPF_EL_UL_DST];
      key6->proto = f->proto;

      upf_debug ("removing %U", format_flow_hashmap_key6_40, key6);
      birv = clib_bihash_add_del_40_8 (&fwk->flows_ht6, &kv6, 0 /* is_add */);
    }

  if (birv)
    {
      clib_warning ("birv: %d fid %u tid %u ip4 %u", birv, fid, thread_id,
                    f->is_ip4);
      ASSERT (birv == 0);
    }

  ASSERT (f->timer_id.as_u32 == ~0);

  if (f->app_uri)
    vec_free (f->app_uri);

  pool_put (fwk->flows, f);

  if (dsx->flow_mode == UPF_SESSION_FLOW_MODE_NO_CREATE)
    {
      if (session_flows_list_is_empty (&dsx->flows))
        // transition to flowless if there is no flows
        dsx->flow_mode = UPF_SESSION_FLOW_MODE_DISABLED;
    }

  fwk->current_flows_count -= 1;
  upf_stats_get_wk_generic (thread_id)->flows_count -= 1;
}

void
flowtable_entry_reset (flow_entry_t *flow, u32 generation)
{
  flow->application_idx = ~0;

  flow->generation = generation;
  flow->pdr_lids[UPF_DIR_UL] = ~0;
  flow->pdr_lids[UPF_DIR_DL] = ~0;
  flow->is_classified_ul = 0;
  flow->is_classified_dl = 0;
}

always_inline u32
_flowtable_get_initial_lifetime (u8 ip_proto)
{
  flowtable_main_t *fm = &flowtable_main;

  switch (ip_proto)
    {
    case IP_PROTOCOL_TCP:
      return fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_TCP_OPENING];
    case IP_PROTOCOL_UDP:
      return fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_UDP];
    case IP_PROTOCOL_ICMP:
      return fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_ICMP];
    default:
      return fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_UNKNOWN];
    }
}

flow_entry_t *
flowtable_entry_new (flowtable_wk_t *fwk)
{
  flowtable_main_t *fm = &flowtable_main;

  if (fwk->current_flows_count >= fm->max_flows_per_worker)
    return NULL;

  if (fwk->flows == NULL)
    {
      // Do not allocate flowtable till it used to save memory, since we
      // allocate entire flowtable at once. Entire flowtable allocated at once
      // to avoid freezes related to reallocation. Flowtable will not be
      // allocated:
      // - for main thread if there are workers
      // - for flowless deployments
      pool_alloc_aligned (fwk->flows, fm->max_flows_per_worker,
                          CLIB_CACHE_LINE_BYTES);
    }
  flow_entry_t *f;
  pool_get_zero (fwk->flows, f);
  return f;
}

static void
_flowtable_entry_init_base (flowtable_wk_t *fwk, flow_entry_t *f,
                            upf_time_t unix_now, upf_dir_t initiator,
                            u8 ip_proto, u16 generation, u32 session_id)
{
  flowtable_main_t *fm = &flowtable_main;
  upf_timer_main_t *utm = &upf_timer_main;

  u16 thread_id = fwk - fm->workers;
  upf_timer_wk_t *utw = vec_elt_at_index (utm->workers, thread_id);

  f->session_id = session_id;
  f->initiator = initiator;
  f->lifetime_ticks = _flowtable_get_initial_lifetime (ip_proto);
  f->last_packet_tick = utw->now_tick;
  f->unix_start_time = unix_now;
  f->unix_last_time = unix_now;
  f->application_idx = ~0;
  f->generation = generation;
  f->ps_index = ~0;
  f->timer_id.as_u32 = ~0;
  f->ipfix.next_export_at = 1; // do export immediately
  f->ipfix.context_index = ~0;
  f->nat_flow_id = ~0;

  f->pdr_lids[UPF_DIR_UL] = ~0;
  f->pdr_lids[UPF_DIR_DL] = ~0;

  session_flows_list_anchor_init (f);

  flowtable_entry_start_timer (fwk, f);

  fwk->current_flows_count += 1;
  upf_stats_get_wk_generic (thread_id)->flows_count += 1;

  upf_debug ("Flow Created: fidx %d timer_id 0x%x", f - fwk->flows,
             f->timer_id.as_u32);
}

void
flowtable_entry_init_by_ip4 (flowtable_wk_t *fwk, flow_entry_t *f,
                             upf_time_t unix_now, upf_dir_t initiator,
                             u16 generation, u32 session_id,
                             clib_bihash_kv_16_8_t *kv4)
{
  flow_hashmap_key4_16_t *key = (flow_hashmap_key4_16_t *) &kv4->key[0];

  ip46_address_set_ip4 (&f->ip[UPF_EL_UL_SRC], &key->ip[UPF_EL_UL_SRC]);
  ip46_address_set_ip4 (&f->ip[UPF_EL_UL_DST], &key->ip[UPF_EL_UL_DST]);
  f->port[UPF_EL_UL_SRC] = key->port[UPF_EL_UL_SRC];
  f->port[UPF_EL_UL_DST] = key->port[UPF_EL_UL_DST];
  f->proto = key->proto;
  f->is_ip4 = 1;

  _flowtable_entry_init_base (fwk, f, unix_now, initiator, key->proto,
                              generation, session_id);

  kv4->value = f - fwk->flows;
  int bv = clib_bihash_add_del_16_8 (&fwk->flows_ht4, kv4, 1 /* is_add */);
  ASSERT (bv == 0);
}

void
flowtable_entry_init_by_ip6 (flowtable_wk_t *fwk, flow_entry_t *f,
                             upf_time_t unix_now, upf_dir_t initiator,
                             u16 generation, u32 session_id,
                             clib_bihash_kv_40_8_t *kv6)
{
  flow_hashmap_key6_40_t *key = (flow_hashmap_key6_40_t *) &kv6->key[0];

  ip46_address_set_ip6 (&f->ip[UPF_EL_UL_SRC], &key->ip[UPF_EL_UL_SRC]);
  ip46_address_set_ip6 (&f->ip[UPF_EL_UL_DST], &key->ip[UPF_EL_UL_DST]);
  f->port[UPF_EL_UL_SRC] = key->port[UPF_EL_UL_SRC];
  f->port[UPF_EL_UL_DST] = key->port[UPF_EL_UL_DST];
  f->proto = key->proto;
  f->is_ip4 = 0;

  _flowtable_entry_init_base (fwk, f, unix_now, initiator, key->proto,
                              generation, session_id);

  kv6->value = f - fwk->flows;
  int bv = clib_bihash_add_del_40_8 (&fwk->flows_ht6, kv6, 1 /* is_add */);
  ASSERT (bv == 0);
}

u8 *
format_flow_primary_key (u8 *s, va_list *args)
{
  flow_entry_t *f = va_arg (*args, flow_entry_t *);

  return format (s, "proto 0x%x, %U:%u <-> %U:%u, sid %u", f->proto,
                 format_ip46_address, &f->ip[UPF_EL_UL_SRC], IP46_TYPE_ANY,
                 f->port[UPF_EL_UL_SRC], format_ip46_address,
                 &f->ip[UPF_EL_UL_DST], IP46_TYPE_ANY, f->port[UPF_EL_UL_DST],
                 f->session_id);
}

u8 *
format_flow_hashmap_key4_16 (u8 *s, va_list *args)
{
  flow_hashmap_key4_16_t *key = va_arg (*args, flow_hashmap_key4_16_t *);

  return format (
    s, "proto 0x%x, %U:%u <-> %U:%u, sid %u", key->proto, format_ip4_address,
    &key->ip[UPF_EL_UL_SRC], key->port[UPF_EL_UL_SRC], format_ip4_address,
    &key->ip[UPF_EL_UL_DST], key->port[UPF_EL_UL_DST], key->session_id);
}

u8 *
format_flow_hashmap_key6_40 (u8 *s, va_list *args)
{
  flow_hashmap_key6_40_t *key = va_arg (*args, flow_hashmap_key6_40_t *);

  return format (
    s, "proto 0x%x, %U:%u <-> %U:%u, sid %u", key->proto, format_ip6_address,
    &key->ip[UPF_EL_UL_SRC], key->port[UPF_EL_UL_SRC], format_ip6_address,
    &key->ip[UPF_EL_UL_DST], key->port[UPF_EL_UL_DST], key->session_id);
}

static const char *_tcp_f_state_names[] = {
  [TCP_F_STATE_START] = "START",   [TCP_F_STATE_SYN] = "SYN",
  [TCP_F_STATE_SYNACK] = "SYNACK", [TCP_F_STATE_ESTABLISHED] = "ESTAB",
  [TCP_F_STATE_FIN] = "FIN",       [TCP_F_STATE_FINACK] = "FINACK",
  [TCP_F_STATE_RST] = "RST",
};

static const char *_proxy_side_state_short[] = {
  [UPF_PROXY_S_S_INVALID] = "INV",    [UPF_PROXY_S_S_CREATED] = "CREAT",
  [UPF_PROXY_S_S_CONNECTED] = "CONN", [UPF_PROXY_S_S_CLOSING] = "CLOS",
  [UPF_PROXY_S_S_RESET] = "RST",      [UPF_PROXY_S_S_DESTROYED] = "DESTR",
};

u8 *
format_flow_entry (u8 *s, va_list *args)
{
  flow_entry_t *flow = va_arg (*args, flow_entry_t *);
  u32 thread_id = va_arg (*args, u32);

  const char *proto_name = NULL;
  switch (flow->proto)
    {
    case IP_PROTOCOL_TCP:
      proto_name = "TCP";
      break;
    case IP_PROTOCOL_UDP:
      proto_name = "UDP";
      break;
    case IP_PROTOCOL_ICMP:
      proto_name = "ICMP";
      break;
    case IP_PROTOCOL_ICMP6:
      proto_name = "ICMP6";
      break;
    }

  if (proto_name)
    s = format (s, "%s ", proto_name);
  else
    s = format (s, "0x%02x ", flow->proto);

  if (flow->proto == IP_PROTOCOL_ICMP || flow->proto == IP_PROTOCOL_ICMP6)
    {
      s = format (s, "%U <-> %U icmp_id=%u", format_ip46_address,
                  &flow->ip[UPF_EL_UL_SRC], IP46_TYPE_ANY, format_ip46_address,
                  &flow->ip[UPF_EL_UL_DST], IP46_TYPE_ANY,
                  flow->port[UPF_EL_UL_SRC]);
    }
  else
    {
      s = format (
        s, "%U:%u <-> %U:%u", format_ip46_address, &flow->ip[UPF_EL_UL_SRC],
        IP46_TYPE_ANY, flow->port[UPF_EL_UL_SRC], format_ip46_address,
        &flow->ip[UPF_EL_UL_DST], IP46_TYPE_ANY, flow->port[UPF_EL_UL_DST]);
    }

  s = format (s, " sid=%u pkts=%u/%u", flow->session_id,
              flow->stats[UPF_DIR_UL].pkts, flow->stats[UPF_DIR_DL].pkts);

  upf_dp_session_t *dsx = upf_wk_get_dp_session (thread_id, flow->session_id);
  upf_rules_t *rules = NULL;
  if (flow->generation == dsx->rules_generation && is_valid_id (dsx->rules_id))
    rules = upf_wk_get_rules (thread_id, dsx->rules_id);

  s = format (s, " pdr=");
  if (flow->is_classified_ul)
    {
      if (rules)
        {
          rules_pdr_t *pdr =
            upf_rules_get_pdr (rules, flow->pdr_lids[UPF_DIR_UL]);
          s = format (s, "#%u[%u]", pdr->pfcp_id, flow->pdr_lids[UPF_DIR_UL]);
        }
      else
        s = format (s, "[%u]", flow->pdr_lids[UPF_DIR_UL]);
    }
  else
    s = format (s, "?");
  s = format (s, "/");
  if (flow->is_classified_dl)
    {
      if (rules)
        {
          rules_pdr_t *pdr =
            upf_rules_get_pdr (rules, flow->pdr_lids[UPF_DIR_DL]);
          s = format (s, "#%u[%u]", pdr->pfcp_id, flow->pdr_lids[UPF_DIR_DL]);
        }
      else
        s = format (s, "[%u]", flow->pdr_lids[UPF_DIR_DL]);
    }
  else
    s = format (s, "?");

  s = format (s, " lifetime=%us",
              flow->lifetime_ticks / (u32) TW_CLOCKS_PER_SEC);

  if (flow->proto == IP_PROTOCOL_TCP && flow->tcp_state < TCP_F_STATE_MAX)
    s = format (s, " tcp=%s", _tcp_f_state_names[flow->tcp_state]);

  if (flow->is_tcp_proxy || flow->created_tcp_proxies)
    {
      s = format (s, " proxy={id:%d", flow->ps_index);
      if (flow->is_tcp_proxy)
        {
          upf_proxy_main_t *upm = &upf_proxy_main;
          upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, thread_id);
          if (!pool_is_free_index (pwk->sessions, flow->ps_index))
            {
              upf_proxy_session_t *ps =
                pool_elt_at_index (pwk->sessions, flow->ps_index);
              if (ps->generation == flow->ps_generation)
                {
                  s = format (s, ",po:%s,ao:%s",
                              _proxy_side_state_short[ps->side_po.state],
                              _proxy_side_state_short[ps->side_ao.state]);
                  if (ps->is_spliced)
                    s = format (s, ",spliced");
                  if (ps->is_redirected)
                    s = format (s, ",redir");
                }
            }
        }
      if (flow->created_tcp_proxies)
        s = format (s, ",created:%u", (u32) flow->created_tcp_proxies);
      s = format (s, "}");
    }

  if (is_valid_id (flow->application_idx))
    {
      upf_adf_app_t *app =
        pool_elt_at_index (upf_main.adf_main.apps, flow->application_idx);
      if (app && vec_len (app->name))
        s = format (s, " app=%v", app->name);
    }

  if (flow->ipfix_exported || is_valid_id (flow->ipfix.context_index))
    {
      s = format (s, " ipfix={");
      if (flow->ipfix_exported)
        s = format (s, "exported");
      if (is_valid_id (flow->ipfix.context_index))
        s = format (s, "%sctx:%u", flow->ipfix_exported ? "," : "",
                    flow->ipfix.context_index);
      s = format (s, "}");
    }

  if (is_valid_id (flow->nat_flow_id))
    {
      upf_nat_main_t *unm = &upf_nat_main;
      upf_nat_wk_t *nwk = vec_elt_at_index (unm->workers, thread_id);
      upf_nat_flow_t *nf = pool_elt_at_index (nwk->flows, flow->nat_flow_id);
      s = format (s, " nat=%U:%u", format_ip4_address, &nf->key_o2i.dst_addr,
                  nf->nat_port);
    }

  return s;
}

static clib_error_t *
upf_flow_timeout_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                             vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u32 timeouts[FT_TIMEOUT_N_TYPE] = {};
  bool presence[FT_TIMEOUT_N_TYPE] = {};

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "tcp-established %u",
                        &timeouts[FT_TIMEOUT_TYPE_TCP_ESTABLISHED]))
            presence[FT_TIMEOUT_TYPE_TCP_ESTABLISHED] = true;
          else if (unformat (line_input, "tcp-opening %u",
                             &timeouts[FT_TIMEOUT_TYPE_TCP_OPENING]))
            presence[FT_TIMEOUT_TYPE_TCP_OPENING] = true;
          else if (unformat (line_input, "tcp-closing %u",
                             &timeouts[FT_TIMEOUT_TYPE_TCP_CLOSING]))
            presence[FT_TIMEOUT_TYPE_TCP_CLOSING] = true;
          else if (unformat (line_input, "udp %u",
                             &timeouts[FT_TIMEOUT_TYPE_UDP]))
            presence[FT_TIMEOUT_TYPE_UDP] = true;
          else if (unformat (line_input, "icmp %u",
                             &timeouts[FT_TIMEOUT_TYPE_ICMP]))
            presence[FT_TIMEOUT_TYPE_ICMP] = true;
          else if (unformat (line_input, "other %u",
                             &timeouts[FT_TIMEOUT_TYPE_UNKNOWN]))
            presence[FT_TIMEOUT_TYPE_UNKNOWN] = true;
          else
            {
              error = unformat_parse_error (line_input);
              unformat_free (line_input);
              return error;
            }
        }
      unformat_free (line_input);
    }

  for (flowtable_timeout_type_t ftt = 0; ftt < FT_TIMEOUT_N_TYPE; ftt++)
    {
      if (!presence[ftt])
        continue;

      clib_error_t *error = flowtable_lifetime_update (ftt, timeouts[ftt]);
      if (error)
        return error;
    }

  return 0;
}

VLIB_CLI_COMMAND (upf_flow_timeout_command, static) = {
  .path = "upf flow timeout",
  .short_help = "upf flow timeout [tcp-established <s>] [tcp-opening <s>] "
                "[tcp-closing <s>] [udp <s>] [icmp <s>] [other <s>]",
  .function = upf_flow_timeout_command_fn,
};

static clib_error_t *
upf_show_flow_timeout_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *cmd)
{
  flowtable_main_t *fm = &flowtable_main;

  vlib_cli_output (vm, "tcp-established: %us\n",
                   fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_TCP_ESTABLISHED] /
                     TW_CLOCKS_PER_SEC);
  vlib_cli_output (vm, "tcp-opening %us\n",
                   fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_TCP_OPENING] /
                     TW_CLOCKS_PER_SEC);
  vlib_cli_output (vm, "tcp-closing: %us\n",
                   fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_TCP_CLOSING] /
                     TW_CLOCKS_PER_SEC);
  vlib_cli_output (vm, "udp: %us\n",
                   fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_UDP] /
                     TW_CLOCKS_PER_SEC);
  vlib_cli_output (vm, "icmp: %us\n",
                   fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_ICMP] /
                     TW_CLOCKS_PER_SEC);
  vlib_cli_output (vm, "other: %us\n",
                   fm->timer_lifetime_ticks[FT_TIMEOUT_TYPE_UNKNOWN] /
                     TW_CLOCKS_PER_SEC);

  return 0;
}

VLIB_CLI_COMMAND (upf_show_flow_timeout_command, static) = {
  .path = "show upf flow timeout",
  .short_help = "show upf flow timeout",
  .function = upf_show_flow_timeout_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_flow_config_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                            vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  flowtable_main_t *fm = &flowtable_main;
  clib_error_t *error = NULL;

  uword max_flows = 0;
  bool has_max_flows = false;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "max-flows-per-worker %u", &max_flows))
            has_max_flows = true;
          else
            {
              error = unformat_parse_error (line_input);
              unformat_free (line_input);
              return error;
            }
        }
      unformat_free (line_input);
    }

  // Validate
  if (has_max_flows)
    {
      if (max_flows < 1000)
        return clib_error_return (0, "max flows %u < 1000", max_flows);
      else if (max_flows >= (1 << 30))
        return clib_error_return (0, "max flows %u >= %u", max_flows,
                                  (1 << 30));

      flowtable_wk_t *wk;
      vec_foreach (wk, fm->workers)
        if (wk->flows)
          return clib_error_return (
            0, "can't change flows count after session creation");
    }

  // Apply
  if (has_max_flows)
    fm->max_flows_per_worker = max_flows;

  return 0;
}

VLIB_CLI_COMMAND (upf_flow_config_command, static) = {
  .path = "upf flow config",
  .short_help = "upf flow config [max-flows-per-worker X]",
  .function = upf_flow_config_command_fn,
};
