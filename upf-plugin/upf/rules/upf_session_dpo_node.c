/*
 * Copyright (c) 2019-2025 Travelping GmbH
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

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/interface_output.h>

#include "upf/upf.h"
#include "upf/rules/upf_session_dpo.h"
#include "upf/utils/ip_helpers.h"
#include "upf/core/upf_buffer_opaque.h"

#define UPF_DEBUG_ENABLE 0

/* Statistics (not all errors) */
#define foreach_upf_session_dpo_error                                         \
  _ (NO_ERROR, "reserved") /* just to reserve 0 for conditional */            \
  _ (HANDOFF, "handoff to other worker")                                      \
  _ (PROXY_LOOP, "proxy output loop detected")                                \
  _ (RULE_BUSY, "rule modification in progress")                              \
  _ (REMOVED_SESSION, "already removed session")                              \
  _ (OLD_SESSION, "previously removed session")

static char *upf_session_dpo_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_session_dpo_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_SESSION_DPO_ERROR_##sym,
  foreach_upf_session_dpo_error
#undef _
    UPF_SESSION_DPO_N_ERROR,
} upf_session_dpo_error_t;

typedef enum
{
  UPF_SESSION_DPO_NEXT_DROP,
  UPF_SESSION_DPO_NEXT_HANDOFF,
  UPF_SESSION_DPO_NEXT_ICMP_ERROR,
  UPF_SESSION_DPO_NEXT_FLOW_PROCESS,
  UPF_SESSION_DPO_NEXT_FLOWLESS,
  UPF_SESSION_DPO_NEXT_NETCAP,
  UPF_SESSION_DPO_N_NEXT,
} upf_session_dpo_next_t;

typedef struct
{
  u64 up_seid;
  u32 session_id;
  u16 session_thread_id;
  u8 packet_data[64];
} upf_session_dpo_trace_t;

static u8 *
format_upf_session_dpo_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_session_dpo_trace_t *t = va_arg (*args, upf_session_dpo_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session=%d thread=%d seid=0x%016" PRIx64 " \n%U",
              t->session_id, t->session_thread_id, t->up_seid,
              format_white_space, indent);
  s = format (s, "%U", format_ip_header, t->packet_data,
              sizeof (t->packet_data));
  return s;
}

/* WARNING: the following code is mostly taken from vnet/ip/ip4_forward.c
 *
 * It is not clear to me if a similar effect
 * could be achived with a feature arc
 */

/* Decrement TTL & update checksum.
   Works either endian, so no need for byte swap. */
static_always_inline void
ip4_ttl_and_checksum_check (vlib_buffer_t *b, ip4_header_t *ip, u16 *next,
                            u32 *error)
{
  i32 ttl;
  u32 checksum;
  if (PREDICT_FALSE (b->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED))
    {
      b->flags &= ~VNET_BUFFER_F_LOCALLY_ORIGINATED;
      return;
    }

  ttl = ip->ttl;

  /* Input node should have reject packets with ttl 0. */
  ASSERT (ip->ttl > 0);

  checksum = ip->checksum + clib_host_to_net_u16 (0x0100);
  checksum += checksum >= 0xffff;

  ip->checksum = checksum;
  ttl -= 1;
  ip->ttl = ttl;

  /*
   * If the ttl drops below 1 when forwarding, generate
   * an ICMP response.
   */
  if (PREDICT_FALSE (ttl <= 0))
    {
      *error = IP4_ERROR_TIME_EXPIRED;
      vnet_buffer (b)->sw_if_index[VLIB_TX] = (u32) ~0;
      icmp4_error_set_vnet_buffer (b, ICMP4_time_exceeded,
                                   ICMP4_time_exceeded_ttl_exceeded_in_transit,
                                   0);
      *next = UPF_SESSION_DPO_NEXT_ICMP_ERROR;
    }

  /* Verify checksum. */
  ASSERT ((ip->checksum == ip4_header_checksum (ip)) ||
          ((b->flags & VNET_BUFFER_F_OFFLOAD) &&
           (vnet_buffer (b)->oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)));
}

/* end of copy from ip4_forward.c */

/* begin of copy from ip6_forward.c */

/* Check and Decrement hop limit */
static_always_inline void
ip6_hop_limit_check (vlib_buffer_t *b, ip6_header_t *ip, u16 *next, u32 *error)
{
  i32 hop_limit = ip->hop_limit;

  if (PREDICT_FALSE (b->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED))
    {
      b->flags &= ~VNET_BUFFER_F_LOCALLY_ORIGINATED;
      return;
    }

  hop_limit = ip->hop_limit;

  /* Input node should have reject packets with hop limit 0. */
  ASSERT (ip->hop_limit > 0);

  hop_limit -= 1;
  ip->hop_limit = hop_limit;

  if (PREDICT_FALSE (hop_limit <= 0))
    {
      /*
       * If the hop count drops below 1 when forwarding, generate
       * an ICMP response.
       */
      *error = IP6_ERROR_TIME_EXPIRED;
      vnet_buffer (b)->sw_if_index[VLIB_TX] = (u32) ~0;
      icmp6_error_set_vnet_buffer (b, ICMP6_time_exceeded,
                                   ICMP6_time_exceeded_ttl_exceeded_in_transit,
                                   0);
      *next = UPF_SESSION_DPO_NEXT_ICMP_ERROR;
    }
}

/* end of copy from ip6_forward.c */

static uword
_upf_ip_session_dpo_node (vlib_main_t *vm, vlib_node_runtime_t *node,
                          vlib_frame_t *from_frame, bool is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *um = &upf_main;
  upf_dpo_main_t *udm = &upf_dpo_main;

  u16 thread_index = vm->thread_index;

  upf_main_wk_t *uwk = vec_elt_at_index (um->workers, thread_index);

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u16 next = 0;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi = from[0];
          to_next[0] = bi;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          u32 error0 = UPF_SESSION_DPO_ERROR_NO_ERROR;

          vlib_buffer_t *b = vlib_get_buffer (vm, bi);

          index_t dpo_index = vnet_buffer (b)->ip.adj_index[VLIB_TX];

          upf_debug ("vec len %u idx %u", vec_len (udm->dp_dpos_results),
                     dpo_index);

          ASSERT (dpo_index < vec_len (udm->dp_dpos_results));

          upf_dpo_result_dp_t dpr = {
            .as_u64 =
              clib_atomic_load_acq_n (&udm->dp_dpos_results[dpo_index].as_u64),
          };

          u32 session_id = dpr.session_id;
          if (PREDICT_FALSE (!dpr.is_active))
            {
              error0 = UPF_SESSION_DPO_ERROR_RULE_BUSY;
              next = UPF_SESSION_DPO_NEXT_DROP;
              goto trace;
            }

          // handoff
          if (dpr.thread_id != thread_index)
            {
              upf_buffer_opaque (b)->handoff.thread_id = dpr.thread_id;
              error0 = UPF_SESSION_DPO_ERROR_HANDOFF;
              next = UPF_SESSION_DPO_NEXT_HANDOFF;
              goto trace_no_error;
            }

          void *iph = vlib_buffer_get_current (b);
          upf_vnet_buffer_l3l4_hdr_offset_current_ip (b, is_ip4);

          ip4_header_t *ip4;
          ip6_header_t *ip6;
          u8 ip_proto;
          if (is_ip4)
            {
              ip4 = iph;
              ip_proto = ip4->protocol;
            }
          else
            {
              ip6 = iph;
              ip_proto = ip6->protocol;
            }

          /*
           * Edge case: misdirected packet from upf-ip[46]-proxy-server-output
           * This happens when a session is modified and the PDRs/FARs relevant
           * for GTPU-U encapsulation are affected. This may cause the packets
           * to loop back to session-dpo via ip[46]-input.
           */
          if ((b->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED) &&
              ip_proto == IP_PROTOCOL_TCP)
            {
              upf_debug ("Proxy output loop detected: %U", format_ip_header,
                         iph, b->current_length);
              if (is_ip4)
                ip4_ttl_and_checksum_check (b, ip4, &next, &error0);
              else
                ip6_hop_limit_check (b, ip6, &next, &error0);

              error0 = UPF_SESSION_DPO_ERROR_PROXY_LOOP;
              next = UPF_SESSION_DPO_NEXT_FLOW_PROCESS;
              goto trace_no_error;
            }

          if (upf_pool_claim_is_free_index (&uwk->dp_session_claims,
                                            session_id))
            {
              error0 = UPF_SESSION_DPO_ERROR_REMOVED_SESSION;
              next = UPF_SESSION_DPO_NEXT_DROP;
              goto trace;
            }

          upf_dp_session_t *dsx =
            upf_wk_get_dp_session (thread_index, session_id);

          if (PREDICT_FALSE (dsx->session_generation !=
                             dpr.session_generation))
            {
              error0 = UPF_SESSION_DPO_ERROR_OLD_SESSION;
              next = UPF_SESSION_DPO_NEXT_DROP;
              goto trace;
            }

          ASSERT (dsx->is_created && !dsx->is_removed);

          upf_rules_t *rules = upf_wk_get_rules (thread_index, dsx->rules_id);
          UPF_ENTER_SUBGRAPH (b, session_id, UPF_PACKET_SOURCE_IP,
                              dpr.ue_ip_lid, is_ip4, dpr.is_src_ue);

          error0 = UPF_SESSION_DPO_ERROR_NO_ERROR;

          if (PREDICT_FALSE (rules->want_netcap))
            next = UPF_SESSION_DPO_NEXT_NETCAP;
          else if (dsx->flow_mode == UPF_SESSION_FLOW_MODE_DISABLED)
            next = UPF_SESSION_DPO_NEXT_FLOWLESS;
          else
            next = UPF_SESSION_DPO_NEXT_FLOW_PROCESS;

          upf_debug ("IP hdr: %U", format_ip_header, iph, b->current_length);

          if (is_ip4)
            ip4_ttl_and_checksum_check (b, ip4, &next, &error0);
          else
            ip6_hop_limit_check (b, ip6, &next, &error0);

          vnet_calc_checksums_inline (vm, b, is_ip4, !is_ip4);

          if (next != UPF_SESSION_DPO_NEXT_DROP &&
              next != UPF_SESSION_DPO_NEXT_ICMP_ERROR)
            goto trace_no_error;

        trace:
          b->error = error0 ? node->errors[error0] : 0;

        trace_no_error:
          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_session_dpo_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));

              tr->session_id = dpr.session_id;
              tr->session_thread_id = dpr.thread_id;
              if (dpr.thread_id == thread_index && is_valid_id (session_id))
                {
                  upf_dp_session_t *dsx =
                    pool_elt_at_index (um->dp_sessions, session_id);
                  tr->up_seid = dsx->up_seid;
                }
              else
                {
                  tr->up_seid = 0;
                }

              clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
                           sizeof (tr->packet_data));
            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi, next);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_session_dpo_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_ip_session_dpo_node (vm, node, from_frame, true);
}

VLIB_NODE_FN (upf_ip6_session_dpo_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_ip_session_dpo_node (vm, node, from_frame, false);
}

VLIB_REGISTER_NODE (upf_ip4_session_dpo_node) = {
  .name = "upf-ip4-session-dpo",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_session_dpo_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(upf_session_dpo_error_strings),
  .error_strings = upf_session_dpo_error_strings,

  .n_next_nodes = UPF_SESSION_DPO_N_NEXT,
  .next_nodes = {
    [UPF_SESSION_DPO_NEXT_DROP]         = "error-drop",
    [UPF_SESSION_DPO_NEXT_HANDOFF]      = "upf-dpo-ip4-handoff",
    [UPF_SESSION_DPO_NEXT_ICMP_ERROR]   = "ip4-icmp-error",
    [UPF_SESSION_DPO_NEXT_FLOW_PROCESS] = "upf-ip4-flow-process",
    [UPF_SESSION_DPO_NEXT_FLOWLESS]     = "upf-ip4-flowless",
    [UPF_SESSION_DPO_NEXT_NETCAP]       = "upf-netcap4",
  },
};

VLIB_REGISTER_NODE (upf_ip6_session_dpo_node) = {
  .name = "upf-ip6-session-dpo",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_session_dpo_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(upf_session_dpo_error_strings),
  .error_strings = upf_session_dpo_error_strings,

  .n_next_nodes = UPF_SESSION_DPO_N_NEXT,
  .next_nodes = {
    [UPF_SESSION_DPO_NEXT_DROP]         = "error-drop",
    [UPF_SESSION_DPO_NEXT_HANDOFF]      = "upf-dpo-ip6-handoff",
    [UPF_SESSION_DPO_NEXT_ICMP_ERROR]   = "ip6-icmp-error",
    [UPF_SESSION_DPO_NEXT_FLOW_PROCESS] = "upf-ip6-flow-process",
    [UPF_SESSION_DPO_NEXT_FLOWLESS]     = "upf-ip6-flowless",
    [UPF_SESSION_DPO_NEXT_NETCAP]       = "upf-netcap6",
  },
};

#include "upf/utils/upf_handoff_template.h"

VLIB_NODE_FN (upf_dpo_input4_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  upf_dpo_main_t *udm = &upf_dpo_main;

  return upf_handoff_template_node (vm, node, from_frame,
                                    udm->fq_dpo4_handoff_index);
}

VLIB_REGISTER_NODE (upf_dpo_input4_handoff_node) =
  UPF_HANDOFF_TEMPLATE_NODE_REGISTRATION ("upf-dpo-ip4-handoff");

VLIB_NODE_FN (upf_dpo_input6_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  upf_dpo_main_t *udm = &upf_dpo_main;

  return upf_handoff_template_node (vm, node, from_frame,
                                    udm->fq_dpo6_handoff_index);
}

VLIB_REGISTER_NODE (upf_dpo_input6_handoff_node) =
  UPF_HANDOFF_TEMPLATE_NODE_REGISTRATION ("upf-dpo-ip6-handoff");
