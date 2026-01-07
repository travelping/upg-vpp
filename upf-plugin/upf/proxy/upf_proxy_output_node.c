/*
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

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include "upf/upf.h"
#include "upf/rules/upf_classify_inlines.h"
#include "upf/proxy/upf_proxy.h"
#include "upf/flow/flowtable_inlines.h"
#include "upf/utils/ip_helpers.h"

#define UPF_DEBUG_ENABLE 0

typedef enum
{
  UPF_PROXY_OUTPUT_NEXT_DROP,
  UPF_PROXY_OUTPUT_NEXT_FORWARD,
  UPF_PROXY_OUTPUT_N_NEXT,
} upf_proxy_output_next_t;

/* Statistics (not all errors) */
#define foreach_upf_proxy_output_error                                        \
  _ (NO_ERROR, "reserved")                                                    \
  _ (PROCESS, "good packets process")                                         \
  _ (INVALID_FLOW, "flow entry not found")                                    \
  _ (INVALID_FLOW_OLD, "flow entry old")                                      \
  _ (LATE_PACKET, "proxy state already removed")                              \
  _ (NOT_CLASSIFIED, "not classified")                                        \
  _ (NO_MATCHED_PDR, "not matched PDR")                                       \
  _ (NON_UPF_TRAFFIC, "non-upf traffic")                                      \
  _ (CONTROLLED_BY_TCP_BYPASS, "controlled by tcp-bypass")

static char *upf_proxy_output_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_proxy_output_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_PROXY_OUTPUT_ERROR_##sym,
  foreach_upf_proxy_output_error
#undef _
    UPF_PROXY_OUTPUT_N_ERROR,
} upf_proxy_output_error_t;

typedef struct
{
  u64 up_seid;
  u32 session_index;
  u32 flow_id;
  u32 ps_id;
  u16 ps_generation;
  pfcp_ie_pdr_id_t pdr_id;
  upf_pdr_lid_t pdr_lid;
  u8 is_uplink : 1;
  u8 packet_data[64];
} upf_proxy_output_trace_t;

static u8 *
_format_upf_proxy_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_proxy_output_trace_t *t = va_arg (*args, upf_proxy_output_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session=%d seid=0x%016" PRIx64 " uplink=%d flow=%d\n%U",
              t->session_index, t->up_seid, t->is_uplink, t->flow_id,
              format_white_space, indent);
  s = format (s, "ps=%d ps_generation=%d pdr_id=%d pdr_lid=%d\n%U", t->ps_id,
              t->ps_generation, t->pdr_id, t->pdr_lid, format_white_space,
              indent);
  s = format (s, "%U", format_ip_header, t->packet_data,
              sizeof (t->packet_data));
  return s;
}

static uword
_upf_proxy_output (vlib_main_t *vm, vlib_node_runtime_t *node,
                   vlib_frame_t *from_frame, upf_proxy_side_t tx_side,
                   int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  flowtable_main_t *fm = &flowtable_main;
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, vm->thread_index);

  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, vm->thread_index);

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  bool is_uplink = (tx_side == UPF_PROXY_SIDE_AO);
  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          flow_entry_t *flow = NULL;
          upf_proxy_session_t *ps = NULL;
          upf_dp_session_t *dsx = NULL;
          upf_lid_t pdr_lid = ~0;

          upf_proxy_output_next_t next;

          u32 bi = from[0];
          to_next[0] = bi;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          vlib_buffer_t *b = vlib_get_buffer (vm, bi);

          upf_proxy_output_error_t error = UPF_PROXY_OUTPUT_ERROR_NO_ERROR;

          void *iph = vlib_buffer_get_current (b);

          ASSERT (b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID);
          ASSERT (b->current_data == vnet_buffer (b)->l3_hdr_offset);
          ASSERT (b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
          ASSERT ((b->current_data + (is_ip4 ? ip4_header_bytes (iph) :
                                               sizeof (ip6_header_t))) ==
                  vnet_buffer (b)->l4_hdr_offset);

          tcp_header_t *th =
            (void *) (b->data + vnet_buffer (b)->l4_hdr_offset);

          _upf_tcp_strip_syn_options (th);

          upf_debug ("IP hdr: %U", format_ip_header,
                     vlib_buffer_get_current (b), b->current_length);

          u32 raw_opaque = vnet_buffer (b)->tcp.next_node_opaque;
          if (raw_opaque == 0)
            {
              /* VPP host stack traffic not related to UPG */
              upf_debug ("Non-UPG TCP traffic, IP hdr: %U", format_ip_header,
                         vlib_buffer_get_current (b), b->current_length);
              error = UPF_PROXY_OUTPUT_ERROR_NON_UPF_TRAFFIC;
              next = UPF_PROXY_OUTPUT_NEXT_DROP;
              goto trace;
            }

          upf_proxy_session_opaque_t opaque = { .as_u32 = raw_opaque - 1 };

          if (pool_is_free_index (pwk->sessions, opaque.id))
            {
              upf_debug ("ps %d:%d not exists", opaque.id, opaque.generation);
              next = UPF_PROXY_OUTPUT_NEXT_DROP;
              error = UPF_PROXY_OUTPUT_ERROR_INVALID_FLOW;
              goto trace;
            }

          ps = pool_elt_at_index (pwk->sessions, opaque.id);
          if (ps->generation != opaque.generation)
            {
              upf_debug ("ps invalid gen %d != %d", ps->generation,
                         opaque.generation);
              next = UPF_PROXY_OUTPUT_NEXT_DROP;
              error = UPF_PROXY_OUTPUT_ERROR_INVALID_FLOW_OLD;
              goto trace;
            }

          if (!is_valid_id (ps->flow_index))
            {
              upf_debug ("ps flow detached ps_id %d", ps->self_id);
              next = UPF_PROXY_OUTPUT_NEXT_DROP;
              error = UPF_PROXY_OUTPUT_ERROR_LATE_PACKET;
              goto trace;
            }

          if (ps->is_spliced)
            {
              upf_debug (
                "remaining tcp stack traffic for stitched flow ps_id %d",
                ps->self_id);
              next = UPF_PROXY_OUTPUT_NEXT_DROP;
              error = UPF_PROXY_OUTPUT_ERROR_CONTROLLED_BY_TCP_BYPASS;
              goto trace;
            }

          flow = pool_elt_at_index (fwk->flows, ps->flow_index);
          upf_debug ("flow: %U\n", format_flow_entry, flow, vm->thread_index);

          upf_debug ("Flow UE/INET PDR Lids: %d/%d. side: %s",
                     flow->pdr_lids[UPF_DIR_UL], flow->pdr_lids[UPF_DIR_DL],
                     (tx_side == UPF_PROXY_SIDE_PO) ? "passive" : "active");

          dsx = upf_wk_get_dp_session (vm->thread_index, flow->session_id);

          u32 len0 = vlib_buffer_length_in_chain (vm, b);

          UPF_ENTER_SUBGRAPH (b, flow->session_id, UPF_PACKET_SOURCE_TCP_STACK,
                              ~0, is_ip4, is_uplink);

          /* update activity timer */
          _flow_update (fwk, flow, iph, th, is_ip4, len0);

          if (flow->generation != dsx->rules_generation)
            flowtable_entry_reset (flow, dsx->rules_generation);

          /* mostly borrowed from vnet/interface_output.c calc_checksums */
          if (is_ip4)
            {
              ip4_header_t *ip4 = iph;
              ip4->checksum = ip4_header_checksum (ip4);
              th->checksum = 0;
              th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
            }
          else
            {
              int bogus;
              th->checksum = 0;
              th->checksum =
                ip6_tcp_udp_icmp_compute_checksum (vm, b, iph, &bogus);
            }

          vnet_buffer_offload_flags_clear (b,
                                           (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
                                            VNET_BUFFER_OFFLOAD_F_UDP_CKSUM |
                                            VNET_BUFFER_OFFLOAD_F_IP_CKSUM));

          if (is_uplink ? flow->is_classified_ul : flow->is_classified_dl)
            {
              pdr_lid = flow->pdr_lids[is_uplink ? UPF_DIR_UL : UPF_DIR_DL];
            }
          else
            {
              upf_rules_t *rules =
                upf_wk_get_rules (vm->thread_index, dsx->rules_id);

              upf_classify_flow (rules, flow, UPF_PACKET_SOURCE_TCP_STACK, ~0,
                                 is_uplink, is_ip4, &pdr_lid);
            }

          if (!is_valid_id (pdr_lid))
            {
              next = UPF_PROXY_OUTPUT_NEXT_DROP;
              error = UPF_PROXY_OUTPUT_ERROR_NO_MATCHED_PDR;
              goto trace;
            }
          _upf_opaque_set_flow_values (fwk, b, flow, is_uplink);
          upf_buffer_opaque (b)->gtpu.is_proxied = 1;
          next = UPF_PROXY_OUTPUT_NEXT_FORWARD;

        trace:
          b->error = error ? node->errors[error] : 0;

          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_proxy_output_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));

              tr->up_seid = dsx ? dsx->up_seid : 0;
              tr->session_index = flow ? flow->session_id : ~0;
              tr->flow_id = ps ? ps->flow_index : ~0;
              tr->ps_id = opaque.id;
              tr->ps_generation = opaque.generation;
              tr->pdr_lid = pdr_lid;
              tr->pdr_id =
                (dsx && is_valid_id (pdr_lid)) ?
                  upf_rules_get_pdr (
                    upf_wk_get_rules (vm->thread_index, dsx->rules_id),
                    pdr_lid)
                    ->pfcp_id :
                  ~0;
              tr->is_uplink = is_uplink;
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

VLIB_NODE_FN (upf_ip4_proxy_server_output_po_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_proxy_output (vm, node, from_frame, UPF_PROXY_SIDE_PO,
                            /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_proxy_server_output_po_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_proxy_output (vm, node, from_frame, UPF_PROXY_SIDE_PO,
                            /* is_ip4 */ 0);
}

VLIB_NODE_FN (upf_ip4_proxy_server_output_ao_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_proxy_output (vm, node, from_frame, UPF_PROXY_SIDE_AO,
                            /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_proxy_server_output_ao_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_proxy_output (vm, node, from_frame, UPF_PROXY_SIDE_AO,
                            /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (upf_ip4_proxy_server_output_ao_node) = {
  .name = "upf-ip4-proxy-server-output-ao",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_proxy_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_output_error_strings),
  .error_strings = upf_proxy_output_error_strings,
  .n_next_nodes = UPF_PROXY_OUTPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_OUTPUT_NEXT_DROP]            = "error-drop",
    [UPF_PROXY_OUTPUT_NEXT_FORWARD]         = "upf-ip4-forward",
  },
};

VLIB_REGISTER_NODE (upf_ip6_proxy_server_output_ao_node) = {
  .name = "upf-ip6-proxy-server-output-ao",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_proxy_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_output_error_strings),
  .error_strings = upf_proxy_output_error_strings,
  .n_next_nodes = UPF_PROXY_OUTPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_OUTPUT_NEXT_DROP]            = "error-drop",
    [UPF_PROXY_OUTPUT_NEXT_FORWARD]         = "upf-ip6-forward",
  },
};

VLIB_REGISTER_NODE (upf_ip4_proxy_server_output_po_node) = {
  .name = "upf-ip4-proxy-server-output-po",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_proxy_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_output_error_strings),
  .error_strings = upf_proxy_output_error_strings,
  .n_next_nodes = UPF_PROXY_OUTPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_OUTPUT_NEXT_DROP]            = "error-drop",
    [UPF_PROXY_OUTPUT_NEXT_FORWARD]         = "upf-ip4-forward",
  },
};

VLIB_REGISTER_NODE (upf_ip6_proxy_server_output_po_node) = {
  .name = "upf-ip6-proxy-server-output-po",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_proxy_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_output_error_strings),
  .error_strings = upf_proxy_output_error_strings,
  .n_next_nodes = UPF_PROXY_OUTPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_OUTPUT_NEXT_DROP]            = "error-drop",
    [UPF_PROXY_OUTPUT_NEXT_FORWARD]         = "upf-ip6-forward",
  },
};
