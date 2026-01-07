/*
 * Copyright (c) 2025 Travelping GmbH
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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>

#include "upf/upf.h"
#include "upf/rules/upf_classify_inlines.h"
#include "upf/flow/flowtable_inlines.h"
#include "upf/utils/ip_helpers.h"

#define UPF_DEBUG_ENABLE 0

typedef enum
{
  UPF_PROXY_RESET_NEXT_DROP,
  UPF_PROXY_RESET_NEXT_FORWARD,
  UPF_PROXY_RESET_N_NEXT,
} upf_proxy_reset_next_t;

/* Statistics (not all errors) */
#define foreach_upf_proxy_reset_error                                         \
  _ (NO_ERROR, "no error") /* just to reserve 0 for conditional */            \
  _ (SENT_TCP_RESET, "sent tcp reset")                                        \
  _ (NO_MATCHED_PDR, "not matched PDR")

static char *upf_proxy_reset_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_proxy_reset_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_PROXY_RESET_ERROR_##sym,
  foreach_upf_proxy_reset_error
#undef _
    UPF_PROXY_RESET_N_ERROR,
} upf_proxy_reset_error_t;

typedef struct
{
  u64 up_seid;
  u32 session_index;
  u32 flow_id;
  pfcp_ie_pdr_id_t pdr_id;
  upf_pdr_lid_t pdr_lid;
  u8 is_rx_uplink : 1;
  u8 is_tx_uplink : 1;
  u8 packet_data[64];
} upf_proxy_reset_trace_t;

static u8 *
format_upf_proxy_reset_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_proxy_reset_trace_t *t = va_arg (*args, upf_proxy_reset_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session=%d seid=0x%016" PRIx64 " flow=%d\n%U",
              t->session_index, t->up_seid, t->flow_id, format_white_space,
              indent);
  s = format (s, "tx_uplink=%d rx_uplink=%d pdr_id=%d pdr_lid=%d\n%U",
              t->is_tx_uplink, t->is_rx_uplink, t->pdr_id, t->pdr_lid,
              format_white_space, indent);
  s = format (s, "%U", format_ip_header, t->packet_data,
              sizeof (t->packet_data));
  return s;
}

static uword
_upf_proxy_reset (vlib_main_t *vm, vlib_node_runtime_t *node,
                  vlib_frame_t *from_frame, bool is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  flowtable_main_t *fm = &flowtable_main;
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, vm->thread_index);

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          bi = from[0];
          to_next[0] = bi;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          vlib_buffer_t *b = vlib_get_buffer (vm, bi);
          upf_proxy_reset_next_t next = UPF_PROXY_RESET_NEXT_FORWARD;
          upf_proxy_reset_error_t error = UPF_PROXY_RESET_ERROR_NO_ERROR;

          ASSERT (is_valid_id (upf_buffer_opaque (b)->gtpu.flow_id));

          flow_entry_t *flow = flowtable_get_flow_by_id (
            vm->thread_index, upf_buffer_opaque (b)->gtpu.flow_id);

          bool rx_ul = upf_buffer_opaque (b)->gtpu.is_uplink;
          bool tx_ul = !rx_ul;

          void *iph = vlib_buffer_get_current (b);

          tcp_header_t *th =
            (void *) (b->data + vnet_buffer (b)->l4_hdr_offset);

          ip4_header_t *ip4h;
          ip6_header_t *ip6h;
          u32 ip_len;
          if (is_ip4)
            {
              ip4h = iph;
              ip_len =
                clib_net_to_host_u16 (ip4h->length) - ip4_header_bytes (iph);
            }
          else
            {
              ip6h = iph;
              ip_len = clib_net_to_host_u16 ((ip6h)->payload_length);
            }

          u32 tcp_segment_len = ip_len - tcp_header_bytes (th);

          if (is_ip4)
            {
              ip4h->length = clib_host_to_net_u16 (sizeof (ip4_header_t) +
                                                   sizeof (tcp_header_t));
              ip4h->fragment_id = 0;
              ip4h->flags_and_fragment_offset = 0;
              ip4h->ttl -= 1;
              ip4h->checksum = 0;

              ip4_address_t orig_src = ip4h->src_address,
                            orig_dst = ip4h->dst_address;
              ip4h->dst_address = orig_src;
              ip4h->src_address = orig_dst;
            }
          else
            {
              ip6h->payload_length =
                clib_host_to_net_u16 (sizeof (tcp_header_t));
              ip6h->hop_limit -= 1;

              ip6_address_t orig_src = ip6h->src_address,
                            orig_dst = ip6h->dst_address;
              ip6h->dst_address = orig_src;
              ip6h->src_address = orig_dst;
            }

          u16 orig_src_port = th->src_port, orig_dst_port = th->dst_port;
          th->src_port = orig_dst_port;
          th->dst_port = orig_src_port;

          if (tcp_ack (th))
            {
              th->seq_number = th->ack_number;
              th->ack_number = 0;
              th->flags = TCP_FLAG_RST;
            }
          else
            {
              th->ack_number = clib_host_to_net_u32 (
                clib_net_to_host_u32 (th->ack_number) + tcp_segment_len);
              th->seq_number = 0;
              th->flags = TCP_FLAG_RST | TCP_FLAG_ACK;
            }

          th->data_offset_and_reserved = (sizeof (tcp_header_t) >> 2) << 4;
          th->window = 0;
          th->urgent_pointer = 0;
          th->checksum = 0;

          if (is_ip4)
            {
              ip4h->checksum = ip4_header_checksum (ip4h);
              th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4h);
            }
          else
            {
              int bogus;
              th->checksum =
                ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6h, &bogus);
            }

          vnet_buffer_offload_flags_clear (b,
                                           (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
                                            VNET_BUFFER_OFFLOAD_F_UDP_CKSUM |
                                            VNET_BUFFER_OFFLOAD_F_IP_CKSUM));
          upf_vnet_buffer_reuse_without_chained_buffers (vm, b);
          b->current_length =
            (vnet_buffer (b)->l4_hdr_offset - vnet_buffer (b)->l3_hdr_offset) +
            sizeof (tcp_header_t);

          upf_dp_session_t *dsx =
            upf_wk_get_dp_session (vm->thread_index, flow->session_id);

          if (CLIB_ASSERT_ENABLE)
            b->flags &= ~UPF_BUFFER_F_GTPU_INITIALIZED;

          // re-enter subgraph in reverse direction
          UPF_ENTER_SUBGRAPH (b, flow->session_id, UPF_PACKET_SOURCE_TCP_STACK,
                              ~0, is_ip4, tx_ul);

          upf_buffer_opaque (b)->gtpu.is_proxied = 1;
          upf_buffer_opaque (b)->gtpu.flow_id = flow - fwk->flows;

          upf_lid_t pdr_lid = ~0;
          if (tx_ul ? flow->is_classified_ul : flow->is_classified_dl)
            {
              pdr_lid = flow->pdr_lids[tx_ul ? UPF_DIR_UL : UPF_DIR_DL];
            }
          else
            {
              upf_rules_t *rules =
                upf_wk_get_rules (vm->thread_index, dsx->rules_id);

              upf_classify_flow (rules, flow, UPF_PACKET_SOURCE_TCP_STACK, ~0,
                                 tx_ul, is_ip4, &pdr_lid);
            }

          if (!is_valid_id (pdr_lid))
            {
              next = UPF_PROXY_RESET_NEXT_DROP;
              error = UPF_PROXY_RESET_ERROR_NO_MATCHED_PDR;
              goto trace;
            }
          _upf_opaque_set_flow_values (fwk, b, flow, tx_ul);

          upf_buffer_opaque (b)->gtpu.is_proxied = 1;

          vlib_node_increment_counter (
            vm, node->node_index, UPF_PROXY_RESET_ERROR_SENT_TCP_RESET, 1);

        trace:
          b->error = error ? node->errors[error] : 0;

          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_proxy_reset_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));

              tr->up_seid = dsx->up_seid;
              tr->session_index = flow->session_id;
              tr->flow_id = upf_buffer_opaque (b)->gtpu.flow_id;
              tr->pdr_lid = pdr_lid;
              tr->pdr_id =
                is_valid_id (pdr_lid) ?
                  upf_rules_get_pdr (
                    upf_wk_get_rules (vm->thread_index, dsx->rules_id),
                    pdr_lid)
                    ->pfcp_id :
                  ~0;
              tr->is_rx_uplink = rx_ul;
              tr->is_tx_uplink = tx_ul;
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

VLIB_NODE_FN (upf_ip4_proxy_reset_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_proxy_reset (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_proxy_reset_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_proxy_reset (vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (upf_ip4_proxy_reset_node) = {
  .name = "upf-ip4-proxy-reset",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_proxy_reset_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_reset_error_strings),
  .error_strings = upf_proxy_reset_error_strings,
  .n_next_nodes = UPF_PROXY_RESET_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_RESET_NEXT_DROP]            = "error-drop",
    [UPF_PROXY_RESET_NEXT_FORWARD]         = "upf-ip4-forward",
  },
};

VLIB_REGISTER_NODE (upf_ip6_proxy_reset_node) = {
  .name = "upf-ip6-proxy-reset",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_proxy_reset_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_reset_error_strings),
  .error_strings = upf_proxy_reset_error_strings,
  .n_next_nodes = UPF_PROXY_RESET_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_RESET_NEXT_DROP]            = "error-drop",
    [UPF_PROXY_RESET_NEXT_FORWARD]         = "upf-ip6-forward",
  },
};
