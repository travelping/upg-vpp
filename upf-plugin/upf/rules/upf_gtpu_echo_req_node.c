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

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>

#include "upf/rules/upf_gtpu_proto.h"
#include "upf/core/upf_buffer_opaque.h"

#define UPF_DEBUG_ENABLE 0

typedef enum
{
  UPF_GTPU_ECHO_REQ_NEXT_DROP,
  UPF_GTPU_ECHO_REQ_NEXT_REPLY,
  UPF_GTPU_ECHO_REQ_N_NEXT,
} gtpu_echo_req_next_t;

#define foreach_upf_gtpu_echo_req_error                                       \
  _ (RESPONSES_SENT, "echo responses sent")

typedef enum
{
#define _(n, s) UPF_GTPU_ECHO_REQ_ERROR_##n,
  foreach_upf_gtpu_echo_req_error
#undef _
    UPF_GTPU_ECHO_REQ_N_ERROR,
} upf_gtpu_echo_req_error_t;

static char *upf_gtpu_echo_req_error_strings[] = {
#define _(n, s) s,
  foreach_upf_gtpu_echo_req_error
#undef _
};

typedef struct
{
  u8 packet_data[64];
} gtpu_echo_req_trace_t;

static u8 *
_format_gtpu_ip4_echo_req_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtpu_echo_req_trace_t *t = va_arg (*args, gtpu_echo_req_trace_t *);

  return format (s, "%U", format_ip4_header, t->packet_data,
                 sizeof (t->packet_data));
}

VLIB_NODE_FN (upf_gtp_ip4_echo_req_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ip4_main_t *i4m = &ip4_main;
  uword n_packets = frame->n_vectors;
  u32 n_left_from, next_index, *from, *to_next;
  u16 *fragment_ids, *fid;
  u8 host_config_ttl = i4m->host_config.ttl;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
                                   sizeof (from[0]),
                                   sizeof (gtpu_echo_req_trace_t));

  /* Get random fragment IDs for replies. */
  fid = fragment_ids = clib_random_buffer_get_data (
    &vm->random_buffer, n_packets * sizeof (fragment_ids[0]));

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 next0 = UPF_GTPU_ECHO_REQ_NEXT_REPLY;
          u32 error0 = UPF_GTPU_ECHO_REQ_ERROR_RESPONSES_SENT;
          ip4_header_t *ip0;
          udp_header_t *udp0;
          gtpu_header_t *gtpu0;
          vlib_buffer_t *p0;
          u32 bi0;
          ip4_address_t tmp0;
          u16 port0;
          ip_csum_t sum0;
          gtpu_ie_recovery_t *gtpu_recovery0;
          u16 new_len0, new_ip_len0;

          bi0 = to_next[0] = from[0];

          from += 1;
          n_left_from -= 1;
          to_next += 1;
          n_left_to_next -= 1;

          p0 = vlib_get_buffer (vm, bi0);
          UPF_CHECK_INNER_NODE (p0);
          ip0 = vlib_buffer_get_current (p0);
          udp0 = ip4_next_header (ip0);

          gtpu0 = (gtpu_header_t *) (udp0 + 1);
          gtpu0->h.ver_flags &= ~(GTPU_E_BIT | GTPU_PN_BIT);
          if (!(gtpu0->h.ver_flags & GTPU_S_BIT))
            {
              gtpu0->h.ver_flags |= GTPU_S_BIT;
              gtpu0->sequence = 0;
            }
          gtpu0->h.type = GTPU_TYPE_ECHO_RESPONSE;
          gtpu0->h.length =
            clib_net_to_host_u16 (sizeof (gtpu_ie_recovery_t) + 4);
          /*
           * TS 29.281 5.1: for Echo Request/Response, 0 is always used
           * for the response TEID
           */
          gtpu0->h.teid = 0;
          gtpu0->pdu_number = 0;
          gtpu0->next_ext_type = 0;
          gtpu_recovery0 = (gtpu_ie_recovery_t *) ((u8 *) (udp0 + 1) +
                                                   sizeof (gtpu_header_t));
          gtpu_recovery0->ie_type = GTPU_IE_RECOVERY;
          gtpu_recovery0->restart_counter = 0;

          vnet_buffer (p0)->sw_if_index[VLIB_RX] =
            vnet_main.local_interface_sw_if_index;

          /* Swap source and destination address. */
          tmp0 = ip0->src_address;
          ip0->src_address = ip0->dst_address;
          ip0->dst_address = tmp0;

          /* Calculate new IP length. */
          new_len0 = ip4_header_bytes (ip0) + sizeof (udp_header_t) +
                     sizeof (gtpu_header_t) + sizeof (gtpu_ie_recovery_t);
          p0->current_length = new_len0;

          /* Update IP header fields and checksum. */
          sum0 = ip0->checksum;

          sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl, ip4_header_t,
                                 ttl);
          ip0->ttl = host_config_ttl;

          sum0 = ip_csum_update (sum0, ip0->fragment_id, fid[0], ip4_header_t,
                                 fragment_id);
          ip0->fragment_id = fid[0];
          fid += 1;

          new_ip_len0 = clib_host_to_net_u16 (new_len0);
          sum0 = ip_csum_update (sum0, ip0->length, new_ip_len0, ip4_header_t,
                                 length);
          ip0->length = new_ip_len0;

          ip0->checksum = ip_csum_fold (sum0);
          ASSERT (ip0->checksum == ip4_header_checksum (ip0));

          /* Swap source and destination port. */
          port0 = udp0->src_port;
          udp0->src_port = udp0->dst_port;
          udp0->dst_port = port0;

          /* UDP length. */
          udp0->length = clib_host_to_net_u16 (sizeof (udp_header_t) +
                                               sizeof (gtpu_header_t) +
                                               sizeof (gtpu_ie_recovery_t));
          /* UDP checksum. */
          udp0->checksum = 0;
          udp0->checksum = ip4_tcp_udp_compute_checksum (vm, p0, ip0);
          if (udp0->checksum == 0)
            udp0->checksum = 0xffff;

          p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

          vlib_error_count (vm, node->node_index, error0, 1);

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static u8 *
_format_gtpu_ip6_echo_req_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtpu_echo_req_trace_t *t = va_arg (*args, gtpu_echo_req_trace_t *);

  return format (s, "%U", format_ip6_header, t->packet_data,
                 sizeof (t->packet_data));
}

VLIB_NODE_FN (upf_gtp_ip6_echo_req_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ip6_main_t *i6m = &ip6_main;
  uword n_packets = frame->n_vectors;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
                                   sizeof (from[0]),
                                   sizeof (gtpu_echo_req_trace_t));

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 next0 = UPF_GTPU_ECHO_REQ_NEXT_REPLY;
          u32 error0 = UPF_GTPU_ECHO_REQ_ERROR_RESPONSES_SENT;
          ip6_header_t *ip0;
          udp_header_t *udp0;
          gtpu_header_t *gtpu0;
          u32 fib_index0;
          vlib_buffer_t *p0;
          u32 bi0;
          ip6_address_t tmp0;
          u16 port0;
          int bogus0;
          gtpu_ie_recovery_t *gtpu_recovery0;
          u16 new_len0;

          bi0 = to_next[0] = from[0];

          from += 1;
          n_left_from -= 1;
          to_next += 1;
          n_left_to_next -= 1;

          p0 = vlib_get_buffer (vm, bi0);
          UPF_CHECK_INNER_NODE (p0);
          ip0 = vlib_buffer_get_current (p0);
          udp0 = ip6_next_header (ip0);

          gtpu0 = (gtpu_header_t *) (udp0 + 1);
          gtpu0->h.ver_flags &= ~(GTPU_E_BIT | GTPU_PN_BIT);
          if (!(gtpu0->h.ver_flags & GTPU_S_BIT))
            {
              gtpu0->h.ver_flags |= GTPU_S_BIT;
              gtpu0->sequence = 0;
            }
          gtpu0->h.type = GTPU_TYPE_ECHO_RESPONSE;
          gtpu0->h.length =
            clib_net_to_host_u16 (sizeof (gtpu_ie_recovery_t) + 4);
          /*
           * TS 29.281 5.1: for Echo Request/Response, 0 is always used
           * for the response TEID
           */
          gtpu0->h.teid = 0;
          gtpu0->pdu_number = 0;
          gtpu0->next_ext_type = 0;
          gtpu_recovery0 = (gtpu_ie_recovery_t *) ((u8 *) (udp0 + 1) +
                                                   sizeof (gtpu_header_t));
          gtpu_recovery0->ie_type = GTPU_IE_RECOVERY;
          gtpu_recovery0->restart_counter = 0;

          /* if the packet is link local, we'll bounce through the link-local
           * table with the RX interface correctly set */
          fib_index0 = vec_elt (i6m->fib_index_by_sw_if_index,
                                vnet_buffer (p0)->sw_if_index[VLIB_RX]);
          vnet_buffer (p0)->sw_if_index[VLIB_TX] = fib_index0;

          /* Swap source and destination address. */
          tmp0 = ip0->src_address;
          ip0->src_address = ip0->dst_address;
          ip0->dst_address = tmp0;

          ip0->hop_limit = i6m->host_config.ttl;

          /* Calculate new IP length. */
          new_len0 = sizeof (udp_header_t) + sizeof (gtpu_header_t) +
                     sizeof (gtpu_ie_recovery_t);
          p0->current_length = sizeof (ip6_header_t) + new_len0;
          ip0->payload_length = clib_host_to_net_u16 (new_len0);

          /* Swap source and destination port. */
          port0 = udp0->src_port;
          udp0->src_port = udp0->dst_port;
          udp0->dst_port = port0;

          /* UDP length. */
          udp0->length = ip0->payload_length;

          /* UDP checksum. */
          udp0->checksum = 0;
          udp0->checksum =
            ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip0, &bogus0);
          if (udp0->checksum == 0)
            udp0->checksum = 0xffff;

          p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

          vlib_error_count (vm, node->node_index, error0, 1);

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (upf_gtp_ip4_echo_req_node) = {
  .name = "upf-gtp-ip4-echo-request",
  .vector_size = sizeof (u32),
  .format_trace = _format_gtpu_ip4_echo_req_trace,

  .n_errors = UPF_GTPU_ECHO_REQ_N_ERROR,
  .error_strings = upf_gtpu_echo_req_error_strings,

  .n_next_nodes = UPF_GTPU_ECHO_REQ_N_NEXT,
  .next_nodes = {
    [UPF_GTPU_ECHO_REQ_NEXT_DROP] = "error-drop",
    [UPF_GTPU_ECHO_REQ_NEXT_REPLY] = "ip4-load-balance",
  },
};

VLIB_REGISTER_NODE (upf_gtp_ip6_echo_req_node) = {
  .name = "upf-gtp-ip6-echo-request",
  .vector_size = sizeof (u32),
  .format_trace = _format_gtpu_ip6_echo_req_trace,

  .n_errors = UPF_GTPU_ECHO_REQ_N_ERROR,
  .error_strings = upf_gtpu_echo_req_error_strings,

  .n_next_nodes = UPF_GTPU_ECHO_REQ_N_NEXT,
  .next_nodes = {
    [UPF_GTPU_ECHO_REQ_NEXT_DROP] = "error-drop",
    [UPF_GTPU_ECHO_REQ_NEXT_REPLY] = "ip6-lookup",
  },
};
