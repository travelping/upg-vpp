/*
 * Copyright (c) 2017 Intel and/or its affiliates
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

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/types.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include "upf/upf.h"
#include "upf/upf_stats.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/rules/upf_gtpu_proto.h"
#include "upf/core/upf_buffer_opaque.h"

#define UPF_DEBUG_ENABLE 0

#define foreach_gtp_upf_encap_error                                           \
  _ (ENCAPSULATED, "good packets encapsulated")

static char *upf_gtp_encap_error_strings[] = {
#define _(sym, string) string,
  foreach_gtp_upf_encap_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_ENCAP_ERROR_##sym,
  foreach_gtp_upf_encap_error
#undef _
    UPF_ENCAP_N_ERROR,
} upf_gtp_encap_error_t;

typedef enum
{
  UPF_GTP_ENCAP_NEXT_IP_LOOKUP,
  UPF_GTP_ENCAP_NEXT_DROP,
  UPF_GTP_ENCAP_N_NEXT,
} upf_gtp_encap_next_t;

typedef struct
{
  u32 session_index;
  u32 teid;
  u32 inner_flow_hash;
  u16 nwi_id;
  pfcp_ie_pdr_id_t pdr_id;
  pfcp_ie_far_id_t far_id;
  u16 gtpu_ep_id;
} upf_gtp_encap_trace_t;

u8 *
format_upf_encap_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_gtp_encap_trace_t *t = va_arg (*args, upf_gtp_encap_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (
    s, "GTPU encap upf_session=%d teid=0x%08x inner_flow_hash 0x%08x\n%U",
    t->session_index, t->teid, t->inner_flow_hash, format_white_space, indent);
  s = format (s, "nwi_id=%d pdr_id=%d far_id=%d gtpu_ep_id=%d", t->nwi_id,
              t->pdr_id, t->far_id, t->gtpu_ep_id);

  return s;
}

always_inline uword
upf_encap_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
                  vlib_frame_t *from_frame, u32 outer_is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *um = &upf_main;
  u32 pkts_encapsulated = 0;
  u32 next0 = 0;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
          UPF_CHECK_INNER_NODE (b0);

          u32 inner_flow_hash0;
          bool inner_is_ip4 = upf_buffer_opaque (b0)->gtpu.is_ue_v4;
          void *inner_iph = b0->data + vnet_buffer (b0)->l3_hdr_offset;
          if (inner_is_ip4)
            inner_flow_hash0 =
              ip4_compute_flow_hash (inner_iph, IP_FLOW_HASH_DEFAULT);
          else
            inner_flow_hash0 =
              ip6_compute_flow_hash (inner_iph, IP_FLOW_HASH_DEFAULT);

          upf_dp_session_t *dsx = pool_elt_at_index (
            um->dp_sessions, upf_buffer_opaque (b0)->gtpu.session_id);

          upf_rules_t *rules =
            upf_wk_get_rules (vm->thread_index, dsx->rules_id);

          rules_pdr_t *pdr0 =
            upf_rules_get_pdr (rules, upf_buffer_opaque (b0)->gtpu.pdr_lid);
          rules_far_t *far0 = upf_rules_get_far (rules, pdr0->far_lid);

          rules_far_forward_t *ff = &far0->forward;

          u16 og_ext_hdr_len = upf_buffer_opaque (b0)->gtpu.gtpu_ext_hdr_len;
          if (!pdr0->gtpu_outer_header_removal)
            {
              // reuse original extension header only if it was removed
              og_ext_hdr_len = 0;
              // advance to original gtpu header
              vlib_buffer_advance (
                b0, -upf_buffer_opaque (b0)->gtpu.outer_hdr_len);
            }

          u16 gtpu_len = sizeof (gtpu_header_tpdu_t) + og_ext_hdr_len;
          u16 inner_len = vlib_buffer_length_in_chain (vm, b0);

          upf_debug (
            "encapping dsx %d rules %d pdr %d (%d) far %d (%d) inner_ip4=%d "
            "outer_ip4=%d LEN: gtpu=%d ext_hdr=%d inner=%d",
            upf_buffer_opaque (b0)->gtpu.session_id, dsx->rules_id,
            upf_buffer_opaque (b0)->gtpu.pdr_lid, pdr0->pfcp_id, pdr0->far_lid,
            far0->pfcp_id, inner_is_ip4, outer_is_ip4, gtpu_len,
            upf_buffer_opaque (b0)->gtpu.gtpu_ext_hdr_len, inner_len);

          upf_nwi_t *nwi = pool_elt_at_index (um->nwis, ff->nwi_id);

          upf_gtpu_endpoint_t *gtpu_ep0 =
            pool_elt_at_index (ugm->endpoints, ff->ohc.src_gtpu_endpoint_id);

          udp_header_t *udp;
          void *iph;
          if (outer_is_ip4)
            {
              vlib_buffer_advance (b0, -(gtpu_len + sizeof (udp_header_t) +
                                         sizeof (ip4_header_t)));
              ip4_header_t *ip4 = iph = vlib_buffer_get_current (b0);

              ip4->ip_version_and_header_length = 0x45;
              ip4->tos = 0;
              ip4->length = clib_host_to_net_u16 (inner_len + gtpu_len +
                                                  sizeof (udp_header_t) +
                                                  sizeof (ip4_header_t));
              ip4->fragment_id = 0;
              ip4->flags_and_fragment_offset = 0;
              ip4->ttl = 127;
              ip4->protocol = IP_PROTOCOL_UDP;
              ip4->checksum = 0;
              ip4->src_address = gtpu_ep0->ip4;
              ip4->dst_address = ff->ohc.addr4;
              ip4->checksum = ip4_header_checksum (ip4);

              udp = (udp_header_t *) (ip4 + 1);
            }
          else
            {
              vlib_buffer_advance (b0, -(gtpu_len + sizeof (udp_header_t) +
                                         sizeof (ip6_header_t)));
              ip6_header_t *ip6 = iph = vlib_buffer_get_current (b0);

              ip6->ip_version_traffic_class_and_flow_label = 0x60;
              ip6->payload_length = clib_host_to_net_u16 (
                inner_len + gtpu_len + sizeof (udp_header_t));
              ip6->protocol = IP_PROTOCOL_UDP;
              ip6->hop_limit = 127;
              ip6->src_address = gtpu_ep0->ip6;
              ip6->dst_address = ff->ohc.addr6;

              udp = (udp_header_t *) (ip6 + 1);
            }
          next0 = UPF_GTP_ENCAP_NEXT_IP_LOOKUP;

          u16 src_port_hash = (inner_flow_hash0 >> 16) ^ inner_flow_hash0;
          udp->src_port = clib_host_to_net_u16 (
            gtpu_ep0->src_port_start +
            (src_port_hash & gtpu_ep0->src_port_len_mask));
          udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_GTPU);
          udp->length = clib_host_to_net_u16 (inner_len + gtpu_len +
                                              sizeof (udp_header_t));
          udp->checksum = 0;

          gtpu_header_tpdu_t *gtpu = (gtpu_header_tpdu_t *) (udp + 1);

          gtpu->length = clib_host_to_net_u16 (inner_len + og_ext_hdr_len);
          gtpu->ver_flags = GTPU_V1_VER | GTPU_PT_GTP;
          if (og_ext_hdr_len)
            gtpu->ver_flags |= GTPU_E_S_PN_BIT;
          gtpu->type = GTPU_TYPE_GTPU;
          gtpu->teid = clib_host_to_net_u32 (far0->forward.ohc.teid);

          if (!outer_is_ip4)
            {
              /* IPv6 UDP checksum is mandatory */
              int bogus_length;
              udp->checksum =
                ip6_tcp_udp_icmp_compute_checksum (vm, b0, iph, &bogus_length);
              ASSERT (bogus_length == 0);
            }
          else
            {
              udp->checksum = 0;
            }

          vlib_increment_combined_counter (
            &upf_stats_main.wk.gtpu_endpoint_tx, vm->thread_index,
            gtpu_ep0 - ugm->endpoints, 1,
            vlib_buffer_length_in_chain (vm, b0));

          b0->flags |=
            outer_is_ip4 ? VNET_BUFFER_F_IS_IP4 : VNET_BUFFER_F_IS_IP6;
          b0->flags |= VNET_BUFFER_F_L4_CHECKSUM_COMPUTED;
          b0->flags |= VNET_BUFFER_F_L4_CHECKSUM_CORRECT;
          b0->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
          b0->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;

          // checksums are valid, no need to offload
          vnet_buffer_offload_flags_clear (b0,
                                           (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
                                            VNET_BUFFER_OFFLOAD_F_UDP_CKSUM |
                                            VNET_BUFFER_OFFLOAD_F_IP_CKSUM));

          vnet_buffer (b0)->l3_hdr_offset = (u8 *) iph - b0->data;
          vnet_buffer (b0)->l4_hdr_offset = (u8 *) udp - b0->data;

          // vnet_buffer (b0)->ip.adj_index[VLIB_TX] =

          // TODO: Maybe it is better to:
          // Instead of nwif fib index use gtpu endpoint fib indexes
          // detected during gtpu endpoint creation
          u16 nwif_id = nwi->interfaces_ids[far0->forward.dst_intf];
          upf_interface_t *nwif =
            pool_elt_at_index (um->nwi_interfaces, nwif_id);
          vnet_buffer (b0)->sw_if_index[VLIB_TX] =
            nwif->tx_fib_index[outer_is_ip4 ? FIB_PROTOCOL_IP4 :
                                              FIB_PROTOCOL_IP6];

          pkts_encapsulated++;

          /* save inner packet flow_hash for load-balance node */
          vnet_buffer (b0)->ip.flow_hash = inner_flow_hash0;

          if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_gtp_encap_trace_t *tr =
                vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->session_index = dsx - um->dp_sessions;
              tr->teid = far0->forward.ohc.teid;
              tr->inner_flow_hash = inner_flow_hash0;
              tr->nwi_id = nwi - um->nwis;
              tr->pdr_id = pdr0->pfcp_id;
              tr->far_id = far0->pfcp_id;
              tr->gtpu_ep_id = ff->ohc.src_gtpu_endpoint_id;
            }
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Do we still need this now that tunnel tx stats is kept? */
  vlib_node_increment_counter (
    vm, node->node_index, UPF_ENCAP_ERROR_ENCAPSULATED, pkts_encapsulated);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_gtp_encap4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_encap_inline (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_gtp_encap6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_encap_inline (vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (upf_gtp_encap4_node) = {
  .name = "upf-gtp-encap4",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_gtp_encap_error_strings),
  .error_strings = upf_gtp_encap_error_strings,
  .n_next_nodes = UPF_GTP_ENCAP_N_NEXT,
  .next_nodes = {
       [UPF_GTP_ENCAP_NEXT_DROP]= "error-drop",
       [UPF_GTP_ENCAP_NEXT_IP_LOOKUP]= "ip4-lookup",
  },
};

VLIB_REGISTER_NODE (upf_gtp_encap6_node) = {
  .name = "upf-gtp-encap6",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_gtp_encap_error_strings),
  .error_strings = upf_gtp_encap_error_strings,
  .n_next_nodes = UPF_GTP_ENCAP_N_NEXT,
  .next_nodes = {
       [UPF_GTP_ENCAP_NEXT_DROP]= "error-drop",
       [UPF_GTP_ENCAP_NEXT_IP_LOOKUP]= "ip6-lookup",
  },
};
