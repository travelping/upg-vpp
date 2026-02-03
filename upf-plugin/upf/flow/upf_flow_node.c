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
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vnet/ip/ip4_packet.h>

#include "upf/upf.h"
#include "upf/flow/flowtable.h"
#include "upf/flow/flowtable_inlines.h"
#include "upf/utils/ip_helpers.h"

#define UPF_DEBUG_ENABLE 0

#define foreach_flowtable_error                                               \
  _ (HIT, "packets with an existing flow")                                    \
  _ (THRU, "packets gone through")                                            \
  _ (CREATED, "packets which created a new flow")                             \
  _ (TIMER_EXPIRE, "flows that have expired")                                 \
  _ (OVERFLOW, "dropped due to flowtable overflow")                           \
  _ (FLOWLESS, "no flow for flowless")

typedef enum
{
#define _(sym, str) FLOWTABLE_ERROR_##sym,
  foreach_flowtable_error
#undef _
    FLOWTABLE_N_ERROR
} flowtable_error_t;

typedef enum
{
  FT_NEXT_DROP,
  FT_NEXT_CLASSIFY,
  FT_NEXT_PROCESS,
  FT_NEXT_FLOWLESS,
  FT_NEXT_PROXY,
  FT_NEXT_N_NEXT
} flowtable_next_t;

typedef struct
{
  u32 session_id;
  u32 flow_id;
  union
  {
    flow_hashmap_key4_16_t key4;
    flow_hashmap_key6_40_t key6;
  } key;
  flowtable_next_t next;
  u8 is_uplink : 1;
  u8 is_ip4 : 1;
  u8 is_flow_created : 1;
  u8 packet_data[64];
} flow_trace_t;

static u8 *
_format_upf_flow_node_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  flow_trace_t *t = va_arg (*args, flow_trace_t *);
  u32 indent = format_get_indent (s);

  void *format_key_fn =
    t->is_ip4 ? format_flow_hashmap_key4_16 : format_flow_hashmap_key6_40;
  u32 key_size = t->is_ip4 ? sizeof (flow_hashmap_key4_16_t) :
                             sizeof (flow_hashmap_key6_40_t);

  s = format (s, "upf_session=%d uplink=%d is_ip4=%d flow=%d next=%d\n%U",
              t->session_id, t->is_uplink, t->is_ip4, t->flow_id, t->next,
              format_white_space, indent);
  s = format (s, "flow_key=%U\n%U", format_key_fn, &t->key, format_white_space,
              indent);
  s = format (s, "is_flow_created=%d flow_key_raw=%U\n%U", t->is_flow_created,
              format_hex_bytes, &t->key, key_size, format_white_space, indent);
  s = format (s, "%U", format_ip_header, t->packet_data,
              sizeof (t->packet_data));
  return s;
}

static uword
_upf_flow_process (vlib_main_t *vm, vlib_node_runtime_t *node,
                   vlib_frame_t *frame, u8 is_ip4)
{
  flowtable_main_t *fm = &flowtable_main;

  u32 thread_index = vm->thread_index;
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, thread_index);

  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  upf_time_t unix_now = upf_time_now (thread_index);

  u32 stats_overflow = 0, stats_flowless = 0;
  u32 stats_created = 0, stats_hit = 0;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          flowtable_next_t next0;
          vlib_buffer_t *b0;
          upf_dp_session_t *dsx0;
          bool flow_found;
          bool flow_created;
          u32 flow_id;
          flow_entry_t *flow = NULL;
          clib_bihash_kv_16_8_t kv4;
          clib_bihash_kv_40_8_t kv6;
          uword len0;

          bi0 = to_next[0] = from[0];
          b0 = vlib_get_buffer (vm, bi0);
          len0 = vlib_buffer_length_in_chain (vm, b0);
          UPF_CHECK_INNER_NODE (b0);

          u32 session_id = upf_buffer_opaque (b0)->gtpu.session_id;
          bool is_uplink = upf_buffer_opaque (b0)->gtpu.is_uplink;
          upf_dir_op_t downlink_swap =
            is_uplink ? UPF_DIR_OP_SAME : UPF_DIR_OP_FLIP;

          ASSERT (b0->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID);
          ASSERT (b0->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
          void *l3hdr = b0->data + vnet_buffer (b0)->l3_hdr_offset;
          void *l4hdr = b0->data + vnet_buffer (b0)->l4_hdr_offset;

          dsx0 = upf_wk_get_dp_session (thread_index, session_id);
          ASSERT (dsx0->is_created && !dsx0->is_removed);

          if (is_ip4)
            {
              flow_hashmap_key4_16_t *key4 =
                (flow_hashmap_key4_16_t *) &kv4.key;

              ip4_header_t *ip4 = (ip4_header_t *) l3hdr;

              *key4 = (flow_hashmap_key4_16_t){};
              key4->ip[UPF_EL_UL_SRC ^ downlink_swap] = ip4->src_address;
              key4->ip[UPF_EL_UL_DST ^ downlink_swap] = ip4->dst_address;
              if (ip4->protocol == IP_PROTOCOL_UDP ||
                  ip4->protocol == IP_PROTOCOL_TCP)
                {
                  udp_header_t *udp = l4hdr;
                  key4->port[UPF_EL_UL_SRC ^ downlink_swap] =
                    clib_net_to_host_u16 (udp->src_port);
                  key4->port[UPF_EL_UL_DST ^ downlink_swap] =
                    clib_net_to_host_u16 (udp->dst_port);
                }
              key4->session_id = session_id;
              key4->proto = ip4->protocol;

              flow_found =
                clib_bihash_search_inline_16_8 (&fwk->flows_ht4, &kv4) == 0;
              if (flow_found)
                flow_id = kv4.value;
            }
          else
            {
              flow_hashmap_key6_40_t *key6 =
                (flow_hashmap_key6_40_t *) &kv6.key;

              ip6_header_t *ip6 = (ip6_header_t *) l3hdr;

              *key6 = (flow_hashmap_key6_40_t){};
              key6->ip[UPF_EL_UL_SRC ^ downlink_swap] = ip6->src_address;
              key6->ip[UPF_EL_UL_DST ^ downlink_swap] = ip6->dst_address;
              if (ip6->protocol == IP_PROTOCOL_UDP ||
                  ip6->protocol == IP_PROTOCOL_TCP)
                {
                  udp_header_t *udp = l4hdr;
                  key6->port[UPF_EL_UL_SRC ^ downlink_swap] =
                    clib_net_to_host_u16 (udp->src_port);
                  key6->port[UPF_EL_UL_DST ^ downlink_swap] =
                    clib_net_to_host_u16 (udp->dst_port);
                }
              key6->session_id = session_id;
              key6->proto = ip6->protocol;

              flow_found =
                clib_bihash_search_inline_40_8 (&fwk->flows_ht6, &kv6) == 0;
              if (flow_found)
                flow_id = kv6.value;
            }

          if (PREDICT_FALSE (!flow_found))
            {
              if (PREDICT_FALSE (dsx0->flow_mode !=
                                 UPF_SESSION_FLOW_MODE_CREATE))
                {
                  stats_flowless += 1;
                  next0 = FT_NEXT_FLOWLESS;
                  goto stats1;
                }

              // create flow
              flow = flowtable_entry_new (fwk);

              if (flow == NULL)
                {
                  stats_overflow += 1;
                  next0 = FT_NEXT_DROP;
                  goto stats1;
                }

              flow_created = true;

              flow_id = flow - fwk->flows;
              upf_dir_t initiator = is_uplink ? UPF_DIR_UL : UPF_DIR_DL;
              if (is_ip4)
                flowtable_entry_init_by_ip4 (fwk, flow, unix_now, initiator,
                                             dsx0->rules_generation,
                                             session_id, &kv4);
              else
                flowtable_entry_init_by_ip6 (fwk, flow, unix_now, initiator,
                                             dsx0->rules_generation,
                                             session_id, &kv6);

              session_flows_list_insert_tail (
                fwk->flows, &dsx0->flows,
                pool_elt_at_index (fwk->flows, flow_id));
            }
          else
            {
              flow = pool_elt_at_index (fwk->flows, flow_id);
              flow_created = false;

              if (flow->generation != dsx0->rules_generation)
                flowtable_entry_reset (flow, dsx0->rules_generation);
            }

          upf_debug ("flow: %p [id %u]: %U: %s \n", (flow),
                     (flow) - (fwk)->flows, format_flow_primary_key, flow,
                     flow_created ? "CREATED_NEW" : "LOOKUP_SUCCESS");

          /* update activity timer */
          _flow_update (fwk, flow, l3hdr, l4hdr, is_ip4, len0);

          /* fill opaque buffer with flow data */
          bool classify =
            !_upf_opaque_set_flow_values (fwk, b0, flow, is_uplink);

          if (classify)
            next0 = FT_NEXT_CLASSIFY;
          else if (flow->is_tcp_proxy && !is_uplink)
            next0 = FT_NEXT_PROXY;
          else
            next0 = FT_NEXT_PROCESS;

          upf_debug (
            "flow next: %u, uplink: %d, ul pdr %d c %d, dl pdr %d c %d", next0,
            is_uplink, flow->pdr_lids[UPF_DIR_UL], flow->is_classified_ul,
            flow->pdr_lids[UPF_DIR_DL], flow->is_classified_dl);

          /* flowtable counters */
          if (flow_created)
            stats_created += 1;
          else
            stats_hit += 1;

        stats1:
          /* frame mgmt */
          from++;
          to_next++;
          n_left_from--;
          n_left_to_next--;

          if (b0->flags & VLIB_BUFFER_IS_TRACED)
            {
              flow_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));

              t->session_id = upf_buffer_opaque (b0)->gtpu.session_id;
              t->flow_id = flow_id;
              if (is_ip4)
                memcpy (&t->key.key4, &kv4.key, sizeof (t->key.key4));
              else
                memcpy (&t->key.key6, &kv6.key, sizeof (t->key.key6));
              t->next = next0;
              t->is_uplink = is_uplink;
              t->is_ip4 = is_ip4;
              t->is_flow_created = flow_created;
              clib_memcpy (t->packet_data, vlib_buffer_get_current (b0),
                           sizeof (t->packet_data));
            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, FLOWTABLE_ERROR_CREATED,
                               stats_created);
  vlib_node_increment_counter (vm, node->node_index, FLOWTABLE_ERROR_HIT,
                               stats_hit);
  vlib_node_increment_counter (vm, node->node_index, FLOWTABLE_ERROR_THRU,
                               stats_created + stats_hit);
  vlib_node_increment_counter (vm, node->node_index, FLOWTABLE_ERROR_OVERFLOW,
                               stats_overflow);
  vlib_node_increment_counter (vm, node->node_index, FLOWTABLE_ERROR_FLOWLESS,
                               stats_flowless);

  return frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_flow_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_flow_process (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_flow_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_flow_process (vm, node, from_frame, /* is_ip4 */ 0);
}

static char *flowtable_error_strings[] = {
#define _(sym, string) string,
  foreach_flowtable_error
#undef _
};

VLIB_REGISTER_NODE(upf_ip4_flow_node) = {
  .name = "upf-ip4-flow-process",
  .vector_size = sizeof(u32),
  .format_trace = _format_upf_flow_node_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = FLOWTABLE_N_ERROR,
  .error_strings = flowtable_error_strings,
  .n_next_nodes = FT_NEXT_N_NEXT,
  .next_nodes = {
    [FT_NEXT_DROP]     = "error-drop",
    [FT_NEXT_CLASSIFY] = "upf-ip4-flow-classify",
    [FT_NEXT_PROCESS]  = "upf-ip4-forward",
    [FT_NEXT_FLOWLESS] = "upf-ip4-flowless",
    [FT_NEXT_PROXY]    = "upf-ip4-proxy-input",
  },
};

VLIB_REGISTER_NODE(upf_ip6_flow_node) = {
  .name = "upf-ip6-flow-process",
  .vector_size = sizeof(u32),
  .format_trace = _format_upf_flow_node_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = FLOWTABLE_N_ERROR,
  .error_strings = flowtable_error_strings,
  .n_next_nodes = FT_NEXT_N_NEXT,
  .next_nodes = {
    [FT_NEXT_DROP]     = "error-drop",
    [FT_NEXT_CLASSIFY] = "upf-ip6-flow-classify",
    [FT_NEXT_PROCESS]  = "upf-ip6-forward",
    [FT_NEXT_FLOWLESS] = "upf-ip6-flowless",
    [FT_NEXT_PROXY]    = "upf-ip6-proxy-input",
  },
};
