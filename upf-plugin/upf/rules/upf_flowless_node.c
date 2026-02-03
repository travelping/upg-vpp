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

#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>

#include "upf/upf.h"
#include "upf/rules/upf_classify_inlines.h"
#include "upf/utils/ip_helpers.h"
#include "upf/core/upf_buffer_opaque.h"

#define UPF_DEBUG_ENABLE 0

#define foreach_upf_flowless_error _ (CLASSIFY, "good packets classify")

static char *upf_flowless_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_flowless_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_FLOWLESS_ERROR_##sym,
  foreach_upf_flowless_error
#undef _
    UPF_FLOWLESS_N_ERROR,
} upf_flowless_error_t;

typedef enum
{
  UPF_FLOWLESS_NEXT_DROP,
  UPF_FLOWLESS_NEXT_FORWARD,
  UPF_FLOWLESS_N_NEXT,
} upf_flowless_next_t;

typedef struct
{
  upf_lidset_t check_pdrs;
  u32 session_index;
  upf_pdr_lid_t pdr_lid;
  pfcp_ie_pdr_id_t pdr_id;
  u8 is_uplink : 1;
  u8 is_match : 1;
  upf_flowless_next_t next;
  u8 packet_data[64];
} upf_flowless_trace_t;

static u8 *
_format_upf_flowless_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_flowless_trace_t *t = va_arg (*args, upf_flowless_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session=%d uplink=%d match=%d next=%d\n%U",
              t->session_index, t->is_uplink, t->is_match, t->next,
              format_white_space, indent);
  s = format (s, "pdr_id=%d pdr_lid=%d\n%U", t->pdr_id, t->pdr_lid,
              format_white_space, indent);
  s = format (s, "check_pdrs=%U", format_upf_lidset, &t->check_pdrs);

  return s;
}

always_inline uword
_upf_flowless_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
                  vlib_frame_t *from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

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

          upf_flowless_next_t next = UPF_FLOWLESS_NEXT_DROP;

          vlib_buffer_t *b = vlib_get_buffer (vm, bi);
          UPF_CHECK_INNER_NODE (b);

          ASSERT (b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID);
          ASSERT (b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
          void *l3hdr = b->data + vnet_buffer (b)->l3_hdr_offset;
          void *l4hdr = b->data + vnet_buffer (b)->l4_hdr_offset;

          u32 session_id = upf_buffer_opaque (b)->gtpu.session_id;
          bool is_uplink = upf_buffer_opaque (b)->gtpu.is_uplink;

          upf_dp_session_t *dsx =
            upf_wk_get_dp_session (vm->thread_index, session_id);

          upf_rules_t *rules =
            upf_wk_get_rules (vm->thread_index, dsx->rules_id);

          upf_debug ("got %U", format_ip_header, vlib_buffer_get_current (b),
                     b->current_length);

          upf_lidset_t check_pdr_lids;
          upf_lid_t source_lid = upf_buffer_opaque (b)->gtpu.source_lid;
          switch (upf_buffer_opaque (b)->gtpu.packet_source)
            {
            case UPF_PACKET_SOURCE_GTPU:
              {
                rules_ep_gtpu_t *ep_gtpu =
                  upf_rules_get_ep_gtpu (rules, source_lid);
                upf_lidset_and (&check_pdr_lids, &ep_gtpu->pdr_lids,
                                is_ip4 ? &rules->pdr_ip4_lids :
                                         &rules->pdr_ip6_lids);
              }
              break;
            case UPF_PACKET_SOURCE_IP:
              {
                rules_ep_ip_t *ep_ip =
                  is_ip4 ? upf_rules_get_ep_ip4 (rules, source_lid) :
                           upf_rules_get_ep_ip6 (rules, source_lid);
                check_pdr_lids = ep_ip->pdr_lids;
              };
              break;
            default:
              {
                ASSERT (0 && "unsupported tcp proxy or nat");
                check_pdr_lids = (upf_lidset_t){};
                next = UPF_FLOWLESS_NEXT_DROP;
                goto _trace;
              }
            }

          upf_debug ("using pdrs %U", format_upf_lidset, &check_pdr_lids);

          bool match;
          upf_pdr_lid_t result_pdr_lid = ~0;
          if (is_ip4)
            match = upf_classify_flowless4_inline (
              rules, l3hdr, l4hdr, check_pdr_lids, is_uplink, &result_pdr_lid);
          else
            match = upf_classify_flowless6_inline (
              rules, l3hdr, l4hdr, check_pdr_lids, is_uplink, &result_pdr_lid);

          upf_debug ("classified pdr_lid %d, match: %d", result_pdr_lid,
                     match);

          upf_buffer_opaque (b)->gtpu.flow_id = ~0;
          if (match)
            {
              next = UPF_FLOWLESS_NEXT_FORWARD;
              upf_buffer_opaque (b)->gtpu.pdr_lid = result_pdr_lid;
            }
          else
            {
              next = UPF_FLOWLESS_NEXT_DROP;
            }

        _trace:

          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_flowless_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));
              tr->check_pdrs = check_pdr_lids;
              tr->session_index = session_id;
              tr->pdr_lid = result_pdr_lid;
              tr->pdr_id =
                match ? upf_rules_get_pdr (rules, result_pdr_lid)->pfcp_id :
                        ~0;
              tr->is_uplink = is_uplink;
              tr->is_match = match;
              tr->next = next;
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

VLIB_NODE_FN (upf_ip4_flowless_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_flowless_fn (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_flowless_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_flowless_fn (vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (upf_ip4_flowless_node) = {
   .name = "upf-ip4-flowless",
   .vector_size = sizeof (u32),
   .format_trace = _format_upf_flowless_trace,
   .type = VLIB_NODE_TYPE_INTERNAL,
   .n_errors = ARRAY_LEN(upf_flowless_error_strings),
   .error_strings = upf_flowless_error_strings,
   .n_next_nodes = UPF_FLOWLESS_N_NEXT,
   .next_nodes = {
     [UPF_FLOWLESS_NEXT_DROP]    = "error-drop",
     [UPF_FLOWLESS_NEXT_FORWARD] = "upf-ip4-forward",
   },
 };

VLIB_REGISTER_NODE (upf_ip6_flowless_node) = {
   .name = "upf-ip6-flowless",
   .vector_size = sizeof (u32),
   .format_trace = _format_upf_flowless_trace,
   .type = VLIB_NODE_TYPE_INTERNAL,
   .n_errors = ARRAY_LEN(upf_flowless_error_strings),
   .error_strings = upf_flowless_error_strings,
   .n_next_nodes = UPF_FLOWLESS_N_NEXT,
   .next_nodes = {
     [UPF_FLOWLESS_NEXT_DROP]    = "error-drop",
     [UPF_FLOWLESS_NEXT_FORWARD] = "upf-ip6-forward",
   },
 };
