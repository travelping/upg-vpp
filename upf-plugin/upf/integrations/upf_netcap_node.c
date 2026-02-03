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
#include "upf/core/upf_buffer_opaque.h"

#define UPF_DEBUG_ENABLE 0

#define foreach_upf_netcap_error                                              \
  _ (CAPTURED, "packets captured")                                            \
  _ (INVALID_CONTEXT, "invalid netcap context")                               \
  _ (INVALID_SESSION, "no capture for session")                               \
  _ (INVALID_SOURCE, "invalid packet source")

static char *upf_netcap_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_netcap_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_NETCAP_ERROR_##sym,
  foreach_upf_netcap_error
#undef _
    UPF_NETCAP_N_ERROR,
} upf_flowless_error_t;

typedef enum
{
  UPF_NETCAP_NEXT_FLOW_PROCESS,
  UPF_NETCAP_NEXT_FLOWLESS,
  UPF_NETCAP_N_NEXT,
} upf_netcap_next_t;

typedef struct
{
  u32 session_index;
  upf_netcap_next_t next;
  u8 want_netcap : 1;
  u8 netcap_context_valid : 1;
} upf_flowless_trace_t;

static u8 *
_format_upf_netcap_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_flowless_trace_t *t = va_arg (*args, upf_flowless_trace_t *);

  s = format (
    s, "upf_session=%d next=%d want_netcap=%d netcap_context_valid=%d",
    t->session_index, t->next, t->want_netcap, t->netcap_context_valid);
  return s;
}

// Copy buffer chain to destination with limit
always_inline void
_read_buffer_content_n (vlib_main_t *vm, vlib_buffer_t *b, u8 *dst, u16 size)
{
  u16 pos = 0;
  u16 copy_left = size;
  while (true)
    {
      u16 buf_l = b->current_length;
      u16 copy_l = clib_min (copy_left, buf_l);
      clib_memcpy_fast (dst + pos, vlib_buffer_get_current (b), copy_l);

      pos += copy_l;
      copy_left -= copy_l;

      if (!copy_left)
        break;

      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
        break;

      b = vlib_get_buffer (vm, b->next_buffer);
    }
}

always_inline uword
_upf_netcap_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
                     vlib_frame_t *from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *um = &upf_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  u32 thread_index = vm->thread_index;

  netcap_v1_dump_context_t netcap_ctx;

  bool netcap_context_valid = false;

  ASSERT (um->netcap.enabled);
  if (um->netcap.enabled)
    {
      netcap_context_valid =
        um->netcap.methods.dump_context_init (&netcap_ctx, thread_index, true);
    }

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

          upf_flowless_error_t error = UPF_NETCAP_ERROR_CAPTURED;

          vlib_buffer_t *b = vlib_get_buffer (vm, bi);
          UPF_CHECK_INNER_NODE (b);

          u32 session_id = upf_buffer_opaque (b)->gtpu.session_id;

          upf_dp_session_t *dsx =
            upf_wk_get_dp_session (thread_index, session_id);

          upf_rules_t *rules = upf_wk_get_rules (thread_index, dsx->rules_id);

          if (PREDICT_FALSE (!rules->want_netcap))
            {
              error = UPF_NETCAP_ERROR_INVALID_SESSION;
              ASSERT (rules->want_netcap);
              goto _do_not_capture;
            }

          if (PREDICT_FALSE (!netcap_context_valid))
            {
              error = UPF_NETCAP_ERROR_INVALID_CONTEXT;
              goto _do_not_capture;
            }

          upf_lid_t stream_set_lid = ~0;
          upf_lid_t source_lid = upf_buffer_opaque (b)->gtpu.source_lid;
          switch (upf_buffer_opaque (b)->gtpu.packet_source)
            {
            case UPF_PACKET_SOURCE_GTPU:
              {
                upf_lidset_t pdr_lids =
                  upf_rules_get_ep_gtpu (rules, source_lid)->pdr_lids;

                // All teps for gtpu should share the same nwi_id and
                // interface. This is verified in
                // _upf_sxu_traffic_endpoint_check_gtpu_ep

                upf_lid_t pdr_lid = upf_lidset_get_first_set_idx (&pdr_lids);
                rules_pdr_t *pdr = upf_rules_get_pdr (rules, pdr_lid);
                rules_tep_t *tep =
                  upf_rules_get_tep (rules, pdr->traffic_ep_lid);
                stream_set_lid = tep->capture_set_lid;
              }
              break;
            case UPF_PACKET_SOURCE_IP:
              {
                rules_ep_ip_t *ep_ip =
                  is_ip4 ? upf_rules_get_ep_ip4 (rules, source_lid) :
                           upf_rules_get_ep_ip6 (rules, source_lid);
                rules_tep_t *tep =
                  upf_rules_get_tep (rules, ep_ip->traffic_ep_lid);
                stream_set_lid = tep->capture_set_lid;
              }
              break;
            case UPF_PACKET_SOURCE_NAT:
              {
                stream_set_lid = rules->nat_netcap_set_lid;
              }
              break;
            default:
              error = UPF_NETCAP_ERROR_INVALID_SOURCE;
              ASSERT (0 && "Can't determine target stream");
              goto _do_not_capture;
            }

          rules_netcap_set_t *set =
            upf_rules_get_netcap_set (rules, stream_set_lid);

          // include GTPU header if possible
          if (upf_buffer_opaque (b)->gtpu.packet_source ==
              UPF_PACKET_SOURCE_GTPU)
            vlib_buffer_advance (b,
                                 -upf_buffer_opaque (b)->gtpu.outer_hdr_len);

          rules_netcap_stream_t *stream;
          vec_foreach (stream, set->streams)
            {
              uword len = vlib_buffer_length_in_chain (vm, b);
              u16 cap_len = clib_min (len, stream->packet_max_bytes);

              void *copy_dst;
              if (PREDICT_TRUE (um->netcap.methods.dump_context_capture (
                    &netcap_ctx, um->netcap.class_session_ip,
                    stream->netcap_stream_id, unix_time_now_nsec (), &copy_dst,
                    cap_len, len, NULL, 0)))
                {
                  _read_buffer_content_n (vm, b, copy_dst, cap_len);
                }
            }

          if (upf_buffer_opaque (b)->gtpu.packet_source ==
              UPF_PACKET_SOURCE_GTPU)
            vlib_buffer_advance (b, upf_buffer_opaque (b)->gtpu.outer_hdr_len);

        _do_not_capture:
          // we do not drop packet here, so increment counter manually
          vlib_node_increment_counter (vm, node->node_index, error, 1);

          upf_netcap_next_t next;
          if (dsx->flow_mode == UPF_SESSION_FLOW_MODE_DISABLED)
            next = UPF_NETCAP_NEXT_FLOWLESS;
          else
            next = UPF_NETCAP_NEXT_FLOW_PROCESS;

          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_flowless_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));
              tr->session_index = session_id;
              tr->next = next;
              tr->want_netcap = rules->want_netcap;
              tr->netcap_context_valid = netcap_context_valid;
            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi, next);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (netcap_context_valid)
    um->netcap.methods.dump_context_flush (&netcap_ctx);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_netcap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_netcap_node_fn (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_netcap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_netcap_node_fn (vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (upf_ip4_netcap_node) = {
   .name = "upf-netcap4",
   .vector_size = sizeof (u32),
   .format_trace = _format_upf_netcap_trace,
   .type = VLIB_NODE_TYPE_INTERNAL,
   .n_errors = ARRAY_LEN(upf_netcap_error_strings),
   .error_strings = upf_netcap_error_strings,
   .n_next_nodes = UPF_NETCAP_N_NEXT,
   .next_nodes = {
     [UPF_NETCAP_NEXT_FLOW_PROCESS] = "upf-ip4-flow-process",
     [UPF_NETCAP_NEXT_FLOWLESS]     = "upf-ip4-flowless",
   },
 };

VLIB_REGISTER_NODE (upf_ip6_netcap_node) = {
   .name = "upf-netcap6",
   .vector_size = sizeof (u32),
   .format_trace = _format_upf_netcap_trace,
   .type = VLIB_NODE_TYPE_INTERNAL,
   .n_errors = ARRAY_LEN(upf_netcap_error_strings),
   .error_strings = upf_netcap_error_strings,
   .n_next_nodes = UPF_NETCAP_N_NEXT,
   .next_nodes = {
     [UPF_NETCAP_NEXT_FLOW_PROCESS] = "upf-ip6-flow-process",
     [UPF_NETCAP_NEXT_FLOWLESS]     = "upf-ip6-flowless",
   },
 };
