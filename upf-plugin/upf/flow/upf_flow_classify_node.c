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

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include "upf/upf.h"
#include "upf/core/upf_buffer_opaque.h"
#include "upf/rules/upf_classify_inlines.h"
#include "upf/utils/ip_helpers.h"

#define UPF_DEBUG_ENABLE 0

/* Statistics (not all errors) */
#define foreach_upf_flow_classify_error _ (FAIL, "no pdr classified")

static char *upf_flow_classify_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_flow_classify_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_FLOW_CLASSIFY_ERROR_##sym,
  foreach_upf_flow_classify_error
#undef _
    UPF_FLOW_CLASSIFY_N_ERROR,
} upf_flow_classify_error_t;

typedef enum
{
  UPF_FLOW_CLASSIFY_NEXT_DROP,
  UPF_FLOW_CLASSIFY_NEXT_FORWARD,
  UPF_FLOW_CLASSIFY_N_NEXT,
} upf_flow_classify_next_t;

typedef struct
{
  u64 up_seid;
  u32 session_index;
  u32 flow_id;
  pfcp_ie_pdr_id_t pdr_id;
  upf_flow_classify_next_t next;
  u8 is_uplink : 1;
  u8 was_classified : 1;
  upf_pdr_lid_t pdr_lid;
} upf_flow_classify_trace_t;

static u8 *
_format_upf_flow_classify_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_flow_classify_trace_t *t = va_arg (*args, upf_flow_classify_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session=%d seid=0x%016" PRIx64 " uplink=%d flow=%d\n%U",
              t->session_index, t->up_seid, t->is_uplink, t->flow_id,
              format_white_space, indent);
  s = format (s, "pdr_id=%d pdr_lid=%d was_classified=%d next=%d", t->pdr_id,
              t->pdr_lid, t->was_classified, t->next);

  return s;
}

always_inline uword
upf_classify_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
                 vlib_frame_t *from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  flowtable_main_t *fm = &flowtable_main;

  u32 thread_index = vm->thread_index;
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, thread_index);

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  upf_flow_classify_next_t next = 0;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          upf_flow_classify_error_t error;

          bi = from[0];
          to_next[0] = bi;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b = vlib_get_buffer (vm, bi);
          UPF_CHECK_INNER_NODE (b);

          flow_entry_t *flow = pool_elt_at_index (
            fwk->flows, upf_buffer_opaque (b)->gtpu.flow_id);
          bool is_uplink = upf_buffer_opaque (b)->gtpu.is_uplink;
          upf_dir_t direction = is_uplink ? UPF_DIR_UL : UPF_DIR_DL;

          rules_pdr_t *pdr = NULL;

          bool already_classified =
            is_uplink ? flow->is_classified_ul : flow->is_classified_dl;
          if (already_classified)
            {
              // done by previous packets of this flow
              upf_buffer_opaque (b)->gtpu.pdr_lid = flow->pdr_lids[direction];
              goto trace_no_error;
            }

          upf_debug (
            "flow: %p (%u): %U\n%U",
            fwk->flows + upf_buffer_opaque (b)->gtpu.flow_id,
            upf_buffer_opaque (b)->gtpu.flow_id, format_flow_primary_key,
            fwk->flows + upf_buffer_opaque (b)->gtpu.flow_id,
            format_flow_entry,
            fwk->flows + upf_buffer_opaque (b)->gtpu.flow_id, thread_index);

          u32 session_id = upf_buffer_opaque (b)->gtpu.session_id;

          upf_dp_session_t *dsx =
            upf_wk_get_dp_session (thread_index, session_id);
          upf_rules_t *rules = upf_wk_get_rules (thread_index, dsx->rules_id);

          upf_debug ("got %U", format_ip_header, vlib_buffer_get_current (b),
                     b->current_length);

          upf_pdr_lid_t pdr_lid = ~0;
          bool classified = upf_classify_flow (
            rules, flow, upf_buffer_opaque (b)->gtpu.packet_source,
            upf_buffer_opaque (b)->gtpu.source_lid, is_uplink, is_ip4,
            &pdr_lid);

          upf_buffer_opaque (b)->gtpu.pdr_lid = pdr_lid;

          upf_debug ("classify = %d tcp proxy = %d pdr_lid %d", classified,
                     flow->is_tcp_proxy, pdr_lid);

          if (!classified)
            {
              next = UPF_FLOW_CLASSIFY_NEXT_DROP;
              error = UPF_FLOW_CLASSIFY_ERROR_FAIL;
              goto trace;
            }

          next = UPF_FLOW_CLASSIFY_NEXT_FORWARD;

          pdr = upf_rules_get_pdr (rules, pdr_lid);

          upf_debug ("taken pdr %d [%d] proxy %u dpi %u redirect %u",
                     pdr->pfcp_id, pdr_lid, flow->is_tcp_proxy,
                     flow->is_tcp_dpi_needed, pdr->need_http_redirect);

          if (upf_buffer_opaque (b)->gtpu.is_proxied)
            ASSERT (flow->is_tcp_proxy);

          goto trace_no_error;

        trace:
          b->error = node->errors[error];

        trace_no_error:
          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_flow_classify_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));

              tr->up_seid = dsx->up_seid;
              tr->session_index = session_id;
              tr->flow_id = flow - fwk->flows;
              tr->pdr_id = pdr ? pdr->pfcp_id : -1;
              tr->next = next;
              tr->is_uplink = is_uplink;
              tr->was_classified = already_classified;
              tr->pdr_lid = pdr_lid;
            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi, next);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_classify_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_classify_fn (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_classify_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_classify_fn (vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (upf_ip4_classify_node) = {
  .name = "upf-ip4-flow-classify",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_flow_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_flow_classify_error_strings),
  .error_strings = upf_flow_classify_error_strings,
  .n_next_nodes = UPF_FLOW_CLASSIFY_N_NEXT,
  .next_nodes = {
    [UPF_FLOW_CLASSIFY_NEXT_DROP]    = "error-drop",
    [UPF_FLOW_CLASSIFY_NEXT_FORWARD] = "upf-ip4-forward",
  },
};

VLIB_REGISTER_NODE (upf_ip6_classify_node) = {
  .name = "upf-ip6-flow-classify",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_flow_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_flow_classify_error_strings),
  .error_strings = upf_flow_classify_error_strings,
  .n_next_nodes = UPF_FLOW_CLASSIFY_N_NEXT,
  .next_nodes = {
    [UPF_FLOW_CLASSIFY_NEXT_DROP]    = "error-drop",
    [UPF_FLOW_CLASSIFY_NEXT_FORWARD] = "upf-ip6-forward",
  },
};
