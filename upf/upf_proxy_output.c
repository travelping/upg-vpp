/*
 * Copyright (c) 2018 Travelping GmbH
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

#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/upf_proxy.h>

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)                                                        \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

typedef enum
{
  UPF_PROXY_OUTPUT_NEXT_DROP,
  UPF_PROXY_OUTPUT_NEXT_CLASSIFY,
  UPF_PROXY_OUTPUT_NEXT_PROCESS,
  UPF_PROXY_OUTPUT_NEXT_IP_LOOKUP,
  UPF_PROXY_OUTPUT_N_NEXT,
} upf_proxy_output_next_t;

static upf_proxy_output_next_t ft_next_map_next[FT_NEXT_N_NEXT] = {
  [FT_NEXT_DROP] = UPF_PROXY_OUTPUT_NEXT_DROP,
  [FT_NEXT_CLASSIFY] = UPF_PROXY_OUTPUT_NEXT_CLASSIFY,
  [FT_NEXT_PROCESS] = UPF_PROXY_OUTPUT_NEXT_PROCESS,
  [FT_NEXT_PROXY] = UPF_PROXY_OUTPUT_NEXT_PROCESS,
};

/* Statistics (not all errors) */
#define foreach_upf_proxy_output_error                                        \
  _ (PROCESS, "good packets process")                                         \
  _ (INVALID_FLOW, "flow entry not found")                                    \
  _ (NO_SESSION, "session not found")

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
  u32 session_index;
  u64 up_seid;
  u32 flow_id;
  u32 pdr_idx;
  u8 packet_data[64 - 1 * sizeof (u32)];
} upf_proxy_output_trace_t;

static u8 *
format_upf_proxy_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_proxy_output_trace_t *t = va_arg (*args, upf_proxy_output_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s,
              "upf_session%d up-seid 0x%016" PRIx64 " Flow %u PDR Idx %u\n"
              "%U%U",
              t->session_index, t->up_seid, t->flow_id, t->pdr_idx,
              format_white_space, indent, format_ip4_header, t->packet_data,
              sizeof (t->packet_data));
  return s;
}

static uword
upf_proxy_output (vlib_main_t *vm, vlib_node_runtime_t *node,
                  vlib_frame_t *from_frame, const flow_direction_t direction,
                  int is_ip4, int no_opaque, int far_only)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *gtm = &upf_main;
  vnet_main_t *vnm = gtm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  flowtable_main_t *fm = &flowtable_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 next = 0;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      u32 error;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          flow_entry_t *flow = NULL;
          upf_session_t *sx = NULL;
          struct rules *active;
          u32 flow_id;
          ip4_header_t *ip4;
          ip6_header_t *ip6;
          tcp_header_t *th;

          bi = from[0];
          to_next[0] = bi;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b = vlib_get_buffer (vm, bi);

          error = 0;

          if (is_ip4)
            {
              ip4 = (ip4_header_t *) vlib_buffer_get_current (b);
              th = (tcp_header_t *) ip4_next_header (ip4);
            }
          else
            {
              ip6 = (ip6_header_t *) vlib_buffer_get_current (b);
              th = (tcp_header_t *) ip6_next_header (ip6);
            }

          flow_id = vnet_buffer (b)->tcp.next_node_opaque;
          if (!flow_id)
            {
              /* VPP host stack traffic not related to UPG */
              upf_debug ("Non-UPG TCP traffic, IP hdr: %U", format_ip4_header,
                         vlib_buffer_get_current (b), b->current_length);
              next = UPF_PROXY_OUTPUT_NEXT_IP_LOOKUP;
              goto trace;
            }

          flow_id--;

          if (pool_is_free_index (fm->flows, flow_id))
            {
              next = UPF_PROXY_OUTPUT_NEXT_DROP;
              error = UPF_PROXY_OUTPUT_ERROR_INVALID_FLOW;
              goto trace;
            }

          flow = pool_elt_at_index (fm->flows, flow_id);

          upf_debug ("flow: %p (0x%08x): %U\n", flow, flow_id, format_flow_key,
                     &flow->key);
          upf_debug ("flow: %U\n", format_flow, flow);

          upf_debug ("IP hdr: %U", format_ip4_header,
                     vlib_buffer_get_current (b), b->current_length);
          upf_debug ("Flow INITIATOR/RESPONDER Pdr Id: %u/%u, FT Next %u/%u",
                     flow_side (flow, FT_INITIATOR)->pdr_id,
                     flow_side (flow, FT_RESPONDER)->pdr_id,
                     flow_side (flow, FT_INITIATOR)->next,
                     flow_side (flow, FT_RESPONDER)->next);

          if (pool_is_free (gtm->sessions,
                            gtm->sessions + flow->session_index))
            {
              clib_warning (
                "The flow has sidx %d that refers to a dead session",
                flow->session_index);
              next = UPF_PROXY_OUTPUT_NEXT_DROP;
              error = UPF_PROXY_OUTPUT_ERROR_INVALID_FLOW;
              goto trace;
            }

          UPF_ENTER_SUBGRAPH (b, flow->session_index, is_ip4);
          upf_buffer_opaque (b)->gtpu.flow_id = flow_id;
          upf_buffer_opaque (b)->gtpu.pkt_key_direction =
            direction ^ flow->flow_key_direction;
          upf_buffer_opaque (b)->gtpu.is_proxied = 1;

          /* mostly borrowed from vnet/interface_output.c calc_checksums */
          if (is_ip4)
            {
              ip4->checksum = ip4_header_checksum (ip4);
              th->checksum = 0;
              th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
            }
          else
            {
              int bogus;
              th->checksum = 0;
              th->checksum =
                ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
            }

          vnet_buffer_offload_flags_clear (b,
                                           (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
                                            VNET_BUFFER_OFFLOAD_F_UDP_CKSUM |
                                            VNET_BUFFER_OFFLOAD_F_IP_CKSUM));

          next = ft_next_map_next[flow_side (flow, direction)->next];
          if (next == UPF_PROXY_OUTPUT_NEXT_PROCESS)
            {
              upf_pdr_t *pdr;

              sx = pool_elt_at_index (gtm->sessions, flow->session_index);
              /*
               * Edge case: session modified after this buffer left
               * upf-ip[46]-flow-process node but before it entered
               * this node.
               * FIXME: this shouldn't actually happen.
               */
              if (sx->generation != flow->generation)
                sx = NULL;

              ASSERT (flow_side (flow, direction)->pdr_id != ~0);
              active = sx ? pfcp_get_rules (sx, PFCP_ACTIVE) : NULL;
              pdr = active ? pfcp_get_pdr_by_id (
                               active, flow_side (flow, direction)->pdr_id) :
                             NULL;
              if (!pdr)
                {
                  next = UPF_PROXY_OUTPUT_NEXT_DROP;
                  error = UPF_PROXY_OUTPUT_ERROR_NO_SESSION;
                  goto trace;
                }

              upf_buffer_opaque (b)->gtpu.pdr_idx = pdr - active->pdr;
              /*
               * Avoid doing counting the packets for the second time
               * on the proxy output
               */
              if (far_only)
                upf_buffer_opaque (b)->gtpu.flags |= BUFFER_FAR_ONLY;
            }

        trace:
          b->error = error ? node->errors[error] : 0;

          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_session_t *sess = NULL;
              u32 sidx = 0;
              upf_proxy_output_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));

              /* Get next node index and adj index from tunnel next_dpo */
              sidx = upf_buffer_opaque (b)->gtpu.session_index;
              sess = pool_elt_at_index (gtm->sessions, sidx);
              tr->session_index = sidx;
              tr->up_seid = sess->up_seid;
              tr->flow_id = upf_buffer_opaque (b)->gtpu.flow_id;
              tr->pdr_idx = upf_buffer_opaque (b)->gtpu.pdr_idx;
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

VLIB_NODE_FN (upf_ip4_proxy_server_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_proxy_output (vm, node, from_frame, FT_RESPONDER, /* is_ip4 */ 1,
                           /* no_opaque */ 0, /* far_only */ 0);
}

VLIB_NODE_FN (upf_ip6_proxy_server_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_proxy_output (vm, node, from_frame, FT_RESPONDER, /* is_ip4 */ 0,
                           /* no_opaque */ 0, /* far_only */ 0);
}

VLIB_NODE_FN (upf_ip4_proxy_server_far_only_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_proxy_output (vm, node, from_frame, FT_INITIATOR, /* is_ip4 */ 1,
                           /* no_opaque */ 0, /* far_only */ 1);
}

VLIB_NODE_FN (upf_ip6_proxy_server_far_only_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_proxy_output (vm, node, from_frame, FT_INITIATOR, /* is_ip4 */ 0,
                           /* no_opaque */ 0, /* far_only */ 1);
}

/* clang-format off */
VLIB_REGISTER_NODE (upf_ip4_proxy_server_far_only_output_node) = {
  .name = "upf-ip4-proxy-server-far-only-output",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_proxy_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_output_error_strings),
  .error_strings = upf_proxy_output_error_strings,
  .n_next_nodes = UPF_PROXY_OUTPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_OUTPUT_NEXT_DROP]      = "error-drop",
    [UPF_PROXY_OUTPUT_NEXT_CLASSIFY]  = "upf-ip4-classify",
    [UPF_PROXY_OUTPUT_NEXT_PROCESS]   = "upf-ip4-forward",
    [UPF_PROXY_OUTPUT_NEXT_IP_LOOKUP] = "ip4-lookup",
  },
};
/* clang-format on */

/* clang-format off */
VLIB_REGISTER_NODE (upf_ip6_proxy_server_far_only_output_node) = {
  .name = "upf-ip6-proxy-server-far-only-output",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_proxy_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_output_error_strings),
  .error_strings = upf_proxy_output_error_strings,
  .n_next_nodes = UPF_PROXY_OUTPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_OUTPUT_NEXT_DROP]      = "error-drop",
    [UPF_PROXY_OUTPUT_NEXT_CLASSIFY]  = "upf-ip6-classify",
    [UPF_PROXY_OUTPUT_NEXT_PROCESS]   = "upf-ip6-forward",
    [UPF_PROXY_OUTPUT_NEXT_IP_LOOKUP] = "ip6-lookup",
  },
};
/* clang-format on */

/* clang-format off */
VLIB_REGISTER_NODE (upf_ip4_proxy_server_output_node) = {
  .name = "upf-ip4-proxy-server-output",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_proxy_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_output_error_strings),
  .error_strings = upf_proxy_output_error_strings,
  .n_next_nodes = UPF_PROXY_OUTPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_OUTPUT_NEXT_DROP]      = "error-drop",
    [UPF_PROXY_OUTPUT_NEXT_CLASSIFY]  = "upf-ip4-classify",
    [UPF_PROXY_OUTPUT_NEXT_PROCESS]   = "upf-ip4-forward",
    [UPF_PROXY_OUTPUT_NEXT_IP_LOOKUP] = "ip4-lookup",
  },
};
/* clang-format on */

/* clang-format off */
VLIB_REGISTER_NODE (upf_ip6_proxy_server_output_node) = {
  .name = "upf-ip6-proxy-server-output",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_proxy_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_output_error_strings),
  .error_strings = upf_proxy_output_error_strings,
  .n_next_nodes = UPF_PROXY_OUTPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_OUTPUT_NEXT_DROP]      = "error-drop",
    [UPF_PROXY_OUTPUT_NEXT_CLASSIFY]  = "upf-ip6-classify",
    [UPF_PROXY_OUTPUT_NEXT_PROCESS]   = "upf-ip6-forward",
    [UPF_PROXY_OUTPUT_NEXT_IP_LOOKUP] = "ip6-lookup",
  },
};
/* clang-format on */
