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
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include "upf/proxy/upf_proxy.h"
#include "upf/core/upf_buffer_opaque.h"
#include "upf/utils/ip_helpers.h"
#include "upf/flow/flowtable.h"

#define UPF_DEBUG_ENABLE 0

typedef enum
{
  UPF_TCP_FORWARD_NEXT_DROP,
  UPF_TCP_FORWARD_NEXT_FORWARD,
  UPF_TCP_FORWARD_N_NEXT,
} upf_tcp_forward_next_t;

/* Statistics (not all errors) */
#define foreach_upf_tcp_forward_error                                         \
  _ (GOOD, "good packets process")                                            \
  _ (INVALID_FLOW, "flow entry not found")

static char *upf_tcp_forward_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_tcp_forward_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_TCP_FORWARD_ERROR_##sym,
  foreach_upf_tcp_forward_error
#undef _
    UPF_TCP_FORWARD_N_ERROR,
} upf_tcp_forward_error_t;

typedef struct
{
  u32 session_index;
  u32 flow_id;
  u32 ps_id;
  u8 packet_data[64];
} upf_tcp_forward_trace_t;

static u8 *
format_upf_tcp_forward_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_tcp_forward_trace_t *t = va_arg (*args, upf_tcp_forward_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session=%d flow=%d ps=%d\n%U", t->session_index,
              t->flow_id, t->ps_id, format_white_space, indent);
  s = format (s, "%U", format_ip_header, t->packet_data,
              sizeof (t->packet_data));
  return s;
}

static_always_inline void
_net_add (u32 *data, u32 add)
{
  add += clib_net_to_host_u32 (*data);
  *data = clib_host_to_net_u32 (add);
}

static_always_inline void
_net_sub (u32 *data, u32 sub)
{
  sub = clib_net_to_host_u32 (*data) - sub;
  *data = clib_host_to_net_u32 (sub);
}

static_always_inline int
_upf_tcp_tstamp_mod (tcp_header_t *th, upf_dir_t direction,
                     upf_proxy_session_t *ps)
{
  const u8 *data;
  u8 opt_len, opts_len, kind;
  int j, blocks;

  opts_len = (tcp_doff (th) << 2) - sizeof (tcp_header_t);
  data = (const u8 *) (th + 1);

  for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
    {
      kind = data[0];

      /* Get options length */
      if (kind == TCP_OPTION_EOL)
        break;
      else if (kind == TCP_OPTION_NOOP)
        {
          opt_len = 1;
          continue;
        }
      else
        {
          /* broken options */
          if (opts_len < 2)
            return -1;
          opt_len = data[1];

          /* weird option length */
          if (opt_len < 2 || opt_len > opts_len)
            return -1;
        }

      /* Parse options */
      switch (kind)
        {
        case TCP_OPTION_TIMESTAMP:
          if (opt_len == TCP_OPTION_LEN_TIMESTAMP)
            {
              /* tsval */
              _net_sub ((u32 *) (data + 2),
                        ps->sides[UPF_DIR_OP_SAME ^ direction].tsval_offs);

              if (tcp_ack (th))
                /* tsecr */
                _net_add ((u32 *) (data + 6),
                          ps->sides[UPF_DIR_OP_FLIP ^ direction].tsval_offs);
            }
          break;

        case TCP_OPTION_SACK_BLOCK:
          /* If a SYN, break */
          if (tcp_syn (th))
            break;

          /* If too short or not correctly formatted, break */
          if (opt_len < 10 || ((opt_len - 2) % TCP_OPTION_LEN_SACK_BLOCK))
            break;

          blocks = (opt_len - 2) / TCP_OPTION_LEN_SACK_BLOCK;
          for (j = 0; j < blocks; j++)
            {
              // TODO: review this code, and maybe revert it
              _net_add ((u32 *) (data + 2 + 8 * j), /* left edge */
                        ps->sides[direction ^ UPF_DIR_OP_SAME].seq_offs);
              _net_add ((u32 *) (data + 6 + 8 * j), /* right edge */
                        ps->sides[direction ^ UPF_DIR_OP_SAME].seq_offs);
            }
          break;

        default:
          break;
        }
    }

  return 0;
}

static uword
_upf_tcp_forward (vlib_main_t *vm, vlib_node_runtime_t *node,
                  vlib_frame_t *from_frame, int is_ip4)
{
  flowtable_main_t *fm = &flowtable_main;
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, vm->thread_index);
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, vm->thread_index);

  u32 n_left_from, next_index, *from, *to_next;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          flow_entry_t *flow = NULL;
          ip4_header_t *ip4;
          ip6_header_t *ip6;
          tcp_header_t *th;
          u32 seq, ack;

          bi = from[0];
          to_next[0] = bi;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b = vlib_get_buffer (vm, bi);
          UPF_CHECK_INNER_NODE (b);

          upf_tcp_forward_error_t error = UPF_TCP_FORWARD_ERROR_GOOD;
          upf_tcp_forward_next_t next = UPF_TCP_FORWARD_NEXT_FORWARD;

          u32 flow_id = upf_buffer_opaque (b)->gtpu.flow_id;
          ASSERT (is_valid_id (flow_id));

          if (!is_valid_id (flow_id) ||
              pool_is_free_index (fwk->flows, flow_id))
            {
              next = UPF_TCP_FORWARD_NEXT_DROP;
              error = UPF_TCP_FORWARD_ERROR_INVALID_FLOW;
              goto _error_trace;
            }

          flow = pool_elt_at_index (fwk->flows, flow_id);
          upf_dir_t direction =
            upf_buffer_opaque (b)->gtpu.is_uplink ? UPF_DIR_UL : UPF_DIR_DL;

          upf_proxy_session_t *ps =
            pool_elt_at_index (pwk->sessions, flow->ps_index);
          ASSERT (ps->generation == flow->ps_generation);

          /* mostly borrowed from vnet/interface_output.c calc_checksums */
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

          seq = clib_net_to_host_u32 (th->seq_number);
          ack = clib_net_to_host_u32 (th->ack_number);

          seq += ps->sides[direction ^ UPF_DIR_OP_SAME].seq_offs;
          ack -= ps->sides[direction ^ UPF_DIR_OP_FLIP].seq_offs;

          th->seq_number = clib_host_to_net_u32 (seq);
          th->ack_number = clib_host_to_net_u32 (ack);

          _upf_tcp_tstamp_mod (th, direction, ps);

          /* calculate new header checksums */
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

          vlib_node_increment_counter (vm, node->node_index,
                                       UPF_TCP_FORWARD_ERROR_GOOD, 1);

          vnet_buffer_offload_flags_clear (b,
                                           (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
                                            VNET_BUFFER_OFFLOAD_F_UDP_CKSUM |
                                            VNET_BUFFER_OFFLOAD_F_IP_CKSUM));
          upf_buffer_opaque (b)->gtpu.is_proxied = 1;

          goto _trace;
        _error_trace:
          b->error = node->errors[error];
        _trace:
          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_tcp_forward_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));

              tr->session_index = flow ? flow->session_id : ~0;
              tr->flow_id = flow ? flow - fwk->flows : ~0;
              tr->ps_id = flow ? flow->ps_index : ~0;
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

VLIB_NODE_FN (upf_proxy_tcp4_bypass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_tcp_forward (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_proxy_tcp6_bypass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_tcp_forward (vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (upf_proxy_tcp4_bypass_node) = {
  .name = "upf-proxy-tcp4-bypass",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_tcp_forward_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_tcp_forward_error_strings),
  .error_strings = upf_tcp_forward_error_strings,
  .n_next_nodes = UPF_TCP_FORWARD_N_NEXT,
  .next_nodes = {
    [UPF_TCP_FORWARD_NEXT_DROP]            = "error-drop",
    [UPF_TCP_FORWARD_NEXT_FORWARD]         = "upf-ip4-forward",
  },
};

VLIB_REGISTER_NODE (upf_proxy_tcp6_bypass_node) = {
  .name = "upf-proxy-tcp6-bypass",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_tcp_forward_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_tcp_forward_error_strings),
  .error_strings = upf_tcp_forward_error_strings,
  .n_next_nodes = UPF_TCP_FORWARD_N_NEXT,
  .next_nodes = {
    [UPF_TCP_FORWARD_NEXT_DROP]            = "error-drop",
    [UPF_TCP_FORWARD_NEXT_FORWARD]         = "upf-ip6-forward",
  },
};
