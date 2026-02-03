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
#include "upf/upf_stats.h"
#include "upf/proxy/upf_proxy.h"
#include "upf/core/upf_buffer_opaque.h"
#include "upf/utils/ip_helpers.h"

#define UPF_DEBUG_ENABLE 0

typedef enum
{
  UPF_PROXY_INPUT_NEXT_DROP,
  UPF_PROXY_INPUT_NEXT_TCP_INPUT,
  UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP,
  UPF_PROXY_INPUT_NEXT_TCP_BYPASS,
  UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT,
  UPF_PROXY_INPUT_NEXT_PROXY_RESET,
  UPF_PROXY_INPUT_N_NEXT,
} upf_proxy_input_next_t;

/* Statistics (not all errors) */
#define foreach_upf_proxy_input_error                                         \
  _ (NO_ERROR, "reserved") /* just to reserve 0 for conditional */            \
  _ (LENGTH, "inconsistent ip/tcp lengths")                                   \
  _ (NO_LISTENER, "no redirect server available")                             \
  _ (PROCESS, "good packets process")                                         \
  _ (OPTIONS, "Could not parse options")                                      \
  _ (CREATE_SESSION_FAIL, "Sessions couldn't be allocated")                   \
  _ (FIRST_NOT_SYN, "First packet is not syn")

static char *upf_proxy_input_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_proxy_input_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_PROXY_INPUT_ERROR_##sym,
  foreach_upf_proxy_input_error
#undef _
    UPF_PROXY_INPUT_N_ERROR,
} upf_proxy_input_error_t;

typedef struct
{
  u32 session_index;
  u32 flow_id;
  u32 ps_id;
  u32 rxs_conn_id;
  u32 txs_conn_id;
  u32 rxs_session_id;
  u32 txs_session_id;
  u16 ps_generation;
  upf_proxy_side_state_t rxs_state;
  upf_proxy_side_state_t txs_state;
  u8 is_uplink : 1;
  u8 is_spliced : 1;
} upf_proxy_input_trace_t;

static u8 *
_format_upf_proxy_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_proxy_input_trace_t *t = va_arg (*args, upf_proxy_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session=%d flow=%d ps=%d ps_generation=%d\n%U",
              t->session_index, t->flow_id, t->ps_id, t->ps_generation,
              format_white_space, indent);
  s = format (s, "rxs_conn=%d txs_conn=%d rxs_state=%U txs_state=%U\n%U",
              t->rxs_conn_id, t->txs_conn_id, format_upf_proxy_side_state,
              t->rxs_state, format_upf_proxy_side_state, t->txs_state,
              format_white_space, indent);
  s =
    format (s, "rxs_session=%d txs_session=%d is_uplink=%d is_spliced=%d",
            t->rxs_session_id, t->txs_session_id, t->is_uplink, t->is_spliced);

  return s;
}

static u8
_tcp_flow_is_valid (tcp_connection_t *tc, flow_entry_t *f, upf_dir_t dir)
{
  if (!tc)
    return 1;

  if (!ip46_address_is_equal (&f->ip[UPF_EL_UL_SRC ^ dir],
                              &tc->connection.lcl_ip))
    {
      upf_debug ("lcl addr mismatch: expected %U, got %U", format_ip46_address,
                 &f->ip[UPF_EL_UL_SRC ^ dir], IP46_TYPE_ANY,
                 format_ip46_address, &tc->connection.lcl_ip, IP46_TYPE_ANY);
      return 0;
    }

  if (!ip46_address_is_equal (&f->ip[UPF_EL_UL_DST ^ dir],
                              &tc->connection.rmt_ip))
    {
      upf_debug ("rmt addr mismatch: expected %U, got %U", format_ip46_address,
                 &f->ip[UPF_EL_UL_DST ^ dir], IP46_TYPE_ANY,
                 format_ip46_address, &tc->connection.rmt_ip, IP46_TYPE_ANY);
      return 0;
    }

  bool src_port_match = clib_host_to_net_u16 (f->port[UPF_EL_UL_SRC ^ dir]) ==
                        tc->connection.lcl_port;

  bool dst_port_match = clib_host_to_net_u16 (f->port[UPF_EL_UL_DST ^ dir]) ==
                        tc->connection.rmt_port;

  if (!src_port_match || !dst_port_match)
    {
      upf_debug ("port mismatch: src=%d dst=%d", src_port_match,
                 dst_port_match);
      return 0;
    }

  return 1;
}

static_always_inline bool
_splice_tcp_connection (u16 thread_index, flow_entry_t *flow,
                        upf_proxy_session_t *ps, upf_dir_t direction,
                        upf_proxy_side_t side)
{
  upf_proxy_side_tcp_t *ftc = &ps->sides[UPF_DIR_OP_SAME ^ direction];
  upf_proxy_side_tcp_t *rev = &ps->sides[UPF_DIR_OP_FLIP ^ direction];
  tcp_connection_t *tcpRx, *tcpTx;

  // We need to have connection in 2 directions
  ASSERT (is_valid_id (ftc->conn_index));
  ASSERT (is_valid_id (rev->conn_index));

  if (ps->is_dont_splice)
    return false;

  // lookup connections
  transport_connection_t *tc = transport_get_connection (
    TRANSPORT_PROTO_TCP, ftc->conn_index, thread_index);
  if (!tc)
    return false;

  session_t *s = session_get_if_valid (tc->s_index, tc->thread_index);
  if (!s)
    return false;

  tcpRx = tcp_get_connection_from_transport (transport_get_connection (
    TRANSPORT_PROTO_TCP, ftc->conn_index, thread_index));
  tcpTx = tcp_get_connection_from_transport (transport_get_connection (
    TRANSPORT_PROTO_TCP, rev->conn_index, thread_index));

  if (!tcpRx || !tcpTx)
    return false;

  ASSERT (_tcp_flow_is_valid (tcpRx, flow, direction ^ UPF_DIR_OP_FLIP));
  ASSERT (_tcp_flow_is_valid (tcpTx, flow, direction ^ UPF_DIR_OP_SAME));

  /* check TCP connection properties */
  if ((tcpRx->snd_mss > tcpTx->rcv_opts.mss) ||
      (tcpTx->snd_mss > tcpRx->rcv_opts.mss))
    {
      upf_debug ("=============> DON'T SPLICE: MSS %d > %d || %d > %d",
                 tcpRx->snd_mss, tcpTx->rcv_opts.mss, tcpTx->snd_mss,
                 tcpRx->rcv_opts.mss);
      ps->is_dont_splice = 1;
      upf_stats_get_wk_generic (thread_index)
        ->flows_tcp_not_stitched_mss_mismatch += 1;
      return false;
    }

  if (tcp_opts_tstamp (&tcpTx->rcv_opts) != tcp_opts_tstamp (&tcpRx->rcv_opts))
    {
      upf_debug ("=============> DON'T SPLICE: tstamp %d != %d",
                 !!tcp_opts_tstamp (&tcpTx->rcv_opts),
                 !!tcp_opts_tstamp (&tcpRx->rcv_opts));
      ps->is_dont_splice = 1;
      upf_stats_get_wk_generic (thread_index)
        ->flows_tcp_not_stitched_tcp_ops_timestamp += 1;
      return false;
    }

  if (tcp_opts_sack_permitted (&tcpTx->rcv_opts) !=
      tcp_opts_sack_permitted (&tcpRx->rcv_opts))
    {
      upf_debug ("=============> DON'T SPLICE: sack %d != %d",
                 !!tcp_opts_sack_permitted (&tcpTx->rcv_opts),
                 !!tcp_opts_sack_permitted (&tcpRx->rcv_opts));
      ps->is_dont_splice = 1;
      upf_stats_get_wk_generic (thread_index)
        ->flows_tcp_not_stitched_tcp_ops_sack_permit += 1;
      return false;
    }

  upf_debug ("tcp flight size tx: %d rx: %d", tcp_flight_size (tcpTx),
             tcp_flight_size (tcpRx));
  upf_debug ("tcp bytes out tx: %d rx: %d", tcp_bytes_out (tcpTx),
             tcp_bytes_out (tcpRx));
  upf_debug ("tcp tx una/nxt: %u/%u rx una/nxt: %u/%u", tcpTx->snd_una,
             tcpTx->snd_nxt, tcpRx->snd_una, tcpRx->snd_nxt);
  if (tcp_flight_size (tcpTx) != 0 || tcp_flight_size (tcpRx) != 0)
    return false;

  if (tcpTx->snd_una != tcpTx->snd_nxt)
    return false;
  if (tcpRx->snd_una != tcpRx->snd_nxt)
    return false;

  // TODO: review or revert
  ftc->seq_offs = tcpTx->snd_nxt - tcpRx->rcv_nxt;
  rev->seq_offs = tcpRx->snd_nxt - tcpTx->rcv_nxt;

  /* switch to direct spliceing */
  ps->is_spliced = 1;

  upf_debug ("spliced %d dirty %d", ps->is_spliced);

  upf_stats_get_wk_generic (thread_index)->flows_tcp_stitched_count += 1;

  return true;
}

static_always_inline int
_upf_vnet_load_tcp_hdr_offset (vlib_buffer_t *b)
{
  ip4_header_t *ip4 = vlib_buffer_get_current (b);
  tcp_header_t *tcp;

  if ((ip4->ip_version_and_header_length & 0xF0) == 0x40)
    {
      int ip_hdr_bytes = ip4_header_bytes (ip4);
      if (PREDICT_FALSE (b->current_length < ip_hdr_bytes + sizeof (*tcp)))
        return -1;

      tcp = ip4_next_header (ip4);
      vnet_buffer (b)->tcp.hdr_offset = (u8 *) tcp - (u8 *) ip4;
    }
  else if ((ip4->ip_version_and_header_length & 0xF0) == 0x60)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      if (PREDICT_FALSE (b->current_length < sizeof (*ip6) + sizeof (*tcp)))
        return -1;

      tcp = ip6_next_header (ip6);
      vnet_buffer (b)->tcp.hdr_offset = (u8 *) tcp - (u8 *) ip6;
    }
  else
    return -1;

  // TODO: replace code with this
  ASSERT (vnet_buffer (b)->tcp.hdr_offset ==
          (vnet_buffer (b)->l4_hdr_offset - vnet_buffer (b)->l3_hdr_offset));

  return 0;
}

static_always_inline void
_load_tstamp_offset (vlib_buffer_t *b, upf_dir_t direction, flow_entry_t *flow,
                     upf_proxy_session_t *ps, u32 thread_index)
{
  tcp_header_t *tcp;
  tcp_options_t opts;

  if (ps->sides[direction].tsval_offs != 0)
    return;

  if (_upf_vnet_load_tcp_hdr_offset (b))
    return;

  tcp = tcp_buffer_hdr (b);
  memset (&opts, 0, sizeof (opts));
  if (tcp_options_parse (tcp, &opts, 1))
    return;

  if (!tcp_opts_tstamp (&opts))
    return;

  ps->sides[direction].tsval_offs =
    opts.tsval - tcp_time_tstamp (thread_index);
}

static uword
upf_proxy_input (vlib_main_t *vm, vlib_node_runtime_t *node,
                 const char *node_name, vlib_frame_t *from_frame, int is_ip4)
{
  upf_proxy_main_t *upm = &upf_proxy_main;

  u32 thread_index = vm->thread_index;

  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, thread_index);

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
          upf_proxy_input_error_t error = UPF_PROXY_INPUT_ERROR_NO_ERROR;

          vlib_buffer_t *b = vlib_get_buffer (vm, bi);

          UPF_CHECK_INNER_NODE (b);

          ASSERT (is_valid_id (upf_buffer_opaque (b)->gtpu.flow_id));

          flow_entry_t *flow = flowtable_get_flow_by_id (
            thread_index, upf_buffer_opaque (b)->gtpu.flow_id);

          upf_proxy_session_t *ps = NULL;
          if (is_valid_id (flow->ps_index))
            {
              ps = pool_elt_at_index (pwk->sessions, flow->ps_index);
              if (PREDICT_FALSE (ps->generation != flow->ps_generation))
                {
                  upf_debug ("generation do not match %x != %x",
                             ps->generation, flow->ps_generation);
                  // TODO: use upf_debug
                  ASSERT (0 && "Stale flow entry");
                  ps = NULL;
                }
            }

          vnet_buffer (b)->ip.rx_sw_if_index =
            vnet_buffer (b)->sw_if_index[VLIB_RX];

          upf_proxy_input_next_t next = UPF_PROXY_INPUT_NEXT_DROP;

          bool is_uplink = upf_buffer_opaque (b)->gtpu.is_uplink;
          upf_dir_t direction = is_uplink ? UPF_DIR_UL : UPF_DIR_DL;
          upf_proxy_side_t side =
            is_uplink ? UPF_PROXY_SIDE_PO : UPF_PROXY_SIDE_AO;

          vnet_buffer (b)->ip.rx_sw_if_index =
            vnet_buffer (b)->sw_if_index[VLIB_RX];

          upf_proxy_side_tcp_t *rxs = &ps->sides[UPF_DIR_OP_SAME ^ side];
          upf_proxy_side_tcp_t *txs = &ps->sides[UPF_DIR_OP_FLIP ^ side];

          tcp_header_t *th =
            (tcp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);

          _upf_tcp_strip_syn_options (th);

          upf_debug ("is_ul:%d IP hdr: %U", is_uplink, format_ip_header,
                     vlib_buffer_get_current (b), b->current_length);

          if (!ps)
            {
              // if session doesn't exists yet
              if (is_uplink)
                {
                  if (tcp_syn (th))
                    {
                      upf_debug ("no session PROXY_ACCEPT");
                      next = UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT;
                    }
                  else
                    {
                      upf_debug ("no session and packet isn't syn");
                      error = UPF_PROXY_INPUT_ERROR_FIRST_NOT_SYN;
                      next = UPF_PROXY_INPUT_NEXT_DROP;
                    }
                }
              else
                {
                  upf_debug ("no active proxy session");
                  next = UPF_PROXY_INPUT_NEXT_PROXY_RESET;
                }
            }
          else if (ps->is_spliced)
            {
              upf_debug ("spliced tcp_forward");
              next = UPF_PROXY_INPUT_NEXT_TCP_BYPASS;
            }
          else if (rxs->state >= UPF_PROXY_S_S_RESET)
            {
              /* that session was already closed */
              upf_debug ("LATE TCP FRAGMENT #1");
              next = UPF_PROXY_INPUT_NEXT_PROXY_RESET;
            }
          else if (!is_valid_id (txs->conn_index))
            {
              // accumulate packets in buffer for DPI
              upf_debug ("no forward tcp connection");

              // Validate TCP connection before using nolookup
              tcp_connection_t *tc_rx =
                tcp_get_connection_from_transport (transport_get_connection (
                  TRANSPORT_PROTO_TCP, rxs->conn_index, thread_index));

              bool connection_valid =
                tc_rx != NULL &&
                _tcp_flow_is_valid (tc_rx, flow, direction ^ UPF_DIR_OP_FLIP);

              if (connection_valid)
                {
                  vnet_buffer (b)->tcp.connection_index = rxs->conn_index;
                  next = UPF_PROXY_INPUT_NEXT_TCP_INPUT;
                }
              else
                {
                  // Connection invalid - use lookup path
                  upf_debug (
                    "connection %d invalid for nolookup path, using lookup",
                    rxs->conn_index);
                  next = UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP;
                }
            }
          else if (is_valid_id (rxs->conn_index))
            {
              upf_debug ("known connection %d", rxs->conn_index);

              // Validate TCP connection before using nolookup.
              tcp_connection_t *tc_rx =
                tcp_get_connection_from_transport (transport_get_connection (
                  TRANSPORT_PROTO_TCP, rxs->conn_index, thread_index));

              bool connection_valid =
                tc_rx != NULL &&
                _tcp_flow_is_valid (tc_rx, flow, direction ^ UPF_DIR_OP_FLIP);

              if (!connection_valid)
                { // Connection is gone - use tcp lookup
                  upf_debug ("connection %d invalid or mismatched",
                             rxs->conn_index);
                  next = UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP;
                }
              else if (txs->state < UPF_PROXY_S_S_CLOSING &&
                       rxs->state < UPF_PROXY_S_S_CLOSING &&
                       _splice_tcp_connection (thread_index, flow, ps,
                                               direction, side))
                {
                  upf_debug ("SPLICED ps %d txsid %d rxsid %d !!!!",
                             ps->self_id, txs->conn_index, rxs->conn_index);
                  proxy_session_close_connections (pwk, ps, 0);
                  next = UPF_PROXY_INPUT_NEXT_TCP_BYPASS;
                }
              else
                {
                  vnet_buffer (b)->tcp.connection_index = rxs->conn_index;
                  next = UPF_PROXY_INPUT_NEXT_TCP_INPUT;
                }
            }
          else if (is_uplink)
            {
              // Uplink should always have passive session.
              // Something went wrong, so reset state.
              upf_debug ("passive session no tcp session");
              next = UPF_PROXY_INPUT_NEXT_PROXY_RESET;
            }
          else
            {
              // active open not yet established
              upf_debug ("ACTIVE INPUT_LOOKUP");
              _load_tstamp_offset (b, direction, flow, ps, thread_index);

              // Before session is established TCP uses half open session which
              // is separate from established one. We could pass this half open
              // to nolookup, but then we couldn't be sure at which moment we
              // should change it to establihsed one, and it could make issues
              // due to having multiple packets from same connection in vector.
              // So we should allow tcp lookup to do lookup on its own.
              next = UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP;
            }

          // TODO: traces
          // if (ps)
          //   {
          //     session_t *s = is_valid_id (rxs->session_index) ?
          //                      session_get (rxs->session_index,
          //                      thread_index) : NULL;
          //     tcp_connection_t *tc = s ? tcp_get_connection_from_transport (
          //                                  session_get_transport (s)) :
          //                                0;
          //     if (tc)
          //       {
          //         clib_warning ("ul %d psstate %d sid %d (%x) state %U tc %d
          //         "
          //                       "(%d) (%x) state %U next %d",
          //                       is_uplink, rxs->state, rxs->session_index,
          //                       s, format_session_state, s,
          //                       s->connection_index, rxs->conn_index, tc,
          //                       format_tcp_state, (u32) tc->state, next);
          //       }
          //     else if (s)
          //       {
          //         clib_warning (
          //           "ul %d psstate %d sid %d (%x) state %U next %d",
          //           is_uplink, rxs->state, rxs->session_index, s,
          //           format_session_state, s, s->connection_index, next);
          //       }
          //     else
          //       {
          //         clib_warning ("ul %d psstate %d no sid or session next
          //         %d",
          //                       is_uplink, rxs->state, next);
          //       }
          //   }
          // else
          //   {
          //     clib_warning ("ul %d no ps next %d", is_uplink, next);
          //   }

        trace:
          b->error = error ? node->errors[error] : 0;

          if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
            {
              upf_proxy_input_trace_t *tr =
                vlib_add_trace (vm, node, b, sizeof (*tr));

              tr->session_index = upf_buffer_opaque (b)->gtpu.session_id;
              tr->flow_id = upf_buffer_opaque (b)->gtpu.flow_id;
              tr->ps_id = ps ? (ps - pwk->sessions) : ~0;
              tr->rxs_conn_id = ps ? rxs->conn_index : ~0;
              tr->txs_conn_id = ps ? txs->conn_index : ~0;
              tr->rxs_session_id = ps ? rxs->session_index : ~0;
              tr->txs_session_id = ps ? txs->session_index : ~0;
              tr->ps_generation = flow->ps_generation;
              tr->rxs_state = ps ? rxs->state : 0;
              tr->txs_state = ps ? txs->state : 0;
              tr->is_uplink = is_uplink;
              tr->is_spliced = ps ? ps->is_spliced : 0;
            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi, next);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_proxy_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_proxy_input (vm, node, "upf-ip4-proxy-input", from_frame,
                          /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_proxy_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return upf_proxy_input (vm, node, "upf-ip6-proxy-input", from_frame,
                          /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (upf_ip4_proxy_input_node) = {
  .name = "upf-ip4-proxy-input",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_proxy_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_input_error_strings),
  .error_strings = upf_proxy_input_error_strings,
  .n_next_nodes = UPF_PROXY_INPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_INPUT_NEXT_DROP]             = "error-drop",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT]        = "tcp4-input-nolookup",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP] = "tcp4-input",
    [UPF_PROXY_INPUT_NEXT_TCP_BYPASS]       = "upf-proxy-tcp4-bypass",
    [UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT]     = "upf-ip4-proxy-accept",
    [UPF_PROXY_INPUT_NEXT_PROXY_RESET]      = "upf-ip4-proxy-reset",
  },
};

VLIB_REGISTER_NODE (upf_ip6_proxy_input_node) = {
  .name = "upf-ip6-proxy-input",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_proxy_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_proxy_input_error_strings),
  .error_strings = upf_proxy_input_error_strings,
  .n_next_nodes = UPF_PROXY_INPUT_N_NEXT,
  .next_nodes = {
    [UPF_PROXY_INPUT_NEXT_DROP]             = "error-drop",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT]        = "tcp6-input-nolookup",
    [UPF_PROXY_INPUT_NEXT_TCP_INPUT_LOOKUP] = "tcp6-input",
    [UPF_PROXY_INPUT_NEXT_TCP_BYPASS]       = "upf-proxy-tcp6-bypass",
    [UPF_PROXY_INPUT_NEXT_PROXY_ACCEPT]     = "upf-ip6-proxy-accept",
    [UPF_PROXY_INPUT_NEXT_PROXY_RESET]      = "upf-ip6-proxy-reset",
  },
};
