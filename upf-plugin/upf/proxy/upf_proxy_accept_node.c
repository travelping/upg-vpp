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
#include "upf/flow/flowtable.h"
#include "upf/utils/ip_helpers.h"

#define UPF_DEBUG_ENABLE 0

/* Statistics (not all errors) */
#define foreach_upf_proxy_error                                               \
  _ (OK, "good packets proxy")                                                \
  _ (OPTIONS, "could not parse options")                                      \
  _ (CREATE_SESSION_FAIL, "sessions couldn't be allocated")                   \
  _ (CONNECTION_EXISTS, "connection already exists")                          \
  _ (TCP_LENGTH, "tcp error length")                                          \
  _ (TCP_OTHER, "tcp error other")                                            \
  _ (HANDLED_PREVIOUSLY, "multiple syn in vector")

static char *upf_proxy_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_proxy_error
#undef _
};

typedef enum
{
#define _(sym, str) UPF_PROXY_ERROR_##sym,
  foreach_upf_proxy_error
#undef _
    UPF_PROXY_N_ERROR,
} upf_proxy_error_t;

typedef struct
{
  u32 session_index;
  u32 flow_id;
  u32 ps_index;
  u32 vpp_session_id;
  u16 ps_generation;
  upf_proxy_error_t error;
  u8 packet_data[64];
} upf_proxy_accept_trace_t;

static u8 *
_format_upf_proxy_accept_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_proxy_accept_trace_t *t = va_arg (*args, upf_proxy_accept_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session=%d flow=%d error=%s\n%U", t->session_index,
              t->flow_id, upf_proxy_error_strings[t->error],
              format_white_space, indent);
  s = format (s, "ps=%d ps_generation=%d vpp_session=%d\n%U", t->ps_index,
              t->ps_generation, t->vpp_session_id, format_white_space, indent);
  s = format (s, "%U", format_ip_header, t->packet_data,
              sizeof (t->packet_data));
  return s;
}

// Based on session_stream_connect_notify and session_stream_accept_notify from
// vnet/session/session.c.
static int
_proxy_session_stream_accept_notify (transport_connection_t *tc,
                                     upf_proxy_session_t *ps)
{
  upf_proxy_main_t *upm = &upf_proxy_main;

  application_t *app = application_get (upm->passive_server_app_index);
  if (!app)
    return -1;

  app_worker_t *app_wrk =
    application_get_worker (app, /* wrk_map_index */ tc->thread_index);

  session_t *s = session_alloc_for_connection (tc);
  s->session_state = SESSION_STATE_CREATED;
  s->app_wrk_index = app_wrk->wrk_index;

  s->opaque = upf_proxy_session_opaque (ps);

  upf_debug (
    "proxy session @ %p, app %p, wrk %p (idx %u), proxy session: 0x%08x", s,
    app, app_wrk, app_wrk->wrk_index, ps->self_id);

  int rv;
  if ((rv = app_worker_init_connected (app_wrk, s)))
    {
      session_free (s);
      return rv;
    }

  session_lookup_add_connection (tc, session_handle (s));

  s->session_state = SESSION_STATE_ACCEPTING;
  /* app_worker_accept_notify implementation always succeeds */
  if ((rv = app_worker_accept_notify (app_wrk, s)))
    {
      session_lookup_del_session (s);
      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
      session_free (s);
      return rv;
    }
  return 0;
}

static u8
tcp_lookup_is_valid (tcp_connection_t *tc, vlib_buffer_t *b, tcp_header_t *hdr)
{
  transport_connection_t *tmp = 0;
  u64 handle;

  if (!tc)
    return 1;

  /* Proxy case */
  if (tc->c_lcl_port == 0 && tc->state == TCP_STATE_LISTEN)
    return 1;

  u8 is_ip_valid = 0, val_l, val_r;

  if (tc->connection.is_ip4)
    {
      ip4_header_t *ip4_hdr = (ip4_header_t *) vlib_buffer_get_current (b);

      val_l = !ip4_address_compare (&ip4_hdr->dst_address,
                                    &tc->connection.lcl_ip.ip4);
      val_l = val_l || ip_is_zero (&tc->connection.lcl_ip, 1);
      val_r = !ip4_address_compare (&ip4_hdr->src_address,
                                    &tc->connection.rmt_ip.ip4);
      val_r = val_r || tc->state == TCP_STATE_LISTEN;
      is_ip_valid = val_l && val_r;
    }
  else
    {
      ip6_header_t *ip6_hdr = (ip6_header_t *) vlib_buffer_get_current (b);

      val_l = !ip6_address_compare (&ip6_hdr->dst_address,
                                    &tc->connection.lcl_ip.ip6);
      val_l = val_l || ip_is_zero (&tc->connection.lcl_ip, 0);
      val_r = !ip6_address_compare (&ip6_hdr->src_address,
                                    &tc->connection.rmt_ip.ip6);
      val_r = val_r || tc->state == TCP_STATE_LISTEN;
      is_ip_valid = val_l && val_r;
    }

  u8 is_valid =
    (tc->c_lcl_port == hdr->dst_port &&
     (tc->state == TCP_STATE_LISTEN || tc->c_rmt_port == hdr->src_port) &&
     is_ip_valid);

  if (!is_valid)
    {
      handle = session_lookup_half_open_handle (&tc->connection);
      tmp = session_lookup_half_open_connection (handle & 0xFFFFFFFF,
                                                 tc->c_proto, tc->c_is_ip4);

      if (tmp)
        {
          if (tmp->lcl_port == hdr->dst_port && tmp->rmt_port == hdr->src_port)
            {
              TCP_DBG ("half-open is valid!");
              is_valid = 1;
            }
        }
    }
  return is_valid;
}

/**
 * Lookup transport connection
 * is_reverse - in this context means that buffer source adress is local
 * address instead of destination
 */
// Based on tcp_lookup_connection from vnet/tcp/tcp_input.c
tcp_connection_t *
_upf_tcp_lookup_connection (u32 fib_index, vlib_buffer_t *b, u8 thread_index,
                            u8 is_ip4, u8 is_reverse)
{
  tcp_header_t *tcp;
  transport_connection_t *tconn;
  tcp_connection_t *tc;
  u8 is_filtered = 0;
  if (is_ip4)
    {
      ip4_header_t *ip4;
      ip4 = vlib_buffer_get_current (b);
      tcp = ip4_next_header (ip4);
      if (is_reverse)
        tconn = session_lookup_connection_wt4 (
          fib_index, &ip4->src_address, &ip4->dst_address, tcp->src_port,
          tcp->dst_port, TRANSPORT_PROTO_TCP, thread_index, &is_filtered);
      else
        tconn = session_lookup_connection_wt4 (
          fib_index, &ip4->dst_address, &ip4->src_address, tcp->dst_port,
          tcp->src_port, TRANSPORT_PROTO_TCP, thread_index, &is_filtered);

      tc = tcp_get_connection_from_transport (tconn);
      ASSERT (tcp_lookup_is_valid (tc, b, tcp));
    }
  else
    {
      ip6_header_t *ip6;
      ip6 = vlib_buffer_get_current (b);
      tcp = ip6_next_header (ip6);
      if (is_reverse)
        tconn = session_lookup_connection_wt6 (
          fib_index, &ip6->src_address, &ip6->dst_address, tcp->src_port,
          tcp->dst_port, TRANSPORT_PROTO_TCP, thread_index, &is_filtered);
      else
        tconn = session_lookup_connection_wt6 (
          fib_index, &ip6->dst_address, &ip6->src_address, tcp->dst_port,
          tcp->src_port, TRANSPORT_PROTO_TCP, thread_index, &is_filtered);
      tc = tcp_get_connection_from_transport (tconn);
      ASSERT (tcp_lookup_is_valid (tc, b, tcp));
    }
  return tc;
}

static_always_inline uword
_upf_proxy_accept_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
                          vlib_frame_t *from_frame, int is_ip4)
{
  upf_proxy_main_t *upm = &upf_proxy_main;
  u32 thread_index = vm->thread_index;
  u32 n_left_from, *from, *first_buffer;

  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, thread_index);

  from = first_buffer = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {
      upf_proxy_error_t error = UPF_PROXY_ERROR_OK;

      u32 bi = from[0];
      from += 1;
      n_left_from -= 1;

      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      UPF_CHECK_INNER_NODE (b);

      upf_proxy_session_t *ps = NULL;

      u32 flow_id = upf_buffer_opaque (b)->gtpu.flow_id;
      upf_debug ("flow_id: 0x%08x", flow_id);
      flow_entry_t *flow = flowtable_get_flow_by_id (thread_index, flow_id);

      if (is_valid_id (flow->ps_index))
        {
          // Probably proxy created by previous packet for this flow in current
          // vector. Ideally we could reinject it to proxy-input node, so it is
          // handled correctly, but it is strange to follow SYN with other
          // packets, so just drop it to avoid loops from input to accept and
          // back.
          upf_debug ("duplicate flow packet during ACCEPT ps_id %d",
                     flow->ps_index);
          error = UPF_PROXY_ERROR_HANDLED_PREVIOUSLY;
          goto done;
        }

      /* make sure connection_index is invalid */
      vnet_buffer (b)->tcp.connection_index = ~0;

      tcp_error_t tcp_error = TCP_ERROR_NONE;
      tcp_input_lookup_buffer (b, thread_index, &tcp_error, is_ip4,
                               1 /* is_nolookup */);
      upf_debug ("tcp_input_lookup error: %d", error);
      if (tcp_error != TCP_ERROR_NONE)
        {
          if (tcp_error == TCP_ERROR_LENGTH)
            error = UPF_PROXY_ERROR_TCP_LENGTH;
          else
            error = UPF_PROXY_ERROR_TCP_OTHER;
          goto done;
        }

      tcp_header_t *tcp = tcp_buffer_hdr (b);
      ASSERT (tcp_syn (tcp)); // should be handled by proxy-input node

      u32 fib_idx = vlib_buffer_get_ip_fib_index (b, is_ip4);
      upf_debug ("FIB: %u", fib_idx);

      /* Make sure connection wasn't just created */
      tcp_connection_t *old_conn =
        _upf_tcp_lookup_connection (fib_idx, b, thread_index, is_ip4, 0);
      if (PREDICT_FALSE (old_conn != NULL))
        {
          // Previous proxy connection was not yet cleaned up properly.
          upf_debug ("duplicate connection in upf-proxy-accept");
          error = UPF_PROXY_ERROR_CONNECTION_EXISTS;
          goto done;
        }

      /* Create child session and send SYN-ACK */
      tcp_connection_t *child = tcp_connection_alloc (thread_index);
      if (tcp_options_parse (tcp, &child->rcv_opts, 1))
        {
          error = UPF_PROXY_ERROR_OPTIONS;
          tcp_connection_free (child);
          goto done;
        }

      ps = upf_proxy_session_new (pwk, flow_id);
      flow->ps_index = ps - pwk->sessions;
      flow->ps_generation = ps->generation;
      flow->created_tcp_proxies += 1;

      tcp_init_w_buffer (child, b, is_ip4);

      child->state = TCP_STATE_SYN_RCVD;
      child->c_fib_index = fib_idx;
      child->mss = upm->config.mss;
      child->cc_algo = tcp_cc_algo_get (TCP_CC_CUBIC);
      tcp_connection_init_vars (child);
      child->rto = TCP_RTO_MIN;

      // Fix for CENNSO-2440
      // In upstream VPP such transport would be created from listener, and in
      // some cases VPP TCP stack will not send notifications to app if
      // connection wasn't established to avoid communcating temporary session
      // which was never established properly. In our case session is pre
      // created, and we need to communicate failure to rely on it for
      // deletion. To workaround this fpp-vpp adds flag which forces tcp stack
      // to force notification for session which failed to establish.
      child->flags |= TCP_CONN_FORCE_NOTIFY;

      child->next_node_index =
        is_ip4 ? upm->tcp4_server_output_next : upm->tcp6_server_output_next;

      // next_node_opaque is 0 when it's not initialized, use it for simple
      // check for proxy related traffic
      child->next_node_opaque = 1 + upf_proxy_session_opaque (ps);

      upf_debug ("Next Node: %u, Opaque (flow_id+1): 0x%08x",
                 child->next_node_index, child->next_node_opaque);

      if (_proxy_session_stream_accept_notify (&child->connection, ps))
        {
          tcp_connection_cleanup (child);
          error = UPF_PROXY_ERROR_CREATE_SESSION_FAIL;
          goto done;
        }

      session_t *s = session_get (child->c_s_index, thread_index);

      upf_debug ("NEW passive session: sidx %d psidx %d", s->session_index,
                 ps - pwk->sessions);

      vnet_buffer (b)->tcp.connection_index = child->c_c_index;

      ps->side_po.state = UPF_PROXY_S_S_CREATED;

      ps->flow_index = flow_id;
      ps->side_po.conn_index = child->c_c_index;

      child->tx_fifo_size = transport_tx_fifo_size (&child->connection);

      tcp_send_synack (child);

      TCP_EVT (TCP_EVT_SYN_RCVD, child, 1);

      if (CLIB_DEBUG)
        {
          ELOG_TYPE_DECLARE (e) = {
            .format = "upf-ps[%d]: ps create sx-%d flow-%d[%d] ps-%d s=%d",
            .format_args = "i2i4i4i2i4i4",
          };
          struct __clib_packed
          {
            u16 thread_id;
            u32 session_id;
            u32 flow_id;
            u16 flow_generation;
            u32 ps_id;
            u32 vpp_session_id;
          } * ed;

          ed = ELOG_DATA (&vlib_global_main.elog_main, e);
          ed->thread_id = thread_index;
          ed->session_id = upf_buffer_opaque (b)->gtpu.session_id;
          ed->flow_id = flow_id;
          ed->flow_generation = flow->generation;
          ed->ps_id = ps - pwk->sessions;
          ed->vpp_session_id = s->session_index;
        }

    done:
      vlib_node_increment_counter (vm, node->node_index, error, 1);

      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
        {
          upf_proxy_accept_trace_t *tr =
            vlib_add_trace (vm, node, b, sizeof (*tr));
          tr->session_index = upf_buffer_opaque (b)->gtpu.session_id;
          tr->flow_id = flow_id;
          tr->ps_index = ps ? (ps - pwk->sessions) : ~0;
          tr->vpp_session_id = s->session_index;
          tr->ps_generation = flow->ps_generation;
          tr->error = error;
          clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
                       sizeof (tr->packet_data));
        }
    }

  vlib_buffer_free (vm, first_buffer, from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_proxy_accept_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_proxy_accept_inline (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_proxy_accept_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return _upf_proxy_accept_inline (vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (upf_ip4_proxy_accept_node) = {
  .name = "upf-ip4-proxy-accept",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_proxy_accept_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (upf_proxy_error_strings),
  .error_strings = upf_proxy_error_strings,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (upf_ip6_proxy_accept_node) = {
  .name = "upf-ip6-proxy-accept",
  .vector_size = sizeof (u32),
  .format_trace = _format_upf_proxy_accept_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (upf_proxy_error_strings),
  .error_strings = upf_proxy_error_strings,
  .n_next_nodes = 0,
};
