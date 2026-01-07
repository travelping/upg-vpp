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

#include <assert.h>
#include <vnet/vnet.h>
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

#include "upf/upf.h"
#include "upf/upf_stats.h"
#include "upf/proxy/upf_proxy.h"
#include "upf/rules/upf_classify_inlines.h"
#include "upf/adf/adf.h"

#define UPF_DEBUG_ENABLE 0

#define TCP_DEFAULT_MSS 1400 // safe value against possible encapsulations

typedef enum
{
  EVENT_WAKEUP = 1,
} http_process_event_t;

upf_proxy_main_t upf_proxy_main;

static session_t *
_session_from_proxy_session_get_if_valid (upf_proxy_worker_t *pwk,
                                          upf_proxy_session_t *ps,
                                          bool is_active_open)
{
  upf_proxy_main_t *upm = &upf_proxy_main;
  u32 thread_index = pwk - upm->workers;

  if (!ps)
    return 0;

  u64 si =
    is_active_open ? ps->side_ao.session_index : ps->side_po.session_index;
  if (!is_valid_id (si))
    return 0;

  return session_get_if_valid (si, thread_index);
}

static const char *_upf_proxy_side_state_str[UPF_PROXY_N_S_S] = {
#define _(name) #name,
  foreach_upf_proxy_side_state
#undef _
};

u8 *
format_upf_proxy_side_state (u8 *s, va_list *args)
{
  upf_proxy_side_state_t state = va_arg (*args, int);

  return format (s, "%s", _upf_proxy_side_state_str[state]);
}

u8 *
format_upf_proxy_session (u8 *s, va_list *args)
{
  u32 thread_id = va_arg (*args, u32);
  upf_proxy_session_t *ps = va_arg (*args, upf_proxy_session_t *);

  upf_proxy_side_tcp_t *po = &ps->side_po, *ao = &ps->side_ao;

  s = format (s, "[t%d] id %d sides (%d:%s=>%d:%s) flow %d", thread_id,
              ps->self_id, po->session_index,
              _upf_proxy_side_state_str[po->state], ao->session_index,
              _upf_proxy_side_state_str[ao->state], ps->flow_index);

  if (ps->is_uri_extracted)
    s = format (s, " uri_extracted");
  if (ps->is_dont_splice)
    s = format (s, " dont_splice");
  if (ps->is_spliced)
    s = format (s, " spliced");
  if (ps->is_redirected)
    s = format (s, " redirected");

  if (is_valid_id (po->session_index))
    {
      session_t *sp = session_get_if_valid (po->session_index, thread_id);
      if (sp)
        s = format (s, " po{conn_id %d state %U}", sp->connection_index,
                    format_session_state, sp);
    }

  if (is_valid_id (ao->session_index))
    {
      session_t *ap = session_get_if_valid (ao->session_index, thread_id);
      if (ap)
        s = format (s, " ao{conn_id %d state %U}", ap->connection_index,
                    format_session_state, ap);
    }

  // if (p)
  //   s = format (s, "Clnt: %U\n", format_session, p, 0);
  // if (ao)
  //   s = format (s, "Srv:  %U\n", format_session, ao, 0);

  return s;
}

upf_proxy_session_t *
upf_proxy_session_new (upf_proxy_worker_t *pwk, u32 flow_id)
{
  upf_proxy_session_t *ps;

  pool_get (pwk->sessions, ps);
  upf_proxy_main_t *upm = &upf_proxy_main;

  u8 old_generation = ps->generation;

  *ps = (upf_proxy_session_t){
    .self_id = ps - pwk->sessions,
    .generation = old_generation,
    .flow_index = flow_id,
    .sides = {
      [UPF_DIR_UL] = {
        .session_index = ~0,
        .conn_index = ~0,
      },
      [UPF_DIR_DL]= {
        .session_index = ~0,
        .conn_index = ~0,
      },
    },
  };

  upf_debug ("created session %d generation %d thread %d", ps - pwk->sessions,
             ps->generation, ps->self_id);

  upf_stats_get_wk_generic (pwk - upm->workers)->flows_tcp_proxied_count += 1;

  return ps;
}

static void
_upf_proxy_session_free (upf_proxy_worker_t *pwk, upf_proxy_session_t *ps)
{
  upf_proxy_main_t *upm = &upf_proxy_main;

  if (CLIB_DEBUG)
    {
      ELOG_TYPE_DECLARE (e) = {
        .format = "upf-ps[%d]: ps deleting flow-%d ps-%d[%d]",
        .format_args = "i2i4i4i2",
      };
      struct __clib_packed
      {
        u16 thread_id;
        u32 flow_id;
        u32 ps_id;
        u16 ps_generation;
      } * ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, e);
      ed->thread_id = pwk - upm->workers;
      ed->flow_id = ps->flow_index;
      ed->ps_id = ps->self_id;
      ed->ps_generation = ps->generation;
    }

  if (is_valid_id (ps->flow_index))
    {
      flow_entry_t *flow =
        flowtable_get_flow_by_id (pwk - upm->workers, ps->flow_index);

      // Reset flow state related to proxy, since flow may require new proxy
      // state on next connection and it may be different. Or rules updated
      // so proxy is not needed anymore
      flow->is_tcp_proxy = 0;
      flow->is_tcp_dpi_needed = 0;
      flow->is_tcp_dpi_done = 0;
      flow->is_classified_dl = 0;
      flow->is_classified_ul = 0;
      flow->ps_index = ~0;
      vec_free (flow->app_uri);
    }
  vec_free (ps->rx_buf);
  ps->generation += 1;
  pool_put (pwk->sessions, ps);

  upf_stats_get_wk_generic (pwk - upm->workers)->flows_tcp_proxied_count -= 1;
}

static bool
_upf_proxy_session_try_put (upf_proxy_worker_t *pwk, upf_proxy_session_t *ps)
{
  ASSERT (ps);

  bool keep_ao = is_valid_id (ps->side_ao.conn_index) &&
                 ps->side_ao.state < UPF_PROXY_S_S_DESTROYED;

  bool keep_po = is_valid_id (ps->side_po.conn_index) &&
                 ps->side_po.state < UPF_PROXY_S_S_DESTROYED;

  bool keep_splice = ps->is_spliced && is_valid_id (ps->flow_index);

  if (keep_ao || keep_po || keep_splice)
    {
      upf_debug ("not removing ao=%d po=%d splice=%d", keep_ao, keep_po,
                 keep_splice);
      return false;
    }

  upf_debug ("FREEING session");
  _upf_proxy_session_free (pwk, ps);
  return true;
}

static upf_proxy_session_t *
_get_ps_from_opaque (upf_proxy_worker_t *pwk, u32 raw_opaque)
{
  upf_proxy_session_opaque_t opaque = { .as_u32 = raw_opaque };

  // Guards needed in case if vpp state remained for some reason.
  // Like when half open connection created during ao vpp_connect which we do
  // not cleanup.

  if (pool_is_free_index (pwk->sessions, opaque.id))
    {
      upf_debug ("couldn't get ps since opaque id %d already freed",
                 opaque.id);
      return NULL;
    }

  upf_proxy_session_t *ps = pool_elt_at_index (pwk->sessions, opaque.id);
  if (ps->generation != opaque.generation)
    {
      upf_debug ("couldn't get ps since opaque id %d incorrect generation "
                 "%d!=%d, %x!=%x",
                 opaque.id, opaque.generation, ps->generation, raw_opaque,
                 upf_proxy_session_opaque (ps));
      return NULL;
    }

  return ps;
}

static upf_proxy_session_t *
_get_ps_from_session (upf_proxy_worker_t *pwk, session_t *s)
{
  return _get_ps_from_opaque (pwk, s->opaque);
}

// acknowledge removal of vnet sesssions
void
proxy_session_on_cleanup_callback (session_t *s, bool is_active_open)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (s->thread_index);

  upf_proxy_main_t *upm = &upf_proxy_main;
  flowtable_main_t *fm = &flowtable_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, s->thread_index);
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, s->thread_index);

  upf_proxy_session_t *ps = _get_ps_from_session (pwk, s);
  if (!ps)
    return;

  u32 psid = ps - pwk->sessions;
  upf_debug ("sidx %d psidx %d", s->session_index, ps - pwk->sessions);

  // this callback can be delayed, so make sure to validate id:generation
  if (is_valid_id (ps->flow_index))
    {
      flow_entry_t *flow = pool_elt_at_index (fwk->flows, ps->flow_index);
      if (flow->ps_index != psid || flow->ps_generation != ps->generation)
        {
          // TODO: use upf_debug
          clib_warning ("ps flow mismatch id %x!=%x || gen %x!=%x",
                        ps->flow_index, psid, ps->generation,
                        flow->ps_generation);
          ASSERT (0);
          return;
        }
    }

  upf_proxy_side_tcp_t *side = is_active_open ? &ps->side_ao : &ps->side_po;

  ASSERT (side->state > UPF_PROXY_S_S_CREATED &&
          side->state < UPF_PROXY_S_S_DESTROYED);

  /*
   * Make sure the corresponding side is marked as disconnected.
   * We mark the specified side as disconnected here to prevent any
   * attempts of data transfer through the proxy at that
   * point. Otherwise, a late session event can cause a crash while
   * trying to use SVM FIFO.
   */
  side->state = UPF_PROXY_S_S_DESTROYED;
  side->session_index = ~0;
  side->conn_index = ~0;

  _upf_proxy_session_try_put (pwk, ps);
}

static void
_proxy_session_close_connection (upf_proxy_worker_t *pwk,
                                 upf_proxy_session_t *ps, bool is_ao,
                                 bool graceful)
{
  upf_proxy_side_tcp_t *side = is_ao ? &ps->side_ao : &ps->side_po;

  if (side->state <= UPF_PROXY_S_S_CREATED)
    {
      upf_debug ("no need to close ao=%d, not created", is_ao);
      return;
    }

  if (side->state >= UPF_PROXY_S_S_RESET)
    {
      upf_debug ("already closed ao=%d", is_ao);
      return;
    }

  session_t *s = _session_from_proxy_session_get_if_valid (pwk, ps, is_ao);
  ASSERT (s);

  if (graceful)
    {
      if (side->state >= UPF_PROXY_S_S_CLOSING)
        {
          upf_debug ("already doing graceful closing");
          return;
        }

      if (CLIB_DEBUG)
        {
          ELOG_TYPE_DECLARE (e) = {
            .format =
              "upf-ps[%d]: ps graceful close flow-%d ps-%d[%d] s=%d ao=%d",
            .format_args = "i2i4i4i2i4i1",
          };
          struct __clib_packed
          {
            u16 thread_id;
            u32 flow_id;
            u32 ps_id;
            u16 ps_generation;
            u32 vpp_session_id;
            u8 is_ao;
          } * ed;

          ed = ELOG_DATA (&vlib_global_main.elog_main, e);
          ed->thread_id = pwk - upf_proxy_main.workers;
          ed->flow_id = ps->flow_index;
          ed->ps_id = ps->self_id;
          ed->ps_generation = ps->generation;
          ed->vpp_session_id = s->session_index;
          ed->is_ao = is_ao;
        }

      upf_debug ("graceful closing of sid %d psid %d: %U", s->session_index,
                 ps->self_id, format_session, s, 1);
      session_close (s);

      side->state = UPF_PROXY_S_S_CLOSING;
    }
  else
    {
      if (CLIB_DEBUG)
        {
          ELOG_TYPE_DECLARE (e) = {
            .format =
              "upf-ps[%d]: ps reset disconnect flow-%d ps-%d[%d] s=%d ao=%d",
            .format_args = "i2i4i4i2i4i1",
          };
          struct __clib_packed
          {
            u16 thread_id;
            u32 flow_id;
            u32 ps_id;
            u16 ps_generation;
            u32 vpp_session_id;
            u8 is_ao;
          } * ed;

          ed = ELOG_DATA (&vlib_global_main.elog_main, e);
          ed->thread_id = pwk - upf_proxy_main.workers;
          ed->flow_id = ps->flow_index;
          ed->ps_id = ps->self_id;
          ed->ps_generation = ps->generation;
          ed->vpp_session_id = s->session_index;
          ed->is_ao = is_ao;
        }

      // It is non trivial to destroy vpp tcp session ourselfs, especially when
      // we could already add packets to tcp nolookup input. Easier to call
      // reset and block unwanted packets if we do not need them.
      // session_reset will eventually call tcp_session_reset which will
      // schedule cleanup in 0.1s (default tcp cleanup-time)

      upf_debug ("reset disconnect of sid %d psid %d: %U", s->session_index,
                 ps->self_id, format_session, s, 1);
      session_reset (s);

      side->state = UPF_PROXY_S_S_RESET;
    }
}

void
proxy_session_close_connections (upf_proxy_worker_t *pwk,
                                 upf_proxy_session_t *ps, bool graceful)
{
  _proxy_session_close_connection (pwk, ps, 0, graceful);
  _proxy_session_close_connection (pwk, ps, 1, graceful);
}

// Handles outgoing data on the server and client side.
static_always_inline int
_tx_callback_inline (session_t *s, bool is_active_open)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (s->thread_index);
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, s->thread_index);

  u32 min_free = clib_min (svm_fifo_size (s->tx_fifo) >> 3, 128 << 10);
  if (svm_fifo_max_enqueue (s->tx_fifo) < min_free)
    {
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  upf_proxy_session_t *ps = _get_ps_from_session (pwk, s);
  if (!ps || ps->side_ao.state >= UPF_PROXY_S_S_CLOSING ||
      ps->side_po.state >= UPF_PROXY_S_S_CLOSING)
    return 0;

  session_t *tx =
    _session_from_proxy_session_get_if_valid (pwk, ps, !is_active_open);
  if (!tx)
    return 0;

  ASSERT (tx != s);

  /* Force ack on other side to update rcv wnd */
  transport_connection_t *tc = session_get_transport (tx);
  tcp_send_ack ((tcp_connection_t *) tc);

  return 0;
}

static void
_upf_proxy_start_ao_connect (upf_proxy_worker_t *pwk, upf_proxy_session_t *ps)
{
  upf_main_t *um = &upf_main;
  upf_proxy_main_t *upm = &upf_proxy_main;

  u16 thread_id = pwk - upm->workers;

  upf_debug ("start ao connect");
  ASSERT (ps->side_ao.state == UPF_PROXY_S_S_INVALID);

  ASSERT (is_valid_id (ps->flow_index));
  flow_entry_t *flow = flowtable_get_flow_by_id (thread_id, ps->flow_index);

  upf_dp_session_t *dsx = upf_wk_get_dp_session (thread_id, flow->session_id);
  ASSERT (flow->generation == dsx->rules_generation);

  bool is_ip4 = flow->is_ip4;
  ASSERT (is_valid_id (flow->pdr_lids[UPF_DIR_UL]));

  upf_rules_t *rules = upf_wk_get_rules (thread_id, dsx->rules_id);
  rules_pdr_t *pdr = upf_rules_get_pdr (rules, flow->pdr_lids[UPF_DIR_UL]);
  rules_far_t *far = upf_rules_get_far (rules, pdr->far_lid);

  vnet_connect_args_t _a = {}, *a = &_a;

  a->api_context = upf_proxy_session_opaque (ps);
  a->app_index = upm->active_open_app_index;
  a->sep_ext = (session_endpoint_cfg_t) SESSION_ENDPOINT_CFG_NULL;
  a->wrk_map_index = thread_id;

  u32 fproto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  upf_nwi_t *nwi = pool_elt_at_index (um->nwis, far->forward.nwi_id);
  upf_interface_t *nwif = pool_elt_at_index (
    um->nwi_interfaces, nwi->interfaces_ids[far->forward.dst_intf]);

  a->sep_ext.sw_if_index = 0;
  a->sep_ext.fib_index = nwif->rx_fib_index[fproto];
  a->sep_ext.transport_proto = TRANSPORT_PROTO_TCP;
  a->sep_ext.mss = upm->config.mss;
  a->sep_ext.is_ip4 = is_ip4;
  a->sep_ext.ip = flow->ip[UPF_EL_UL_DST];
  a->sep_ext.port = clib_host_to_net_u16 (flow->port[UPF_EL_UL_DST]);
  a->sep_ext.next_node_index = is_ip4 ? upm->tcp4_server_output_next_active :
                                        upm->tcp6_server_output_next_active;
  a->sep_ext.next_node_opaque = 1 + upf_proxy_session_opaque (ps);
  a->sep_ext.peer.fib_index = a->sep_ext.fib_index;
  a->sep_ext.peer.sw_if_index = a->sep_ext.sw_if_index;
  a->sep_ext.peer.is_ip4 = is_ip4;
  a->sep_ext.peer.ip = flow->ip[UPF_EL_UL_SRC];
  a->sep_ext.peer.port = clib_host_to_net_u16 (flow->port[UPF_EL_UL_SRC]);

  // TODO: use
  // session_send_rpc_evt_to_thread_force (transport_cl_thread (),
  //   hcc_connect_rpc, a);

  session_error_t rv = vnet_connect (a);

  if (rv != SESSION_E_NONE)
    {
      // Example: vnet_connect() failed: -15 lcl port in use
      clib_warning ("vnet_connect() failed: %d %U", rv, format_session_error,
                    rv);
      return;
    }

  // Created session is half open and has no use for us. On establishment
  // success proper session will be created and saved.
  ps->side_ao.state = UPF_PROXY_S_S_CREATED;
}

static void
_proxy_on_disconnect_callback (upf_proxy_worker_t *pwk, session_t *s,
                               bool is_ao, bool is_reset)
{
  upf_proxy_session_t *ps = _get_ps_from_session (pwk, s);
  if (!ps)
    return;

  upf_debug ("sidx %d psidx %d", s->session_index, ps - pwk->sessions);

  if (CLIB_DEBUG)
    {
      ELOG_TYPE_DECLARE (e) = {
        .format =
          "upf-ps[%d]: ps disconnected flow-%d ps-%d[%d] s=%d ao=%d reset=%d",
        .format_args = "i2i4i4i2i4i1i1",
      };
      struct __clib_packed
      {
        u16 thread_id;
        u32 flow_id;
        u32 ps_id;
        u16 ps_generation;
        u32 vpp_session_id;
        u8 is_ao;
        u8 is_reset;
      } * ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, e);
      ed->thread_id = s->thread_index;
      ed->flow_id = ps->flow_index;
      ed->ps_id = ps - pwk->sessions;
      ed->ps_generation = ps->generation;
      ed->vpp_session_id = s->session_index;
      ed->is_ao = is_ao;
      ed->is_reset = is_reset;
    }

  proxy_session_close_connections (pwk, ps, is_reset ? 0 : 1);
}

static const char *upf_proxy_template =
  "HTTP/1.1 302 OK\r\n"
  "Location: %v\r\n"
  "Content-Type: text/html\r\n"
  "Cache-Control: private, no-cache, must-revalidate\r\n"
  "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
  "Connection: close\r\n"
  "Pragma: no-cache\r\n"
  "Content-Length: %d\r\n\r\n%v";

static const char *http_error_template =
  "HTTP/1.1 %s\r\n"
  "Content-Type: text/html\r\n"
  "Cache-Control: private, no-cache, must-revalidate\r\n"
  "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
  "Connection: close\r\n"
  "Pragma: no-cache\r\n"
  "Content-Length: 0\r\n\r\n";

static const char *wispr_proxy_template =
  "<!--\n"
  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
  "<WISPAccessGatewayParam"
  " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
  " xsi:noNamespaceSchemaLocation=\"http://www.acmewisp.com/"
  "WISPAccessGatewayParam.xsd\">"
  "<Proxy>"
  "<MessageType>110</MessageType>"
  "<ResponseCode>200</ResponseCode>"
  "<NextURL>%v</NextURL>"
  "</Proxy>"
  "</WISPAccessGatewayParam>\n"
  "-->\n";

static const char *html_redirect_template =
  "<!DOCTYPE html>\n"
  "<html>\n"
  "%v"
  "   <head>\n"
  "      <title>Redirection</title>\n"
  "      <meta http-equiv=\"refresh\" content=\"0; URL=%v\">\n"
  "   </head>\n"
  "   <body>\n"
  "      Please <a href='%v'>click here</a> to continue\n"
  "   </body>\n"
  "</html>\n";

static void
_http_redir_send_data (upf_proxy_worker_t *pwk, upf_proxy_session_t *ps,
                       session_t *s, u8 *data)
{
  vlib_main_t *vm = vlib_get_main ();
  f64 vlib_now = vlib_time_now (vm);
  u32 offset, bytes_to_send;
  f64 delay = 10e-3;

  bytes_to_send = vec_len (data);
  offset = 0;

  while (bytes_to_send > 0)
    {
      int actual_transfer;

      actual_transfer =
        svm_fifo_enqueue (s->tx_fifo, bytes_to_send, data + offset);

      /* Made any progress? */
      if (actual_transfer <= 0)
        {
          ASSERT (0);
          /* TODO: this one is broken, use different approach */
          vlib_process_suspend (vm, delay);
          /* 10s deadman timer */
          if (vlib_time_now (vm) > vlib_now + 10.0)
            {
              proxy_session_close_connections (pwk, ps, 0);
              break;
            }
          /* Exponential backoff, within reason */
          if (delay < 1.0)
            delay = delay * 2.0;
        }
      else
        {
          vlib_now = vlib_time_now (vm);
          offset += actual_transfer;
          bytes_to_send -= actual_transfer;

          if (svm_fifo_set_event (s->tx_fifo))
            session_send_io_evt_to_thread (s->tx_fifo,
                                           SESSION_IO_EVT_TX_FLUSH);
          delay = 10e-3;
        }
    }
}

static void
_http_redir_send_http_error (upf_proxy_worker_t *pwk, upf_proxy_session_t *ps,
                             session_t *s, char *str)
{
  u8 *data;

  data = format (0, http_error_template, str);
  _http_redir_send_data (pwk, ps, s, data);
  vec_free (data);
}

static int
_proxy_coommon_fifo_tuning_callback (session_t *s, svm_fifo_t *f,
                                     session_ft_action_t act, u32 bytes)
{
  upf_proxy_main_t *upm = &upf_proxy_main;

  upf_debug ("sidx %d", s->session_index);

  segment_manager_t *sm = segment_manager_get (f->segment_manager);
  fifo_segment_t *fs = segment_manager_get_segment (sm, f->segment_index);

  u8 seg_usage = fifo_segment_get_mem_usage (fs);
  u32 fifo_in_use = svm_fifo_max_dequeue_prod (f);
  u32 fifo_size = svm_fifo_size (f);
  u32 fifo_usage = ((u64) fifo_in_use * 100) / (u64) fifo_size;
  u32 update_size = 0;

  ASSERT (act < SESSION_FT_ACTION_N_ACTIONS);

  if (act == SESSION_FT_ACTION_ENQUEUED)
    {
      if (seg_usage < upm->config.low_watermark && fifo_usage > 50)
        update_size = fifo_in_use;
      else if (seg_usage < upm->config.high_watermark && fifo_usage > 80)
        update_size = fifo_in_use;

      update_size = clib_min (update_size, sm->max_fifo_size - fifo_size);
      if (update_size)
        svm_fifo_set_size (f, fifo_size + update_size);
    }
  else /* dequeued */
    {
      if (seg_usage > upm->config.high_watermark || fifo_usage < 20)
        update_size = bytes;
      else if (seg_usage > upm->config.low_watermark && fifo_usage < 50)
        update_size = (bytes / 2);

      ASSERT (fifo_size >= 4096);
      update_size = clib_min (update_size, fifo_size - 4096);
      if (update_size)
        svm_fifo_set_size (f, fifo_size - update_size);
    }

  return 0;
}

// This is passive side listener, it initializes proxy handling procedure
static int
_proxy_po_session_accept_callback (session_t *s)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (s->thread_index);

  flowtable_main_t *fm = &flowtable_main;
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, s->thread_index);

  upf_proxy_session_t *ps = _get_ps_from_session (pwk, s);
  if (!ps)
    {
      upf_debug ("proxy accept sidx %d invalid ps", s);
      ASSERT (0);
      return -1;
    }

  if (is_valid_id (ps->side_po.session_index))
    {
      upf_debug ("DUP accept: sidx %d psidx %d", s->session_index,
                 ps - pwk->sessions);
      ASSERT (0);
      return -1;
    }

  if (ps->side_po.state != UPF_PROXY_S_S_CREATED)
    {
      ASSERT (0);
      return -1;
    }

  ps->side_po.state = UPF_PROXY_S_S_CONNECTED;
  ps->po_rx_fifo = s->rx_fifo;
  ps->po_tx_fifo = s->tx_fifo;
  ps->side_po.session_index = s->session_index;

  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, s->thread_index);
  if (pool_is_free_index (fwk->flows, ps->flow_index))
    {
      upf_debug ("flow removed: sidx %d psidx %d flow_id %d", s->session_index,
                 ps - pwk->sessions, ps->flow_index);
      return -1;
    }

  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    {
      clib_warning ("session-%d state %d already closing", s->session_index,
                    s->session_state);
      return -1;
    }
  else if (s->session_state != SESSION_STATE_ACCEPTING)
    {
      clib_warning ("session-%d state %d to ready", s->session_index,
                    s->session_state);
      ASSERT (s->session_state == SESSION_STATE_ACCEPTING);
    }

  s->session_state = SESSION_STATE_READY;

  if (CLIB_DEBUG)
    {
      ELOG_TYPE_DECLARE (e) = {
        .format = "upf-ps[%d]: ps accepted po flow-%d ps-%d[%d] s=%d",
        .format_args = "i2i4i4i2i4",
      };
      struct __clib_packed
      {
        u16 thread_id;
        u32 flow_id;
        u32 ps_id;
        u16 ps_generation;
        u32 vpp_session_id;
      } * ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, e);
      ed->thread_id = s->thread_index;
      ed->flow_id = ps->flow_index;
      ed->ps_id = ps - pwk->sessions;
      ed->ps_generation = ps->generation;
      ed->vpp_session_id = s->session_index;
    }

  return 0;
}

static void
_proxy_po_session_disconnect_callback (session_t *s)
{
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, s->thread_index);

  upf_debug ("sidx %d", s->session_index);
  _proxy_on_disconnect_callback (pwk, s, 0, 0);
}

static void
_proxy_po_reset_callback (session_t *s)
{
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, s->thread_index);

  upf_debug ("sidx %d", s->session_index);
  _proxy_on_disconnect_callback (pwk, s, 0, 1);
}

static void
_proxy_po_session_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  upf_debug ("sidx %d (ntf %d)", s->session_index, ntf);

  // seems like SESSION_CLEANUP_SESSION is not called in all session_reset
  // cases
  if (ntf == SESSION_CLEANUP_TRANSPORT)
    proxy_session_on_cleanup_callback (s, 0 /* is_active_open */);
}

static void
_proxy_po_session_half_open_cleanup_callback (session_t *s)
{
  upf_debug ("sidx %d", s->session_index);
  ASSERT (0); // only for listener
  proxy_session_on_cleanup_callback (s, 0 /* is_active_open */);
}

static int
_proxy_po_sesssion_connected_callback (u32 app_index, u32 opaque, session_t *s,
                                       session_error_t err)
{
  // called during transition to _SYN_RCVD, but we create transport in such
  // state, so shouldn't be called
  ASSERT (0);
  upf_debug ("called...");
  return -1;
}

static int
_proxy_po_add_segment_callback (u32 client_index, u64 segment_handle)
{
  upf_debug ("called...");
  return 0;
}

static int
_proxy_rx_process_request (upf_proxy_worker_t *pwk, upf_proxy_session_t *ps)
{
  upf_debug ("psidx %d", ps - pwk->sessions);

  u32 max_dequeue =
    clib_min (svm_fifo_max_dequeue_cons (ps->po_rx_fifo), 4096);

  vec_validate (ps->rx_buf, max_dequeue - 1);
  int n_read = app_recv_stream_raw (ps->po_rx_fifo, ps->rx_buf, max_dequeue, 0,
                                    1 /* peek */);
  ASSERT (n_read == max_dequeue);

  // vec_set_len (ps->rx_buf, n_read);
  _vec_find (ps->rx_buf)->len = n_read;
  return 0;
}

static void
_proxy_send_redir (upf_proxy_worker_t *pwk, session_t *s,
                   upf_proxy_session_t *ps, upf_dp_session_t *dsx,
                   rules_far_t *ul_far)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (dsx->thread_id);

  upf_debug ("sidx %d psidx %d", s->session_index, ps - pwk->sessions);

  svm_fifo_dequeue_drop_all (ps->po_rx_fifo);
  svm_fifo_unset_event (ps->po_rx_fifo);

  u8 *request = ps->rx_buf;
  if (vec_len (request) < 6)
    {
      _http_redir_send_http_error (pwk, ps, s, "400 Bad Request");
      return;
    }

  bool is_get = false;
  for (int i = 0; i < vec_len (request) - 4; i++)
    if (request[i] == 'G' && request[i + 1] == 'E' && request[i + 2] == 'T' &&
        request[i + 3] == ' ')
      {
        is_get = true;
        break;
      }

  if (!is_get)
    {
      _http_redir_send_http_error (pwk, ps, s, "400 Bad Request");
      return;
    }

  /* Send it */
  u8 *url = ul_far->forward.redirect_uri;
  upf_debug ("URL %v REDIRECT INFORMATION type %x", url,
             ul_far->forward.redirect_uri);
  u8 *wispr = format (0, wispr_proxy_template, url);
  u8 *html = format (0, html_redirect_template, wispr, url, url);
  u8 *http = format (0, upf_proxy_template, url, vec_len (html), html);

  _http_redir_send_data (pwk, ps, s, http);

  vec_free (http);
  vec_free (html);
  vec_free (wispr);
}

static_always_inline void
_passive_rx_callback_with_active (svm_fifo_t *tx_fifo)
{
  upf_proxy_main_t *upm = &upf_proxy_main;

  // Send event for server tx fifo
  if (svm_fifo_set_event (tx_fifo))
    {
      u8 thread_index = tx_fifo->master_thread_index;
      ASSERT_THREAD_INDEX_OR_BARRIER (thread_index);

      u32 session_index = tx_fifo->shr->master_session_index;
      if (session_send_io_evt_to_thread_custom (&session_index, thread_index,
                                                SESSION_IO_EVT_TX))
        clib_warning ("failed to enqueue tx evt");
    }

  if (svm_fifo_max_enqueue (tx_fifo) <= upm->config.mss)
    svm_fifo_add_want_deq_ntf (tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
}

static int
_passive_rx_callback_no_active (upf_proxy_worker_t *pwk, session_t *s,
                                upf_proxy_session_t *ps)
{
  upf_debug ("sidx %d psidx %d", s->session_index, ps - pwk->sessions);

  ASSERT (ps->side_po.state == UPF_PROXY_S_S_CONNECTED);
  if (!is_valid_id (ps->flow_index))
    {
      clib_warning ("BUG: proxy RX callback for a dead flow");
      return -1;
    }

  int rv = _proxy_rx_process_request (pwk, ps);
  if (rv)
    return rv;

  flow_entry_t *flow =
    flowtable_get_flow_by_id (s->thread_index, ps->flow_index);
  upf_dp_session_t *dsx =
    upf_wk_get_dp_session (s->thread_index, flow->session_id);
  upf_rules_t *rules = upf_wk_get_rules (s->thread_index, dsx->rules_id);

  bool want_reclassify = true;
  if (flow->is_tcp_dpi_needed && !flow->is_tcp_dpi_done)
    {
      // do not do anything before we get or fail to get URIs
      upf_debug ("proxy uri extract: %v", ps->rx_buf);

      u8 *uri = NULL;
      adf_result_t r =
        upf_adf_dpi_extract_uri (ps->rx_buf, flow->port[UPF_EL_UL_DST], &uri);

      upf_debug ("uri extract r:%d, buffer len: %d, uri:%v", r,
                 svm_fifo_max_dequeue_cons (ps->po_rx_fifo), uri);

      if (r == ADR_NEED_MORE_DATA)
        {
          if (svm_fifo_max_dequeue_cons (ps->po_rx_fifo) < 4096)
            return 0; // wait for more data
          // if we over 4k of data - surrender and use emtpy URI
        }

      // DPI is done with success or failure (empty URI), but is done
      flow->is_tcp_dpi_done = 1;
      flow->app_uri = uri;
      want_reclassify = true;
    }

  // get needed UL PDR to decide on drop, redirection or proxy
  u8 ul_pdr_lid = ~0;
  if (want_reclassify || flow->generation != dsx->rules_generation)
    {
      u8 dl_pdr_lid = ~0;
      flowtable_entry_reset (flow, dsx->rules_generation);

      upf_classify_flow (rules, flow, UPF_PACKET_SOURCE_TCP_STACK, ~0, true,
                         flow->is_ip4, &ul_pdr_lid);
      upf_classify_flow (rules, flow, UPF_PACKET_SOURCE_TCP_STACK, ~0, false,
                         flow->is_ip4, &dl_pdr_lid);

      upf_debug ("reclassified (after_dpi: %d) ul: %d dl: %d", want_reclassify,
                 ul_pdr_lid, dl_pdr_lid);
    }
  else
    {
      ul_pdr_lid = flow->pdr_lids[UPF_DIR_UL];
    }

  // DPI is done or not needed, check if we need to do redirect
  rules_far_action_t apply_action = UPF_FAR_ACTION_DROP;
  if (is_valid_id (ul_pdr_lid))
    {
      rules_pdr_t *ul_pdr = upf_rules_get_pdr (rules, ul_pdr_lid);

      if (is_valid_id (ul_pdr->far_lid))
        {
          rules_far_t *ul_far = upf_rules_get_far (rules, ul_pdr->far_lid);

          if (ul_far->forward.has_redirect_information)
            {
              // Do redirect
              _proxy_send_redir (pwk, s, ps, dsx, ul_far);
              proxy_session_close_connections (pwk, ps, 1);
              ps->is_redirected = 1;
              return 0;
            }

          apply_action = ul_far->apply_action;
        }
    }

  // no need in redirect, create active end to proxy traffic
  if (apply_action == UPF_FAR_ACTION_FORWARD)
    _upf_proxy_start_ao_connect (pwk, ps);
  else
    proxy_session_close_connections (pwk, ps, 0);

  return 0;
}

// Handles incoming data on the client side
static int
_proxy_po_builtin_app_rx_callback (session_t *s)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (s->thread_index);
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, s->thread_index);

  upf_debug ("sidx %d", s->session_index);

  upf_proxy_session_t *ps = _get_ps_from_session (pwk, s);

  if (!ps || ps->side_po.state >= UPF_PROXY_S_S_CLOSING ||
      ps->side_ao.state >= UPF_PROXY_S_S_CLOSING)
    {
      upf_debug ("late rx callback: sidx %d psidx %d", s->session_index,
                 ps - pwk->sessions);
      return -1;
    }

  upf_debug ("sidx %d psidx %d", s->session_index, ps - pwk->sessions);
  if (is_valid_id (ps->side_ao.session_index) &&
      ps->side_ao.state >= UPF_PROXY_S_S_CREATED)
    _passive_rx_callback_with_active (s->rx_fifo);
  else
    return _passive_rx_callback_no_active (pwk, s, ps);

  return 0;
}

// Handles outgoing data on the client side.
static int
_proxy_po_builtin_app_tx_callback (session_t *po_s)
{
  upf_debug ("sidx %d", po_s->session_index);
  return _tx_callback_inline (po_s, 0);
}

static int
_proxy_ao_proxy_alloc_session_fifos_callback (session_t *ao_s)
{
  // called due to APP_OPTIONS_FLAGS_IS_BUILTIN | APP_OPTIONS_FLAGS_IS_PROXY

  ASSERT_THREAD_INDEX_OR_BARRIER (ao_s->thread_index);
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk =
    vec_elt_at_index (upm->workers, ao_s->thread_index);

  upf_proxy_session_t *ps = _get_ps_from_session (pwk, ao_s);
  upf_debug ("alloc session fifos for %U", format_session, ao_s, 2);

  if (!ps)
    {
      upf_debug ("couldn't allocate fifos for ao: po already destroyed");
      return -1;
    }

  if (ps->side_po.state >= UPF_PROXY_S_S_CLOSING)
    {
      upf_debug ("will not allocate fifos for ao: po closing");
      proxy_session_close_connections (pwk, ps, 0);
      _upf_proxy_session_try_put (pwk, ps);
      return -1;
    }

  svm_fifo_t *ao_tx_fifo = ps->po_rx_fifo;
  svm_fifo_t *ao_rx_fifo = ps->po_tx_fifo;

  /*
   * Reset the active-open tx-fifo master indices so the active-open session
   * will receive data, etc.
   */
  ao_tx_fifo->shr->master_session_index = ao_s->session_index;
  ao_tx_fifo->master_thread_index = ao_s->thread_index;

  /*
   * Account for the active-open session's use of the fifos
   * so they won't disappear until the last session which uses
   * them disappears
   */
  ao_rx_fifo->refcnt++;
  ao_tx_fifo->refcnt++;

  ao_s->rx_fifo = ao_rx_fifo;
  ao_s->tx_fifo = ao_tx_fifo;

  return 0;
}

static session_cb_vft_t proxy_session_cb_vft = {
  .session_accept_callback = _proxy_po_session_accept_callback,
  .session_disconnect_callback = _proxy_po_session_disconnect_callback,
  .session_connected_callback = _proxy_po_sesssion_connected_callback,
  .add_segment_callback = _proxy_po_add_segment_callback,
  .builtin_app_rx_callback = _proxy_po_builtin_app_rx_callback,
  .builtin_app_tx_callback = _proxy_po_builtin_app_tx_callback,
  .session_reset_callback = _proxy_po_reset_callback,
  .session_cleanup_callback = _proxy_po_session_cleanup_callback,
  .half_open_cleanup_callback = _proxy_po_session_half_open_cleanup_callback,
  .fifo_tuning_callback = _proxy_coommon_fifo_tuning_callback,
};

// Called when the server-side connection is established.
static int
_proxy_ao_session_connected_callback (u32 app_wrk_index, u32 opaque,
                                      session_t *s, session_error_t err)
{
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk =
    vec_elt_at_index (upm->workers, vlib_get_thread_index ());

  upf_proxy_session_t *ps = _get_ps_from_opaque (pwk, opaque);
  upf_debug ("sidx %d opaque 0x%x ao_sid %d", s ? s->session_index : -1,
             opaque, ps ? ps->side_ao.session_index : -1);

  if (err != SESSION_E_NONE)
    {
      /*
       * Upon active open connection failure, we close the passive
       * side, too
       */
      upf_debug ("sidx %d opaque 0x%x: connection failed: %U",
                 s ? s->session_index : -1, opaque, format_session_error, err);
      if (ps)
        {
          ps->side_ao.state = UPF_PROXY_S_S_DESTROYED;
          proxy_session_close_connections (pwk, ps, 0);
          _upf_proxy_session_try_put (pwk, ps);
        }
      return -1;
    }

  ASSERT_THREAD_INDEX_OR_BARRIER (s->thread_index);
  ASSERT (s->thread_index == app_worker_get (app_wrk_index)->wrk_map_index);

  // Setup proxy session handle
  ASSERT (ps->side_ao.session_index);
  ASSERT (ps->side_ao.state == UPF_PROXY_S_S_CREATED);

  if (CLIB_DEBUG)
    {
      ELOG_TYPE_DECLARE (e) = {
        .format = "upf-ps[%d]: ps connected ao flow-%d ps-%d[%d] s=%d",
        .format_args = "i2i4i4i2i4",
      };
      struct __clib_packed
      {
        u16 thread_id;
        u32 flow_id;
        u32 ps_id;
        u16 ps_generation;
        u32 vpp_session_id;
      } * ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, e);
      ed->thread_id = s->thread_index;
      ed->flow_id = ps->flow_index;
      ed->ps_id = ps - pwk->sessions;
      ed->ps_generation = ps->generation;
      ed->vpp_session_id = s->session_index;
    }

  /*
   * When the flow is removed, the passive side should be disconnected
   * immediatelly via upf_kill_connection_hard(), which causes session
   * cleanup to be invoked for the passive side, which sets
   * ps->po_disconnected to 1
   */
  ASSERT (is_valid_id (ps->flow_index) ||
          ps->side_po.state >= UPF_PROXY_S_S_CLOSING);

  if (ps->side_po.state >= UPF_PROXY_S_S_CLOSING)
    {
      upf_debug ("sidx %d opaque 0x%x: passive open side disconnected / flow "
                 "removed, closing active open connection",
                 s ? s->session_index : -1, opaque);
      ps->side_ao.state = UPF_PROXY_S_S_DESTROYED;
      proxy_session_close_connections (pwk, ps, 0);
      _upf_proxy_session_try_put (pwk, ps);
      /*
       * Returning -1 here will cause the active open side to be
       * closed immediatelly. Cleanup callback will not be invoked.
       */
      return -1;
    }

  ASSERT (s);

  ps->side_ao.state = UPF_PROXY_S_S_CONNECTED;
  ps->side_ao.session_index = s->session_index;

  // TODO: otherwise should be cleaned up before
  ASSERT (
    flowtable_get_flow_by_id (s->thread_index, ps->flow_index)->ps_index ==
    ps - pwk->sessions);

  transport_connection_t *tc = session_get_transport (s);
  ASSERT (tc->thread_index == s->thread_index);

  ps->side_ao.conn_index = tc->c_index;

  upf_debug ("sidx %d psidx %d: max tx dequeue %d", s->session_index, opaque,
             svm_fifo_max_dequeue (s->tx_fifo));
  /*
   * Send event for active open tx fifo
   *  ... we left the so far received data in rx fifo,
   *  this will therefore forward that data...
   */

  if (svm_fifo_set_event (s->tx_fifo))
    {
      upf_debug ("sidx %d psidx %d: sending TX event", s->session_index,
                 opaque);
      session_send_io_evt_to_thread (s->tx_fifo, SESSION_IO_EVT_TX);
    }
  else
    {
      upf_debug ("sidx %d psidx %d: NOT sending TX event", s->session_index,
                 opaque);
    }

  return 0;
}

static void
_proxy_ao_session_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  upf_debug ("sidx %d (ntf %d)", s->session_index, ntf);

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    proxy_session_on_cleanup_callback (s, 1 /* is_active_open */);
}

static void
_proxy_ao_half_open_session_cleanup_callback (session_t *s)
{
  upf_debug ("sidx %d", s->session_index);
  // This handler called both on ao connect success and failure.
  // Since half open session is not tracked we do not use this handler.
}

static int
_proxy_ao_session_create_callback (session_t *s)
{
  ASSERT (0); // listener only callback
  upf_debug ("sidx %d", s->session_index);
  return 0;
}

static void
_proxy_ao_disconnect_callback (session_t *s)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (s->thread_index);
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, s->thread_index);

  upf_debug ("sidx %d", s->session_index);
  _proxy_on_disconnect_callback (pwk, s, 1, 0);
}

static void
_proxy_ao_session_reset_callback (session_t *s)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (s->thread_index);
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, s->thread_index);

  upf_debug ("sidx %d", s->session_index);
  _proxy_on_disconnect_callback (pwk, s, 1, 1);
}

static int
_proxy_ao_add_segment_callback (u32 client_index, u64 segment_handle)
{
  upf_debug ("called...");
  return 0;
}

// Handles incoming data on the server side.
static int
_proxy_ao_builtin_app_rx_callback (session_t *s)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (s->thread_index);
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, s->thread_index);

  upf_debug ("sidx %d", s->session_index);

  upf_proxy_session_t *ps = _get_ps_from_session (pwk, s);
  if (!ps)
    {
      upf_debug ("no proxy session for sidx %d", s->session_index);
      return 0;
    }

  if (ps->side_ao.state >= UPF_PROXY_S_S_CLOSING ||
      ps->side_po.state >= UPF_PROXY_S_S_CLOSING)
    {
      upf_debug ("late tx callback: sidx %d psidx %d", s->session_index,
                 ps - pwk->sessions);
      return 0;
    }

  upf_debug ("sidx %d psidx %d", s->session_index, ps - pwk->sessions);

  _passive_rx_callback_with_active (s->rx_fifo);
  return 0;
}

// Handles outgoing data on the server side.
static int
_proxy_ao_builtin_app_tx_callback (session_t *s)
{
  upf_debug ("sidx %d", s->session_index);
  return _tx_callback_inline (s, 1);
}

static session_cb_vft_t active_open_clients = {
  .session_reset_callback = _proxy_ao_session_reset_callback,
  .session_connected_callback = _proxy_ao_session_connected_callback,
  .session_accept_callback = _proxy_ao_session_create_callback,
  .session_disconnect_callback = _proxy_ao_disconnect_callback,
  .add_segment_callback = _proxy_ao_add_segment_callback,
  .builtin_app_rx_callback = _proxy_ao_builtin_app_rx_callback,
  .builtin_app_tx_callback = _proxy_ao_builtin_app_tx_callback,
  .session_cleanup_callback = _proxy_ao_session_cleanup_callback,
  .half_open_cleanup_callback = _proxy_ao_half_open_session_cleanup_callback,
  .fifo_tuning_callback = _proxy_coommon_fifo_tuning_callback,
  .proxy_alloc_session_fifos = _proxy_ao_proxy_alloc_session_fifos_callback,
};

static int
_application_create_workers (u32 app_index)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  for (int i = 0; i < tm->n_threads; i++)
    {
      // Attach created only 1 worker for main thread. Create rest of workers,
      // to process sessions on their threads
      vnet_app_worker_add_del_args_t aw = { .is_add = 1,
                                            .app_index = app_index };
      session_error_t serr = vnet_app_worker_add_del (&aw);

      ASSERT (aw.wrk_map_index == i + 1);
      // we could save this value, but instead predict that it will allocate
      // sequentially and map threads like this
      if (aw.wrk_map_index != i + 1)
        return -2;

      if (serr != SESSION_E_NONE)
        return -3;
    };

  return 0;
}

static int
proxy_server_attach ()
{
  upf_proxy_main_t *upm = &upf_proxy_main;

  u64 options[APP_OPTIONS_N_OPTIONS] = {};
  u8 *name = format (0, "upf-proxy-server");

  vnet_app_attach_args_t a = { .options = options };
  a.name = name;
  a.session_cb_vft = &proxy_session_cb_vft;
  a.api_client_index = APP_INVALID_INDEX;
  a.options[APP_OPTIONS_SEGMENT_SIZE] = upm->config.private_segment_size;
  a.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = upm->config.private_segment_size;
  a.options[APP_OPTIONS_RX_FIFO_SIZE] = upm->config.fifo_size;
  a.options[APP_OPTIONS_TX_FIFO_SIZE] = upm->config.fifo_size;
  a.options[APP_OPTIONS_MAX_FIFO_SIZE] = upm->config.max_fifo_size;
  a.options[APP_OPTIONS_HIGH_WATERMARK] = (u64) upm->config.high_watermark;
  a.options[APP_OPTIONS_LOW_WATERMARK] = (u64) upm->config.low_watermark;
  a.options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] =
    upm->config.private_segment_count;
  a.options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
    upm->config.prealloc_fifos ? upm->config.prealloc_fifos : 0;

  a.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;

  session_error_t serr = vnet_application_attach (&a);
  vec_free (name);

  if (serr != SESSION_E_NONE)
    {
      upf_debug ("failed to attach passive application: %U",
                 format_session_error, serr);
      return -1;
    }

  upm->passive_server_app_index = a.app_index;

  return _application_create_workers (a.app_index);
}

static int
active_open_attach (void)
{
  upf_proxy_main_t *upm = &upf_proxy_main;

  u64 options[APP_OPTIONS_N_OPTIONS] = {};
  u8 *name = format (0, "upf-proxy-active-open");

  vnet_app_attach_args_t a = { .options = options };
  a.name = name;
  a.session_cb_vft = &active_open_clients;
  a.api_client_index = APP_INVALID_INDEX;
  a.options[APP_OPTIONS_ACCEPT_COOKIE] = 0x12345678;
  a.options[APP_OPTIONS_SEGMENT_SIZE] = 128 << 20;
  a.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = upm->config.private_segment_size;
  a.options[APP_OPTIONS_RX_FIFO_SIZE] = upm->config.fifo_size;
  a.options[APP_OPTIONS_TX_FIFO_SIZE] = upm->config.fifo_size;
  a.options[APP_OPTIONS_MAX_FIFO_SIZE] = upm->config.max_fifo_size;
  a.options[APP_OPTIONS_HIGH_WATERMARK] = (u64) upm->config.high_watermark;
  a.options[APP_OPTIONS_LOW_WATERMARK] = (u64) upm->config.low_watermark;
  a.options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] =
    upm->config.private_segment_count;
  a.options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
    upm->config.prealloc_fifos ? upm->config.prealloc_fifos : 0;

  // needed for proxy_alloc_session_fifos to merge active and passive fifos
  a.options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_IS_BUILTIN | APP_OPTIONS_FLAGS_IS_PROXY;

  session_error_t serr = vnet_application_attach (&a);
  vec_free (name);

  if (serr != SESSION_E_NONE)
    {
      upf_debug ("failed to attach active application: %U",
                 format_session_error, serr);
      return -1;
    }

  upm->active_open_app_index = a.app_index;

  return _application_create_workers (a.app_index);
}

static int
_upf_proxy_start (vlib_main_t *vm)
{
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_mt_main_t *umm = &upf_mt_main;

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */);
  vec_validate_init_empty (upm->workers, vec_len (umm->workers),
                           (upf_proxy_worker_t){});

  int rv;
  if ((rv = proxy_server_attach ()))
    {
      clib_warning ("failed to attach server app: %d", rv);
      return rv;
    }

  if ((rv = active_open_attach ()))
    {
      clib_warning ("failed to attach active open app: %d", rv);
      return rv;
    }

  return 0;
}

void
upf_proxy_flow_remove_handler (u16 thread_id, flow_entry_t *flow)
{
  ASSERT_THREAD_INDEX_OR_BARRIER (thread_id);
  upf_proxy_main_t *upm = &upf_proxy_main;
  upf_proxy_worker_t *pwk = vec_elt_at_index (upm->workers, thread_id);

  ASSERT (is_valid_id (flow->ps_index));

  upf_proxy_session_t *ps = pool_elt_at_index (pwk->sessions, flow->ps_index);
  ASSERT (ps);

  proxy_session_close_connections (pwk, ps, 0);

  if (ps->is_spliced)
    upf_stats_get_wk_generic (thread_id)->flows_tcp_stitched_count -= 1;

  ps->flow_index = ~0;

  _upf_proxy_session_try_put (pwk, ps);
}

clib_error_t *
upf_proxy_main_init (vlib_main_t *vm)
{
  upf_proxy_main_t *upm = &upf_proxy_main;
  tcp_main_t *tm = vnet_get_tcp_main ();

  upm->config.mss = TCP_DEFAULT_MSS;
  upm->config.fifo_size = 64 << 10;
  upm->config.max_fifo_size = 128 << 20;
  upm->config.high_watermark = 80;
  upm->config.low_watermark = 50;
  upm->config.prealloc_fifos = 0;
  upm->config.private_segment_count = 0;
  upm->config.private_segment_size = 512 << 20;

  /*
   * FIXME: this disables a TIME_WAIT -> LISTEN transition in the TCP stack.
   * We have to do that because UPF proxy doesn't use listeners.
   */
  tm->dispatch_table[TCP_STATE_TIME_WAIT][TCP_FLAG_SYN].next =
    0 /* TCP_INPUT_NEXT_DROP */;
  tm->dispatch_table[TCP_STATE_TIME_WAIT][TCP_FLAG_SYN].error =
    TCP_ERROR_DISPATCH;

  upf_debug ("TCP4 Output Node Index %u, IP4 Proxy Output Node Index %u",
             tcp4_output_node.index,
             upf_ip4_proxy_server_output_po_node.index);
  upf_debug ("TCP6 Output Node Index %u, IP6 Proxy Output Node Index %u",
             tcp6_output_node.index,
             upf_ip6_proxy_server_output_po_node.index);
  upm->tcp4_server_output_next = vlib_node_add_next (
    vm, tcp4_output_node.index, upf_ip4_proxy_server_output_po_node.index);
  upm->tcp6_server_output_next = vlib_node_add_next (
    vm, tcp6_output_node.index, upf_ip6_proxy_server_output_po_node.index);
  upm->tcp4_server_output_next_active = vlib_node_add_next (
    vm, tcp4_output_node.index, upf_ip4_proxy_server_output_ao_node.index);
  upm->tcp6_server_output_next_active = vlib_node_add_next (
    vm, tcp6_output_node.index, upf_ip6_proxy_server_output_ao_node.index);

  return 0;
}

/*
 * _upf_proxy_init() calls vnet_session_enable_disable() which must
 * not be invoked from an init function, as this leads to a crash in
 * the case of non-zero workers. See session_main_loop_init() in
 * src/vnet/session/session.c
 */
static clib_error_t *
upf_proxy_main_loop_init (vlib_main_t *vm)
{
  static bool upf_proxy_is_initialized = false;

  vlib_worker_thread_barrier_sync (vm);
  if (!upf_proxy_is_initialized)
    {
      upf_proxy_is_initialized = true;
      _upf_proxy_start (vm);
    }
  vlib_worker_thread_barrier_release (vm);

  return 0;
}

VLIB_INIT_FUNCTION (upf_proxy_main_init);
VLIB_MAIN_LOOP_ENTER_FUNCTION (upf_proxy_main_loop_init);
