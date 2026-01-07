/*
 * Copyright (c) 2017 Cisco and/or its affiliates
 * Copyright (c) 2019-2025 Travelping GmbH
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

#include <vnet/vnet.h>
#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>

#include "upf/pfcp/upf_pfcp_server.h"
#include "upf/upf.h"

#define UPF_DEBUG_ENABLE 0

typedef struct
{
  /* API application handle */
  u32 app_index;

  /* process node index for evnt scheduling */
  u32 node_index;

  u32 prealloc_fifos;
  u32 private_segment_size;
  u32 fifo_size;
  vlib_main_t *vlib_main;
} pfcp_session_server_main_t;

typedef struct
{
  upf_pfcp_message_t m;
  u8 *data;
} pfcp_rx_message_t;

typedef enum
{
  EVENT_RX = 1,
} pfcp_process_event_t;

pfcp_session_server_main_t pfcp_session_server_main;
vlib_node_registration_t pfcp_api_process_node;

static int
_pfcp_session_server_rx_callback (session_t *s)
{
  session_dgram_pre_hdr_t ph;
  pfcp_rx_message_t *msg;
  u32 max_deq;
  int len, rv;

  max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
  while (max_deq >= sizeof (session_dgram_hdr_t))
    {
      svm_fifo_peek (s->rx_fifo, 0, sizeof (ph), (u8 *) &ph);
      ASSERT (ph.data_length >= ph.data_offset);

      len = ph.data_length - ph.data_offset;
      msg = clib_mem_alloc_no_fail (sizeof (*msg));
      memset (msg, 0, sizeof (*msg));

      msg->m.k.session_handle = session_handle (s);

      if (!ph.data_offset)
        {
          app_session_transport_t at;

          svm_fifo_peek (s->rx_fifo, sizeof (ph), sizeof (at), (u8 *) &at);

          msg->m.lcl_address = at.lcl_ip;
          msg->m.lcl_port = at.lcl_port;
          msg->m.k.rmt_address = at.rmt_ip;
          msg->m.k.rmt_port = at.rmt_port;

          if (at.is_ip4)
            {
              ip46_address_mask_ip4 (&msg->m.lcl_address);
              ip46_address_mask_ip4 (&msg->m.k.rmt_address);
            }
        }

      vec_validate (msg->data, len - 1);
      rv = svm_fifo_peek (s->rx_fifo, ph.data_offset + SESSION_CONN_HDR_LEN,
                          len, msg->data);

      ph.data_offset += rv;
      if (ph.data_offset == ph.data_length)
        svm_fifo_dequeue_drop (s->rx_fifo,
                               ph.data_length + SESSION_CONN_HDR_LEN);
      else
        svm_fifo_overwrite_head (s->rx_fifo, (u8 *) &ph, sizeof (ph));

      upf_debug ("sending event %d, %p %U:%d - %U:%d, data %p", ph.data_offset,
                 msg, format_ip46_address, &msg->m.k.rmt_address,
                 IP46_TYPE_ANY, clib_net_to_host_u16 (msg->m.k.rmt_port),
                 format_ip46_address, &msg->m.lcl_address, IP46_TYPE_ANY,
                 clib_net_to_host_u16 (msg->m.lcl_port), msg->data);

      vlib_process_signal_event_mt (vlib_get_first_main (),
                                    pfcp_api_process_node.index, EVENT_RX,
                                    (uword) msg);

      max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
    }

  return 0;
}

static int
_pfcp_session_server_session_accept_callback (session_t *s)
{
  upf_debug ("called...");
  return -1;
}

static void
_pfcp_session_server_session_disconnect_callback (session_t *s)
{
  upf_debug ("called...");
}

static void
_pfcp_session_server_session_reset_callback (session_t *s)
{
  upf_debug ("called...");
}

static int
_pfcp_session_server_session_connected_callback (u32 app_index,
                                                 u32 api_context, session_t *s,
                                                 session_error_t err)
{
  upf_debug ("called...");
  return -1;
}

static int
_pfcp_session_server_add_segment_callback (u32 client_index,
                                           u64 segment_handle)
{
  upf_debug ("called...");
  return 0;
}

static int
_pfcp_session_server_del_segment_callback (u32 client_index,
                                           u64 segment_handle)
{
  upf_debug ("called...");
  return 0;
}

static int
_pfcp_session_server_session_fifo_tuning_callback (session_t *s, svm_fifo_t *f,
                                                   session_ft_action_t act,
                                                   u32 bytes)
{
  upf_debug ("called...");
  return 0;
}

static session_cb_vft_t pfcp_session_server_session_cb_vft = {
  .session_reset_callback = _pfcp_session_server_session_reset_callback,
  .session_accept_callback = _pfcp_session_server_session_accept_callback,
  .session_disconnect_callback =
    _pfcp_session_server_session_disconnect_callback,
  .session_connected_callback =
    _pfcp_session_server_session_connected_callback,
  .add_segment_callback = _pfcp_session_server_add_segment_callback,
  .del_segment_callback = _pfcp_session_server_del_segment_callback,
  .builtin_app_rx_callback = _pfcp_session_server_rx_callback,
  .fifo_tuning_callback = _pfcp_session_server_session_fifo_tuning_callback,
};

static int
_pfcp_server_attach (vlib_main_t *vm)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;

  if (is_valid_id (pssm->app_index))
    {
      upf_debug ("app exists");
      return 0;
    }

  upf_debug ("creating app");

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */);

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "upf-pfcp-server");
  a->session_cb_vft = &pfcp_session_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = pssm->private_segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = pssm->private_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = pssm->fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = pssm->fifo_size;
  a->options[APP_OPTIONS_MAX_FIFO_SIZE] = pssm->fifo_size; // FIXME
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = pssm->prealloc_fifos;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      upf_debug ("failed to attach server");
      return -1;
    }

  upf_debug ("attached vnet application");

  vec_free (a->name);
  pssm->app_index = a->app_index;
  return 0;
}

int
upf_pfcp_endpoint_add_del (ip46_address_t *ip, u32 fib_index, u8 add)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  upf_main_t *um = &upf_main;
  upf_pfcp_endpoint_key_t key;
  uword *p;

  key.addr = *ip;
  key.fib_index = fib_index;

  p = mhash_get (&um->pfcp_endpoint_index, &key);

  if (add)
    {
      vnet_listen_args_t _a, *a = &_a;

      if (p)
        return VNET_API_ERROR_VALUE_EXIST;

      if (_pfcp_server_attach (pssm->vlib_main))
        return VNET_ERR_APPLICATION_NOT_ATTACHED;

      clib_memset (a, 0, sizeof (*a));

      a->app_index = pssm->app_index;
      a->sep_ext = (session_endpoint_cfg_t) SESSION_ENDPOINT_CFG_NULL;
      a->sep_ext.fib_index = fib_index;
      a->sep_ext.transport_proto = TRANSPORT_PROTO_UDP;
      a->sep_ext.is_ip4 = ip46_address_is_ip4 (ip);
      a->sep_ext.ip = *ip;
      a->sep_ext.port = clib_host_to_net_u16 (UDP_DST_PORT_PFCP);

      // use same socket for endpoints? does it makes sense for us?
      // TODO: this makes sense and works in clusters, but breaks e2e?
      // a->sep_ext.transport_flags |= TRANSPORT_CFG_F_CONNECTED;

      session_error_t listen_err = vnet_listen (a);
      if (listen_err != SESSION_E_NONE)
        {
          clib_warning ("vnet_listen returned %U", format_session_error,
                        listen_err);
          // most probably it was caused by invalid address for provided fib
          return VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE;
        }
      else
        mhash_set (&um->pfcp_endpoint_index, &key, a->handle, NULL);

      clib_warning ("vnet listen done (handle %d)", a->handle);
    }
  else
    {
      vnet_unlisten_args_t _a, *a = &_a;

      if (!p)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      clib_memset (a, 0, sizeof (*a));

      a->app_index = pssm->app_index;
      a->handle = p[0];

      mhash_unset (&um->pfcp_endpoint_index, &key, NULL);

      session_error_t listen_err = vnet_unlisten (a);
      if (listen_err != SESSION_E_NONE)
        {
          clib_warning ("ignoring vnet_listen error %U", format_session_error,
                        listen_err);
          return VNET_API_ERROR_UNSPECIFIED;
        }
    }

  return 0;
}

int
upf_pfcp_session_server_apply_config (u64 segment_size, u32 prealloc_fifos,
                                      u32 fifo_size)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;

  if (pssm->app_index != (u32) ~0)
    {
      clib_warning ("PFCP Server already running");
      return 1;
    }

  pssm->private_segment_size = segment_size;
  pssm->prealloc_fifos = prealloc_fifos;
  pssm->fifo_size = fifo_size;

  return 0;
}

void
upf_pfcp_session_server_get_config (u64 *segment_size, u32 *prealloc_fifos,
                                    u32 *fifo_size)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;

  *segment_size = pssm->private_segment_size;
  *prealloc_fifos = pssm->prealloc_fifos;
  *fifo_size = pssm->fifo_size;
}

static clib_error_t *
_pfcp_session_server_set_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 prealloc_fifos = pssm->prealloc_fifos;
  u32 fifo_size = pssm->fifo_size;
  u64 seg_size = pssm->private_segment_size;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "prealloc-fifos %d", &prealloc_fifos))
        ;
      else if (unformat (line_input, "private-segment-size %U",
                         unformat_memory_size, &seg_size))
        {
          if (seg_size >= 0x100000000ULL)
            {
              vlib_cli_output (vm, "private segment size %llu, too large",
                               seg_size);
              return 0;
            }
        }
      else if (unformat (line_input, "fifo-size %d", &fifo_size))
        fifo_size <<= 10;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (upf_pfcp_session_server_apply_config (seg_size, prealloc_fifos,
                                            fifo_size))
    return clib_error_return (0, "test pfcp server is already running");

  return 0;
}

VLIB_CLI_COMMAND (pfcp_session_server_set_command, static) = {
  .path = "upf pfcp server set",
  .short_help = "upf pfcp server set",
  .function = _pfcp_session_server_set_command_fn,
};

static clib_error_t *
_pfcp_session_server_main_init (vlib_main_t *vm)
{
  pfcp_session_server_main_t *pssm = &pfcp_session_server_main;

  pssm->app_index = ~0;
  pssm->vlib_main = vm;

  /* PFPC server defaults */
  // check via show segment-manager verbose
  pssm->prealloc_fifos = 0;
  pssm->fifo_size = 256 << 10;
  pssm->private_segment_size = 256 << 20;

  return 0;
}

VLIB_INIT_FUNCTION (_pfcp_session_server_main_init);

static uword
_pfcp_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  uword event_type, *event_data = 0;

  while (1)
    {
      (void) vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
        {
        case ~0:
          clib_warning ("unknown event type %d", event_type);
          break;

        case EVENT_RX:
          {
            for (int i = 0; i < vec_len (event_data); i++)
              {
                pfcp_rx_message_t *msg = (pfcp_rx_message_t *) event_data[i];
                upf_pfcp_server_rx_message (&msg->m, msg->data);

                vec_free (msg->data);
                clib_mem_free (msg);
              }
            break;
          }
        default:
          upf_debug ("event %ld, %p. ", event_type, event_data[0]);
          break;
        }

      vec_reset_length (event_data);
    }

  return (0);
}

VLIB_REGISTER_NODE (pfcp_api_process_node) = {
  .function = _pfcp_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 16,
  .runtime_data_bytes = sizeof (void *),
  .name = "upf-pfcp-api",
};
