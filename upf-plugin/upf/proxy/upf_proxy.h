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

#ifndef UPF_PROXY_UPF_PROXY_H_
#define UPF_PROXY_UPF_PROXY_H_

#include <vnet/vnet.h>
#include <vnet/session/application.h>
#include <vnet/tcp/tcp.h>

extern vlib_node_registration_t upf_ip4_proxy_server_output_po_node;
extern vlib_node_registration_t upf_ip6_proxy_server_output_po_node;
extern vlib_node_registration_t upf_ip4_proxy_server_output_ao_node;
extern vlib_node_registration_t upf_ip6_proxy_server_output_ao_node;

format_function_t format_upf_proxy_session;
format_function_t format_upf_proxy_side_state;

typedef enum : u8
{
  // passive open side - used for DPI, after DPI, or redirect
  UPF_PROXY_SIDE_PO = 0,
  // active open side - used after DPI decided to continue forwarding
  UPF_PROXY_SIDE_AO = 1,
  UPF_PROXY_N_SIDES = 2,
} upf_proxy_side_t;

#define foreach_upf_proxy_side_state                                          \
  _ (INVALID)                                                                 \
  _ (CREATED)                                                                 \
  _ (CONNECTED)                                                               \
  /* graceful close via FIN/ACK, should allow packets in and out vpp tcp */   \
  _ (CLOSING)                                                                 \
  /* forced close via RST, allow packets only out of vpp tcp */               \
  _ (RESET)                                                                   \
  /* session and transport removed */                                         \
  _ (DESTROYED)

// 1. SYN received → upf_proxy_accept creates PO (Passive Open) session
// 2. DPI analysis (optional)
// 3. Decision:
//    - Redirect → send HTTP 302, close gracefully
//    - Forward → create AO (Active Open) connection
//    - Drop → close immediately
// 4. Data forwarding (either spliced or proxied)
// 5. Connection close (graceful or reset)
// 6. Cleanup after 0.1s (VPP TCP timer)

typedef enum : u8
{
#define _(name) UPF_PROXY_S_S_##name,
  foreach_upf_proxy_side_state
#undef _
    UPF_PROXY_N_S_S,
} upf_proxy_side_state_t;

typedef struct
{
  u32 session_index;
  u32 conn_index; // vpp transport_connection_t->c_index
  u32 seq_offs;   // amount to add to seq and substract from acks
  u32 tsval_offs;
  // TODO: hijack and modify window as large as possible with advertised
  // scaling
  u32 todo_real_wnd_scaling;

  upf_proxy_side_state_t state;
} upf_proxy_side_tcp_t;

// manages both client and server sides
typedef struct
{
  u32 self_id;

  // same fifos reused for ao, but reversed
  svm_fifo_t *po_rx_fifo;
  svm_fifo_t *po_tx_fifo;

  u8 generation : 4;

  u8 is_spliced : 1;
  u8 is_dont_splice : 1;
  u8 is_uri_extracted : 1;
  u8 is_redirected : 1;

  u32 flow_index;

  u8 *rx_buf; /**< intermediate rx buffers */
  union
  {
    upf_proxy_side_tcp_t sides[UPF_PROXY_N_SIDES];
    struct
    {
      upf_proxy_side_tcp_t side_po;
      upf_proxy_side_tcp_t side_ao;
    };
  };
} upf_proxy_session_t;

STATIC_ASSERT (offsetof (upf_proxy_session_t, sides[UPF_PROXY_SIDE_PO]) ==
                 offsetof (upf_proxy_session_t, side_po),
               "po offset");
STATIC_ASSERT (offsetof (upf_proxy_session_t, sides[UPF_PROXY_SIDE_AO]) ==
                 offsetof (upf_proxy_session_t, side_ao),
               "ao offset");

typedef union
{
  struct
  {
    u32 id : 28;
    u32 generation : 4;
  };
  u32 as_u32;
} upf_proxy_session_opaque_t;

STATIC_ASSERT_SIZEOF (upf_proxy_session_opaque_t, sizeof (u32));

#define foreach_upf_proxy_config_fields                                       \
  _ (u16, mss)                    /**< TCP MSS */                             \
  _ (uword, fifo_size)            /**< initial fifo size */                   \
  _ (uword, max_fifo_size)        /**< max fifo size */                       \
  _ (u8, high_watermark)          /**< high watermark (%) */                  \
  _ (u8, low_watermark)           /**< low watermark (%) */                   \
  _ (u32, private_segment_count)  /**< Number of private fifo segs */         \
  _ (uword, private_segment_size) /**< size of private fifo segs */           \
  _ (u8, prealloc_fifos)          /**< Request fifo preallocation */

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  upf_proxy_session_t *sessions;
} upf_proxy_worker_t;

typedef struct
{
  u16 tcp4_server_output_next;
  u16 tcp6_server_output_next;
  u16 tcp4_server_output_next_active;
  u16 tcp6_server_output_next_active;

  upf_proxy_worker_t *workers;

  u32 passive_server_app_index; /**< server app index */
  u32 active_open_app_index;    /**< active open index after attach */

  struct
  {
    /*
     * Configuration params
     */
#define _(type, name) type name;
    foreach_upf_proxy_config_fields
#undef _
  } config;
} upf_proxy_main_t;

extern upf_proxy_main_t upf_proxy_main;

upf_proxy_session_t *upf_proxy_session_new (upf_proxy_worker_t *pwk,
                                            u32 flow_id);

void upg_session_cleanup (session_t *s, bool is_active_open);

void proxy_session_close_connections (upf_proxy_worker_t *pwk,
                                      upf_proxy_session_t *ps, bool graceful);

tcp_connection_t *_upf_tcp_lookup_connection (u32 fib_index, vlib_buffer_t *b,
                                              u8 thread_index, u8 is_ip4,
                                              u8 is_reverse);

__clib_unused static u32
upf_proxy_session_opaque (upf_proxy_session_t *ps)
{
  upf_proxy_session_opaque_t opaque = { .generation = ps->generation,
                                        .id = ps->self_id };
  return opaque.as_u32;
}

// disable timestamp transmission hack
__clib_unused static void
_upf_tcp_strip_syn_options (tcp_header_t *th)
{
  if (!tcp_syn (th))
    return;

  u8 opts_len = (tcp_doff (th) << 2) - sizeof (tcp_header_t);
  u8 *data = (u8 *) (th + 1);

  u8 opt_len;
  for (u8 pos = 0; pos <= opts_len; pos += opt_len)
    {
      u8 kind = data[pos];
      if (kind == TCP_OPTION_EOL)
        {
          break;
        }
      else if (kind == TCP_OPTION_NOOP)
        {
          opt_len = 1;
          continue;
        }
      else
        {
          opt_len = data[pos + 1];
          if (opt_len < 2 || opt_len > opts_len)
            break;
        }

      // TODO: Verify and figure out if we can use timestamp or scale options
      // properly
      bool zero_opt = (kind == TCP_OPTION_TIMESTAMP /*||
                         kind == TCP_OPTION_WINDOW_SCALE*/);

      if (zero_opt)
        for (u8 i = 0; i < opt_len; i++)
          data[pos + i] = TCP_OPTION_NOOP;
    }
}

// defined in vnet/session/session_cli.c
u8 *format_session_state (u8 *s, va_list *args);

#endif // UPF_PROXY_UPF_PROXY_H_
