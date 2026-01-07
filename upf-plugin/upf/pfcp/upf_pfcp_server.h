/*
 * Copyright (c) 2017-2025 Travelping GmbH
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

#ifndef UPF_PFCP_UPF_PFCP_SERVER_H_
#define UPF_PFCP_UPF_PFCP_SERVER_H_

#include <vppinfra/types.h>
#include <vnet/session/session.h>

#include "upf/utils/upf_timer.h"
#include "upf/pfcp/upf_pfcp_assoc.h"
#include "upf/pfcp/upf_session.h"

#define PFCP_DEFAULT_REQUEST_INTERVAL 10
#define PFCP_DEFAULT_REQUEST_RETRIES  3
#define PFCP_MAX_HB_INTERVAL          120
#define PFCP_MAX_HB_RETRIES           30
// default limit to not accidentaly overload control plane network and endpoint
#define PFCP_DEFAULT_PACKETS_DROP_RATELIMIT 20000

#define UDP_DST_PORT_PFCP 8805

typedef struct __key_packed
{
  ip46_address_t addr;
  u32 fib_index;
} upf_pfcp_endpoint_key_t;
STATIC_ASSERT_SIZEOF (upf_pfcp_endpoint_key_t, 20);

typedef struct
{
  u8 retries;
  u8 timeout;
} upf_pfcp_server_retransmit_config_t;

typedef union __key_packed
{
  struct __key_packed
  {
    session_handle_t session_handle;
    ip46_address_t rmt_address;
    u16 rmt_port;
    u8 _pad[2];
    u32 seq_no;
  };
  u64 as_u64[4];
} upf_pfcp_key_t;
STATIC_ASSERT_SIZEOF_ELT (upf_pfcp_key_t, as_u64, sizeof (upf_pfcp_key_t));

typedef struct
{
  upf_pfcp_key_t k;
  ip46_address_t lcl_address;
  u16 lcl_port; // network order
} upf_pfcp_message_t;

// Request from UPF to remote endpoint
typedef struct
{
  upf_pfcp_message_t m;
  u8 *data;

  struct
  {
    u32 id; // may become ~0
    upf_assoc_requests_list_anchor_t anchor;
  } assoc;

  struct
  {
    // request can lose session in-flight if session was removed while
    // request is being answered
    u32 id;
    upf_session_requests_list_anchor_t anchor;
    u64 up_seid; // for reliability
  } session;

  upf_timer_id_t timer;
  u32 n1;
  u32 t1;

  struct
  {
    u8 is_migrated_in_smfset : 1;
    u8 is_stopped : 1;
  } flags;
} upf_pfcp_request_t;

// Response slot. Similar to async promise for response
typedef struct
{
  upf_pfcp_message_t m;
  // data can be NULL if response not yet populated, but in process of
  // processing. To handle received retransmits while processing request
  u8 *data;

  upf_timer_id_t timer;
} upf_pfcp_response_t;

typedef struct
{
  u32 seq_no;

  ip46_address_t address;

  upf_pfcp_request_t *requests;   // pool
  upf_pfcp_response_t *responses; // pool

  uword *request_q;   // sequence number to request
  mhash_t response_q; // message key to response

  upf_pfcp_server_retransmit_config_t heartbeat_cfg;
  upf_pfcp_server_retransmit_config_t default_cfg;

  time_t recovery;

  tokenbucket_t pfcp_request_drop_ratelimit;
} pfcp_server_main_t;

typedef struct
{
  u8 *identity;
  upf_nwi_name_t nwi_name;
} upf_ue_ip_pool_info_t;

UPF_LLIST_TEMPLATE_DEFINITIONS (upf_session_requests_list, upf_pfcp_request_t,
                                session.anchor);
UPF_LLIST_TEMPLATE_DEFINITIONS (upf_assoc_requests_list, upf_pfcp_request_t,
                                assoc.anchor);

extern pfcp_server_main_t pfcp_server_main;

// Requests management
upf_pfcp_request_t *upf_pfcp_request_create (upf_assoc_t *assoc);
void upf_pfcp_request_link_session (upf_pfcp_request_t *req, u32 session_id);
void upf_pfcp_request_unlink_session (upf_pfcp_request_t *req);
// Takes ownership of data
void
upf_pfcp_request_send (upf_pfcp_request_t *req, u8 *data,
                       upf_pfcp_server_retransmit_config_t *retransmit_cfg);
void upf_pfcp_request_delete (upf_pfcp_request_t *req);

void upf_pfcp_message_encode (upf_pfcp_message_t *msg,
                              pfcp_decoded_msg_t *dmsg, u64 seid,
                              u8 **result_vec);

// Retransmit detection managment
upf_pfcp_response_t *upf_pfcp_response_create (upf_pfcp_message_t *in_req);
// Takes ownership of data
void upf_pfcp_response_populate (upf_pfcp_response_t *resp, u8 *data);
void upf_pfcp_response_delete (upf_pfcp_response_t *resp);

void upf_pfcp_server_send_response_with_seid (upf_pfcp_message_t *in_req,
                                              pfcp_decoded_msg_t *dmsg,
                                              u64 seid);
void upf_pfcp_server_send_response (upf_pfcp_message_t *in_req,
                                    pfcp_decoded_msg_t *dmsg);

void upf_pfcp_server_rx_message (upf_pfcp_message_t *msg, u8 *data);

int upf_pfcp_session_server_apply_config (u64 segment_size, u32 prealloc_fifos,
                                          u32 fifo_size);
void upf_pfcp_session_server_get_config (u64 *segment_size,
                                         u32 *prealloc_fifos, u32 *fifo_size);

int upf_pfcp_endpoint_add_del (ip46_address_t *ip, u32 fib_index, u8 add);

int upf_pfcp_heartbeat_config (u32 timeout, u32 retires);

vnet_api_error_t upf_ue_ip_pool_add_del (u8 *identity, u8 *nwi_name,
                                         int is_add);

vnet_api_error_t upf_node_id_set (const pfcp_ie_node_id_t *node_id);

format_function_t format_upf_pfcp_key;
format_function_t format_upf_pfcp_message;
format_function_t format_upf_pfcp_request;
format_function_t format_upf_pfcp_response;

void pfcp_server_main_init ();

#endif // UPF_PFCP_UPF_PFCP_SERVER_H_
