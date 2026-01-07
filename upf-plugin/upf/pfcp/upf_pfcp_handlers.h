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

#ifndef UPF_PFCP_UPF_PFCP_HANDLERS_H_
#define UPF_PFCP_UPF_PFCP_HANDLERS_H_

#include "upf/pfcp/upf_pfcp_server.h"

void upf_usage_report_add_queued_reports (pfcp_ie_usage_report_t **urs_vec,
                                          upf_time_t now);

typedef enum
{
  UPF_PFCP_MESSAGE_RV_SUCCESS,
  UPF_PFCP_MESSAGE_RV_FAILED,
} upf_pfcp_message_rv_t;

typedef enum
{
  // Request completed, consume it
  UPF_PFCP_RESPONSE_RV_ACCEPT,
  // Keep waiting for response
  UPF_PFCP_RESPONSE_RV_IGNORE,
} upf_pfcp_response_rv_t;

// received message without existing request
typedef upf_pfcp_message_rv_t (*upf_pfcp_message_handler_t) (
  upf_pfcp_message_t *msg, pfcp_decoded_msg_t *dmsg);

// received message for existing request
typedef upf_pfcp_response_rv_t (*upf_pfcp_response_handler_t) (
  upf_pfcp_message_t *msg, upf_pfcp_request_t *our_req,
  pfcp_decoded_msg_t *dmsg);

// request timed out
typedef void (*upf_pfcp_timeout_handler_t) (upf_pfcp_request_t *req);

// message decoding failed with cause
typedef void (*upf_pfcp_decode_error_handler_t) (
  upf_pfcp_message_t *msg, pfcp_msg_type_t t, pfcp_ie_cause_t cause,
  pfcp_ie_offending_ie_t *decode_errs);

upf_pfcp_message_handler_t upf_pfcp_get_message_handler (pfcp_msg_type_t t);
upf_pfcp_response_handler_t upf_pfcp_get_response_handler (pfcp_msg_type_t t);
upf_pfcp_timeout_handler_t upf_pfcp_get_timeout_handler (pfcp_msg_type_t t);
upf_pfcp_decode_error_handler_t
upf_pfcp_get_on_decode_error_handler (pfcp_msg_type_t t);

#endif // UPF_PFCP_UPF_PFCP_HANDLERS_H_
