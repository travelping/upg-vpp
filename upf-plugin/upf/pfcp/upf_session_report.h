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

#ifndef UPF_PFCP_UPF_SESSION_REPORT_H_
#define UPF_PFCP_UPF_SESSION_REPORT_H_

#include <vppinfra/vec.h>

#include "upf/pfcp/pfcp_proto.h"

typedef struct
{
  u32 teid;
  ip46_address_t addr;
  u16 port;
} upf2_session_report_error_indication_t;

typedef struct
{
  struct
  {
    struct
    {
      u64 total;
      u64 ul;
      u64 dl;
    } bytes;
    struct
    {
      u64 total;
      u64 ul;
      u64 dl;
    } packets;
  } volume_measurments;
  f64 time_start;
  f64 time_end;
  u32 duration_measurement;
  pfcp_ie_time_of_first_packet_t time_of_first_packet;
  pfcp_ie_time_of_last_packet_t time_of_last_packet;
  pfcp_ie_usage_information_t usage_information;
} upf2_usage_report_measurment_t;

typedef struct
{
  ip46_address_t ue_ip_address;
  u16 nwi_id;
} upf2_usage_report_start_of_traffic_t;

typedef struct
{
  pfcp_ie_urr_id_t urr_id;
  pfcp_ie_ur_seqn_t seq;

  pfcp_ie_usage_report_trigger_t usage_report_trigger;
  union
  {
    upf2_usage_report_measurment_t measurment;
    upf2_usage_report_start_of_traffic_t start_of_traffic;
  };
} upf2_usage_report_t;

typedef struct
{
  // for simplicity we support only single type
  pfcp_ie_report_type_t type;

  union
  {
    // usage reports sent in previous messages to main thread should be
    // combined with this message
    u32 usage_reports_count;
    upf2_session_report_error_indication_t error_indication;
  };
} upf2_session_report_t;

// substract and clamp to zero in case of underflow
#define _upf_sub_to_zero(_minuend, _subtrahend)                               \
  ({                                                                          \
    _Static_assert(                                                           \
      __builtin_types_compatible_p (typeof (_minuend), typeof (_subtrahend)), \
      "must have the same type");                                             \
    typeof (_minuend) minuend = (_minuend);                                   \
    typeof (_subtrahend) subtrahend = (_subtrahend);                          \
    (minuend <= subtrahend ? 0 : minuend - subtrahend);                       \
  })

#endif // UPF_PFCP_UPF_SESSION_REPORT_H_
