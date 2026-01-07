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

#ifndef UPF_FLOW_FLOWTABLE_TCP_H_
#define UPF_FLOW_FLOWTABLE_TCP_H_

#include <vnet/tcp/tcp_packet.h>

typedef enum : u8
{
  TCP_F_STATE_START = 0,
  TCP_F_STATE_SYN = 1,
  TCP_F_STATE_SYNACK = 2,
  TCP_F_STATE_ESTABLISHED = 3,
  TCP_F_STATE_FIN = 4,
  TCP_F_STATE_FINACK = 5,
  TCP_F_STATE_RST = 6,
  TCP_F_STATE_MAX
} tcp_f_state_t;

typedef enum tcp_event
{
  TCP_EV_NONE,
  TCP_EV_SYN,
  TCP_EV_SYNACK,
  TCP_EV_FIN,
  TCP_EV_FINACK,
  TCP_EV_RST,
  TCP_EV_PSHACK,
  TCP_EV_MAX
} tcp_event_t;

__clib_unused static const tcp_f_state_t tcp_trans[TCP_F_STATE_MAX][TCP_EV_MAX] = {
    [TCP_F_STATE_START] =
        {
            [TCP_EV_SYN] = TCP_F_STATE_SYN,
            [TCP_EV_SYNACK] = TCP_F_STATE_SYNACK,
            [TCP_EV_FIN] = TCP_F_STATE_FIN,
            [TCP_EV_FINACK] = TCP_F_STATE_FINACK,
            [TCP_EV_RST] = TCP_F_STATE_RST,
            [TCP_EV_NONE] = TCP_F_STATE_ESTABLISHED,
        },
    [TCP_F_STATE_SYN] =
        {
            [TCP_EV_SYNACK] = TCP_F_STATE_SYNACK,
            [TCP_EV_PSHACK] = TCP_F_STATE_ESTABLISHED,
            [TCP_EV_FIN] = TCP_F_STATE_FIN,
            [TCP_EV_FINACK] = TCP_F_STATE_FINACK,
            [TCP_EV_RST] = TCP_F_STATE_RST,
        },
    [TCP_F_STATE_SYNACK] =
        {
            [TCP_EV_PSHACK] = TCP_F_STATE_ESTABLISHED,
            [TCP_EV_FIN] = TCP_F_STATE_FIN,
            [TCP_EV_FINACK] = TCP_F_STATE_FINACK,
            [TCP_EV_RST] = TCP_F_STATE_RST,
        },
    [TCP_F_STATE_ESTABLISHED] =
        {
            [TCP_EV_FIN] = TCP_F_STATE_FIN,
            [TCP_EV_FINACK] = TCP_F_STATE_FINACK,
            [TCP_EV_RST] = TCP_F_STATE_RST,
        },
    [TCP_F_STATE_FIN] =
        {
            [TCP_EV_FINACK] = TCP_F_STATE_FINACK,
            [TCP_EV_RST] = TCP_F_STATE_RST,
        },
    [TCP_F_STATE_FINACK] =
        {
            [TCP_EV_RST] = TCP_F_STATE_RST,
        },
};

__clib_unused always_inline tcp_event_t
tcp_event (tcp_header_t *hdr)
{
  if (hdr->flags & TCP_FLAG_SYN && hdr->flags & TCP_FLAG_ACK)
    return TCP_EV_SYNACK;
  else if (hdr->flags & TCP_FLAG_SYN)
    return TCP_EV_SYN;
  else if (hdr->flags & TCP_FLAG_FIN && hdr->flags & TCP_FLAG_ACK)
    return TCP_EV_FINACK;
  else if (hdr->flags & TCP_FLAG_FIN)
    return TCP_EV_FIN;
  else if (hdr->flags & TCP_FLAG_RST)
    return TCP_EV_RST;
  else
    return TCP_EV_PSHACK;
}

#endif // UPF_FLOW_FLOWTABLE_TCP_H_
