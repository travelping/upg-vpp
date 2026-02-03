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

#ifndef UPF_RULES_UPF_GTPU_PROTO_H_
#define UPF_RULES_UPF_GTPU_PROTO_H_

#include <vppinfra/mhash.h>
#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_24_8.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/policer/policer.h>
#include <vnet/session/session_types.h>
#include <vlib/vlib.h>
#include <vlib/log.h>

typedef struct __clib_packed
{
  u8 ver_flags;
  u8 type;
  u16 length; // length of the gtp packet minus 8 mandatory hdr bytes
  u32 teid;
} gtpu_header_tpdu_t;

STATIC_ASSERT_SIZEOF (gtpu_header_tpdu_t, 8);

typedef struct __clib_packed
{
  gtpu_header_tpdu_t h;
  u16 sequence;
  u8 pdu_number;
  u8 next_ext_type;
} gtpu_header_t;

STATIC_ASSERT_SIZEOF (gtpu_header_t, 12);

typedef struct __clib_packed
{
  u8 type;
  u8 len;
  u16 pad;
} gtpu_ext_header_t;

typedef struct __clib_packed
{
  u8 ie_type;
  u8 restart_counter;
} gtpu_ie_recovery_t;

#define GTPU_V1_HDR_LEN 8

#define GTPU_VER_MASK   (7 << 5)
#define GTPU_PT_BIT     (1 << 4)
#define GTPU_E_BIT      (1 << 2)
#define GTPU_S_BIT      (1 << 1)
#define GTPU_PN_BIT     (1 << 0)
#define GTPU_E_S_PN_BIT (7 << 0)

#define GTPU_V1_VER (1 << 5)

#define GTPU_PT_GTP             (1 << 4)
#define GTPU_TYPE_ECHO_REQUEST  1
#define GTPU_TYPE_ECHO_RESPONSE 2
#define GTPU_TYPE_ERROR_IND     26
#define GTPU_TYPE_END_MARKER    254
#define GTPU_TYPE_GTPU          255

#define GTPU_UDP_PORT 2152

#define GTPU_EXT_HEADER_UDP_PORT_LENGTH 1

#define GTPU_EXT_HEADER_NEXT_HEADER_NO_MORE 0
#define GTPU_EXT_HEADER_UDP_PORT            0x40

#define GTPU_IE_RECOVERY    14
#define GTPU_IE_TEID_I      16
#define GTPU_IE_GSN_ADDRESS 133

typedef struct __clib_packed
{
  u8 id;
  u8 data[];
} gtpu_tv_ie_t;

typedef struct __clib_packed
{
  u8 id;
  u16 len;
  u8 data[];
} gtpu_tlv_ie_t;

typedef struct __clib_packed
{
  ip4_header_t ip4;        // 20 bytes
  udp_header_t udp;        // 8 bytes
  gtpu_header_tpdu_t gtpu; // 8 bytes
} ip4_gtpu_header_t;

typedef struct __clib_packed
{
  ip6_header_t ip6;        // 40 bytes
  udp_header_t udp;        // 12 bytes
  gtpu_header_tpdu_t gtpu; // 8 bytes
} ip6_gtpu_header_t;

#endif // UPF_RULES_UPF_GTPU_PROTO_H_
