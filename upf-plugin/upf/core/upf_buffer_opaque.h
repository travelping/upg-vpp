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

#ifndef UPF_CORE_UPF_BUFFER_OPAQUE_H_
#define UPF_CORE_UPF_BUFFER_OPAQUE_H_

#include <stdbool.h>

#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#include "upf/core/upf_types.h"
#include "upf/utils/upf_localids.h"

/* UPF buffer opaque definition */
typedef union
{
  struct
  {
    u32 session_id;
    u32 flow_id;

    u8 packet_source : 2; // where buffer was captured
    u8 is_proxied : 1;    // can be not from tcp stack (with bypass)
    u8 is_uplink : 1;
    u8 is_gtpu_v4 : 1; // otherwise gtpuv6
    u8 is_ue_v4 : 1;   // otherwise ipv6

    // for ip - ip endpoint id
    // for gtpu - gtp endpoint id
    // for nat and proxy - invalid
    upf_lid_t source_lid;

    // Result of classification. Used for forwarding
    upf_lid_t pdr_lid;

    u16 gtpu_ext_hdr_len; // len of gtpu extensions
    u16 outer_hdr_len;    // offset to inner ip hdr or outer ip+udp+gtpu len
  } gtpu;

  struct
  {
    u16 thread_id; // target thread id
  } handoff;

  u32 as_u32[8]; // mark size limit
} upf_buffer_opaque_t;

STATIC_ASSERT (sizeof (upf_buffer_opaque_t) ==
                 STRUCT_SIZE_OF (vnet_buffer_opaque2_t, unused),
               "upf_buffer_opaque_t too large for vnet_buffer_opaque2_t");

#define upf_buffer_opaque(b)                                                  \
  ((upf_buffer_opaque_t *) ((u8 *) ((b)->opaque2) +                           \
                            STRUCT_OFFSET_OF (vnet_buffer_opaque_t, unused)))

/*
 * For debug builds, we add a flag to each buffer when we initialize
 * GTPU metadata when the buffer enters UPF nodes chain
 */
#define UPF_BUFFER_F_GTPU_INITIALIZED VNET_BUFFER_F_AVAIL1

__clib_unused always_inline void
UPF_ENTER_SUBGRAPH (vlib_buffer_t *b, u32 session_id,
                    upf_packet_source_t packet_source, upf_lid_t source_lid,
                    bool is_ue_ipv4, bool is_uplink)
{
  ASSERT (!((b)->flags & UPF_BUFFER_F_GTPU_INITIALIZED));

  clib_memset (upf_buffer_opaque (b), 0, sizeof (upf_buffer_opaque_t));

  if (CLIB_ASSERT_ENABLE)
    b->flags |= UPF_BUFFER_F_GTPU_INITIALIZED;

  // this values are required for pdr matching
  upf_buffer_opaque (b)->gtpu.session_id = session_id;
  upf_buffer_opaque (b)->gtpu.flow_id = ~0;
  upf_buffer_opaque (b)->gtpu.is_uplink = is_uplink;
  upf_buffer_opaque (b)->gtpu.is_ue_v4 = is_ue_ipv4;
  upf_buffer_opaque (b)->gtpu.packet_source = packet_source;
  upf_buffer_opaque (b)->gtpu.source_lid = source_lid;
  upf_buffer_opaque (b)->gtpu.pdr_lid = ~0;
}

__clib_unused always_inline void
UPF_CHECK_INNER_NODE (vlib_buffer_t *b)
{
  ASSERT (b->flags & UPF_BUFFER_F_GTPU_INITIALIZED);
}

// Cache l3 and l4 headers offsets. Every UPF node may use them.
__clib_unused static_always_inline void
upf_vnet_buffer_l3l4_hdr_offset_current_ip (vlib_buffer_t *b, bool is_ip4)
{
  u32 l3_hdr_size;
  if (is_ip4)
    l3_hdr_size =
      ip4_header_bytes ((ip4_header_t *) (b->data + b->current_data));
  else
    l3_hdr_size = sizeof (ip6_header_t);

  vnet_buffer (b)->l3_hdr_offset = b->current_data;
  vnet_buffer (b)->l4_hdr_offset = b->current_data + l3_hdr_size;
  b->flags |=
    (VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
}

// When we reuse packet for response and we shrink it, we should remove chained
// buffers, since they could contain data
__clib_unused static_always_inline void
upf_vnet_buffer_reuse_without_chained_buffers (vlib_main_t *vm,
                                               vlib_buffer_t *b)
{
  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      // remove unneded buffers
      vlib_buffer_free_one (vm, b->next_buffer);
      b->flags &= ~(VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID);
    }
  b->flags |= (VNET_BUFFER_F_LOCALLY_ORIGINATED);
}

#endif // UPF_CORE_UPF_BUFFER_OPAQUE_H_
