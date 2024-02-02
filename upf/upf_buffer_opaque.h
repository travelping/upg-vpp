/*
 * upf.h - 3GPP TS 29.244 GTP-U UP plug-in header file
 *
 * Copyright (c) 2017-2019 Travelping GmbH
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
#ifndef __included_upf_buffer_opaque_h__
#define __included_upf_buffer_opaque_h__

#include <vppinfra/error.h>
#include <vnet/vnet.h>

/* UPF buffer opaque definition */
typedef struct
{
  struct
  {
    u64 pad[1];
    u32 teid;
    u32 session_index;
    u16 ext_hdr_len;
    u16 data_offset; /* offset relative to ip hdr */
    u8 hdr_flags;
    u8 flags;
    u8 pkt_key_direction : 1; // flow_key_direction_t
    u8 direction : 1;         // flow_direction_t
    u8 is_proxied : 1;
    u32 pdr_idx;
    u32 flow_id;
  } gtpu;
} upf_buffer_opaque_t;

STATIC_ASSERT (sizeof (upf_buffer_opaque_t) <=
                 STRUCT_SIZE_OF (vnet_buffer_opaque2_t, unused),
               "upf_buffer_opaque_t too large for vnet_buffer_opaque2_t");

#define upf_buffer_opaque(b)                                                  \
  ((upf_buffer_opaque_t *) ((u8 *) ((b)->opaque2) +                           \
                            STRUCT_OFFSET_OF (vnet_buffer_opaque_t, unused)))

#if CLIB_DEBUG > 0

/*
 * For debug builds, we add a flag to each buffer when we initialize
 * GTPU metadata when the buffer is processed by one of the UPF
 * entry nodes (upf-gtpu[46]-input, upf-ip[46]-session-dpo,
 * upf-ip[46]-proxy-server-output)
 */
#define UPF_BUFFER_F_GTPU_INITIALIZED VNET_BUFFER_F_AVAIL1
#define UPF_ENTER_SUBGRAPH(b, sidx, is_ip4)                                   \
  do                                                                          \
    {                                                                         \
      ASSERT (!((b)->flags & UPF_BUFFER_F_GTPU_INITIALIZED));                 \
      clib_memset (upf_buffer_opaque (b), 0, sizeof (upf_buffer_opaque_t));   \
      b->flags |= UPF_BUFFER_F_GTPU_INITIALIZED;                              \
      upf_buffer_opaque (b)->gtpu.session_index = sidx;                       \
      upf_buffer_opaque (b)->gtpu.flags =                                     \
        is_ip4 ? BUFFER_GTP_UDP_IP4 : BUFFER_GTP_UDP_IP6;                     \
    }                                                                         \
  while (0)
#define UPF_CHECK_INNER_NODE(b)                                               \
  ASSERT (b->flags &UPF_BUFFER_F_GTPU_INITIALIZED)

#else

#define UPF_ENTER_SUBGRAPH(b, sidx, is_ip4)                                   \
  do                                                                          \
    {                                                                         \
      clib_memset (upf_buffer_opaque (b), 0, sizeof (upf_buffer_opaque_t));   \
      upf_buffer_opaque (b)->gtpu.session_index = sidx;                       \
      upf_buffer_opaque (b)->gtpu.flags =                                     \
        is_ip4 ? BUFFER_GTP_UDP_IP4 : BUFFER_GTP_UDP_IP6;                     \
    }                                                                         \
  while (0)
#define UPF_CHECK_INNER_NODE(b)

#endif

#define BUFFER_FAR_ONLY    (1 << 3) /* don't include in QER/URR processing */
#define BUFFER_HAS_GTP_HDR (1 << 4)
#define BUFFER_HAS_UDP_HDR (1 << 5)
#define BUFFER_HAS_IP4_HDR (1 << 6)
#define BUFFER_HAS_IP6_HDR (1 << 7)
#define BUFFER_HDR_MASK                                                       \
  (BUFFER_HAS_GTP_HDR | BUFFER_HAS_UDP_HDR | BUFFER_HAS_IP4_HDR |             \
   BUFFER_HAS_IP6_HDR)
#define BUFFER_GTP_UDP_IP4                                                    \
  (BUFFER_HAS_GTP_HDR | BUFFER_HAS_UDP_HDR | BUFFER_HAS_IP4_HDR)
#define BUFFER_GTP_UDP_IP6                                                    \
  (BUFFER_HAS_GTP_HDR | BUFFER_HAS_UDP_HDR | BUFFER_HAS_IP6_HDR)
#define BUFFER_UDP_IP4 (BUFFER_HAS_UDP_HDR | BUFFER_HAS_IP4_HDR)
#define BUFFER_UDP_IP6 (BUFFER_HAS_UDP_HDR | BUFFER_HAS_IP6_HDR)

#endif /* __included_upf_buffer_opaque_h__ */
