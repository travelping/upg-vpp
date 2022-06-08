/*
 * Copyright (c) 2017-2022 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __included_upf_ipfix_templates_h__
#define __included_upf_ipfix_templates_h__

/*
 * NTP rfc868 : 2 208 988 800 corresponds to 00:00  1 Jan 1970 GMT
 */
#define NTP_TIMESTAMP 2208988800LU

/*
 * In each value macro:
 * - v represents the value
 * - n represents byte count when it's not fixed
 * - c is a condition expression for fields that aren't
 *   always applicable (NAT-related, for example)
 */

#define IPFIX_VALUE_DIRECT(v, n, c) to_b->data[offset++] = (v)

#define IPFIX_VALUE_MEMCPY_DIRECT(v, n, c)		\
  do {							\
    clib_memcpy_fast (to_b->data + offset, v, n);	\
    offset += n;					\
  } while (0)

#define IPFIX_VALUE_MEMCPY_DIRECT_COND(v, n, c)		\
  do {							\
    if (c)						\
      clib_memcpy_fast (to_b->data + offset, v, n);	\
    else						\
      clib_memset (to_b->data + offset, 0, n);		\
    offset += n;					\
  } while (0)

#define IPFIX_VALUE_U8_COND(v, n, c)	\
  to_b->data[offset++] = (c) ? (v) : 0

#define IPFIX_VALUE_U16(v, n, c)				\
  do {								\
    u16 tmp = clib_host_to_net_u16 (v);				\
    clib_memcpy_fast (to_b->data + offset, &tmp, sizeof (u16));	\
    offset += sizeof (u16);					\
  } while (0)

#define IPFIX_VALUE_U16_COND(v, n, c)				\
  do {								\
    u16 tmp = (c) ? clib_host_to_net_u16 (v) : 0;		\
    clib_memcpy_fast (to_b->data + offset, &tmp, sizeof (u16));	\
    offset += sizeof (u16);					\
  } while (0)

#define IPFIX_VALUE_U32(v, n, c)				\
  do {								\
    u64 tmp = clib_host_to_net_u32 (v);				\
    clib_memcpy_fast (to_b->data + offset, &tmp, sizeof (u32));	\
    offset += sizeof (u32);					\
  } while (0)

#define IPFIX_VALUE_U64(v, n, c)				\
  do {								\
    u64 tmp = clib_host_to_net_u64 (v);				\
    clib_memcpy_fast (to_b->data + offset, &tmp, sizeof (u64));	\
    offset += sizeof (u64);					\
  } while (0)

#define IPFIX_VALUE_DELTA_U64(v, n, c)				\
  do {								\
    u64 tmp = clib_host_to_net_u64 (v);				\
    clib_memcpy_fast (to_b->data + offset, &tmp, sizeof (u64));	\
    offset += sizeof (u64);					\
    v = 0;							\
  } while (0)

#define IPFIX_VALUE_NSEC(v, n, c)				\
  do {								\
    u32 tmp = clib_host_to_net_u32((v).sec + NTP_TIMESTAMP);	\
    clib_memcpy_fast (to_b->data + offset, &tmp, sizeof (u32));	\
    offset += sizeof (u32);					\
    tmp = clib_host_to_net_u32((v).nsec);			\
    clib_memcpy_fast (to_b->data + offset, &tmp, sizeof (u32));	\
    offset += sizeof (u32);					\
  } while (0)

#define IPFIX_VALUE_MOBILE_IMSI(v, n, c)		\
  do {							\
    uword l = tbcd_len (v, n);				\
    to_b->data[offset++] = l;				\
    decode_tbcd (v, n, to_b->data + offset, l);		\
    offset += l;					\
  } while (0)

#define IPFIX_VALUE_STRING(v, n, c)			\
  do {							\
    u64 l = clib_min(255, vec_len (v));			\
    to_b->data[offset++] = (u8) l;			\
    if (l)						\
      clib_memcpy_fast (to_b->data + offset, v, l);	\
    offset += l;					\
  } while (0)

#define IPFIX_FIELD_SOURCE_IPV4_ADDRESS(F)			\
  F(sourceIPv4Address, 4,					\
    IPFIX_VALUE_MEMCPY_DIRECT,					\
    &f->key.ip[FT_ORIGIN ^ f->is_reverse ^ direction].ip4,	\
    sizeof(ip4_address_t), 1)
#define IPFIX_FIELD_SOURCE_IPV6_ADDRESS(F)			\
  F(sourceIPv6Address, 16,					\
    IPFIX_VALUE_MEMCPY_DIRECT,					\
    &f->key.ip[FT_ORIGIN ^ f->is_reverse ^ direction].ip6,	\
    sizeof(ip6_address_t), 1)
#define IPFIX_FIELD_DESTINATION_IPV4_ADDRESS(F)			\
  F(destinationIPv4Address, 4,					\
    IPFIX_VALUE_MEMCPY_DIRECT,					\
    &f->key.ip[FT_REVERSE ^ f->is_reverse ^ direction].ip4,	\
    sizeof(ip4_address_t), 1)
#define IPFIX_FIELD_DESTINATION_IPV6_ADDRESS(F)			\
  F(destinationIPv6Address, 16,					\
    IPFIX_VALUE_MEMCPY_DIRECT,					\
    &f->key.ip[FT_REVERSE ^ f->is_reverse ^ direction].ip6,	\
    sizeof(ip6_address_t), 1)
#define IPFIX_FIELD_PROTOCOL_IDENTIFIER(F)			\
  F(protocolIdentifier, 1,					\
    IPFIX_VALUE_DIRECT, f->key.proto, 1, 1)
#define IPFIX_FIELD_MOBILE_IMSI(F)				\
  F(455, 65535,							\
    IPFIX_VALUE_MOBILE_IMSI,					\
    sx->user_id.imsi, sx->user_id.imsi_len, 1)
#define IPFIX_FIELD_INITIATOR_PACKETS(F)			\
  F(initiatorPackets, 8,					\
    IPFIX_VALUE_DELTA_U64,					\
    flow_stats(f, FT_ORIGIN).pkts_unreported,			\
    sizeof(u64), 1)
#define IPFIX_FIELD_RESPONDER_PACKETS(F)			\
  F(responderPackets, 8,					\
    IPFIX_VALUE_DELTA_U64,					\
    flow_stats(f, FT_REVERSE).pkts_unreported,			\
    sizeof(u64), 1)
#define IPFIX_FIELD_INITIATOR_OCTETS(F)				\
  F(initiatorOctets, 8,						\
    IPFIX_VALUE_DELTA_U64,					\
    flow_stats(f, FT_ORIGIN).l4_bytes_unreported,		\
    sizeof(u64), 1)
#define IPFIX_FIELD_RESPONDER_OCTETS(F)				\
  F(responderOctets, 8,						\
    IPFIX_VALUE_DELTA_U64,					\
    flow_stats(f, FT_REVERSE).l4_bytes_unreported,		\
    sizeof(u64), 1)
#define IPFIX_FIELD_PACKET_DELTA_COUNT(F)			\
  F(packetDeltaCount, 8,					\
    IPFIX_VALUE_DELTA_U64,					\
    flow_stats(f, direction).pkts_unreported,			\
    sizeof(u64), 1)
#define IPFIX_FIELD_OCTET_DELTA_COUNT(F)			\
  F(octetDeltaCount, 8,						\
    IPFIX_VALUE_DELTA_U64,					\
    flow_stats(f, direction).bytes_unreported,			\
    sizeof(u64), 1)
#define IPFIX_FIELD_PACKET_TOTAL_COUNT(F)		       	\
  F(packetTotalCount, 8,					\
    IPFIX_VALUE_U64,						\
    flow_stats(f, direction).pkts,				\
    sizeof(u64), 1)
#define IPFIX_FIELD_OCTET_TOTAL_COUNT(F)			\
  F(octetTotalCount, 8,						\
    IPFIX_VALUE_U64,						\
    flow_stats(f, direction).bytes,				\
    sizeof (u64), 1)
#define IPFIX_FIELD_FLOW_START_NANOSECONDS(F)			\
  F(flowStartNanoseconds, 8,					\
    IPFIX_VALUE_NSEC,						\
    f->flow_start,						\
    sizeof(u32), 1)
#define IPFIX_FIELD_FLOW_END_NANOSECONDS(F)			\
  F(flowEndNanoseconds, 8,					\
    IPFIX_VALUE_NSEC,						\
    f->flow_end,						\
    sizeof(u32), 1)
#define IPFIX_FIELD_FLOW_DIRECTION(F)				\
  F(flowDirection, 1,						\
    IPFIX_VALUE_DIRECT,						\
    direction == FT_ORIGIN ? 1 : 0,				\
    1, 1)
#define IPFIX_FIELD_SOURCE_TRANSPORT_PORT(F)			\
  F(sourceTransportPort, 2,					\
    IPFIX_VALUE_MEMCPY_DIRECT,					\
    &f->key.port[FT_ORIGIN ^ f->is_reverse ^ direction],	\
    2, 1)
#define IPFIX_FIELD_DESTINATION_TRANSPORT_PORT(F)		\
  F(destinationTransportPort, 2,				\
    IPFIX_VALUE_MEMCPY_DIRECT,					\
    &f->key.port[FT_REVERSE ^ f->is_reverse ^ direction],	\
    2, 1)
#define IPFIX_FIELD_POST_NAT_IPV4_ADDRESS(F)			\
  F(postNATSourceIPv4Address, 4,				\
    IPFIX_VALUE_MEMCPY_DIRECT,					\
    &sx->nat_addr->ext_addr,					\
    sizeof (ip4_address_t), 1)
#define IPFIX_FIELD_POST_NAPT_SOURCE_TRANSPORT_PORT(F)		\
  F(postNAPTSourceTransportPort, 2,				\
    IPFIX_VALUE_U16_COND,					\
    f->nat_sport, sizeof (u16),					\
    sx->nat_addr)
#define IPFIX_FIELD_POST_NAT_SOURCE_IPV4_ADDRESS(F)		\
  F(postNATSourceIPv4Address, 4,				\
    IPFIX_VALUE_MEMCPY_DIRECT_COND,				\
    &sx->nat_addr->ext_addr,					\
    sizeof(ip4_address_t),					\
    sx->nat_addr)
#define IPFIX_FIELD_INGRESS_VRF_ID(F)				\
  F(ingressVRFID, 4,						\
    IPFIX_VALUE_U32,						\
    info->ingress_vrf_id, sizeof(u32), 1)
#define IPFIX_FIELD_EGRESS_VRF_ID(F)				\
  F(egressVRFID, 4,						\
    IPFIX_VALUE_U32,						\
    info->egress_vrf_id, sizeof(u32), 1)
#define IPFIX_FIELD_VRF_NAME(F)					\
  F(VRFname, 65535,						\
    IPFIX_VALUE_STRING,						\
    info->vrf_name, vec_len (info->vrf_name), 1)
#define IPFIX_FIELD_INTERFACE_NAME(F)				\
  F(interfaceName, 65535,					\
    IPFIX_VALUE_STRING,						\
    info->interface_name,					\
    vec_len (info->interface_name), 1)
#define IPFIX_FIELD_OBSERVATION_DOMAIN_NAME(F)			\
  F(observationDomainName, 65535,				\
    IPFIX_VALUE_STRING,						\
    info->observation_domain_name, 				\
    vec_len (info->observation_domain_name), 1)
#define IPFIX_FIELD_OBSERVATION_POINT_ID(F)			\
  F(observationPointId, 8,					\
    IPFIX_VALUE_U64,						\
    info->observation_point_id,					\
    sizeof(u64), 1)

#define UPF_NAT_EVENT_NAT44_SESSION_CREATE 4
#define UPF_NAT_EVENT_NAT44_SESSION_DELETE 5
#define IPFIX_FIELD_NAT_EVENT(F)				\
  F(natEvent, 1,						\
    IPFIX_VALUE_U8_COND,					\
    !f->exported ? UPF_NAT_EVENT_NAT44_SESSION_CREATE :		\
    last ? UPF_NAT_EVENT_NAT44_SESSION_DELETE : 0,		\
    sizeof (u8), 1)

#define IPFIX_FIELD(fieldName, specLen, valCopy, v, n, c)	\
  do {								\
    f->e_id_length = ipfix_e_id_length (0, fieldName, specLen);	\
    f++;							\
  } while (0);

#define IPFIX_VALUE(fieldName, specLen, valCopy, v, n, c)	\
  valCopy(v, n, c);

#define IPFIX_COUNT(fieldName, specLen, valCopy, v, n, c) 1 +

#define IPFIX_TEMPLATE_COUNT(T1, T2) 		\
  (T1(IPFIX_COUNT) T2(IPFIX_COUNT) 0)
#define IPFIX_TEMPLATE_FIELDS(T1, T2)		\
  T1 (IPFIX_FIELD);				\
  T2 (IPFIX_FIELD);				\
  return f
#define IPFIX_TEMPLATE_VALUES(T1, T2)		\
  u16 start = offset;				\
  T1 (IPFIX_VALUE);				\
  T2 (IPFIX_VALUE);				\
  return offset - start

#endif
