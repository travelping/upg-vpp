/*
 * Copyright (c) 2017-2019 Travelping GmbH
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

#include <math.h>
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <inttypes.h>
#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/pool.h>
#include <vppinfra/sparse_vec.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <search.h>
#include <netinet/ip.h>
#include <vlib/unix/plugin.h>

#include "pfcp.h"
#include "upf.h"
#include "upf_app_db.h"
#include "upf_pfcp.h"
#include "upf_pfcp_api.h"
#include "upf_pfcp_server.h"
#include "upf_ipfilter.h"
#include "upf_ipfix.h"

// static_always_inline nat_translation_error_e
// nat_6t_flow_buf_translate (vlib_main_t *vm, snat_main_t *sm, vlib_buffer_t
// *b,
//                            ip4_header_t *ip, nat_6t_flow_t *f,
//                            ip_protocol_t proto, int is_output_feature,
//                            int is_i2o)
// {
//   if (!is_output_feature && f->ops & NAT_FLOW_OP_TXFIB_REWRITE)
//     {
//       vnet_buffer (b)->sw_if_index[VLIB_TX] = f->rewrite.fib_index;
//     }
//
//   if (IP_PROTOCOL_ICMP == proto)
//     {
//       if (ip->src_address.as_u32 != f->rewrite.saddr.as_u32)
//         {
//           // packet is returned from a router, not from destination
//           // skip source address rewrite if in o2i path
//           nat_6t_flow_ip4_translate (sm, b, ip, f, proto,
//                                      0 /* is_icmp_inner_ip4 */,
//                                      !is_i2o /* skip_saddr_rewrite */);
//         }
//       else
//         {
//           nat_6t_flow_ip4_translate (sm, b, ip, f, proto,
//                                      0 /* is_icmp_inner_ip4 */,
//                                      0 /* skip_saddr_rewrite */);
//         }
//       return nat_6t_flow_icmp_translate (vm, sm, b, ip, f);
//     }
//
//   nat_6t_flow_ip4_translate (sm, b, ip, f, proto, 0 /* is_icmp_inner_ip4 */,
//                              0 /* skip_saddr_rewrite */);
//
//   return NAT_ED_TRNSL_ERR_SUCCESS;
// }
//
// void
// nat_6t_l3_l4_csum_calc (nat_6t_flow_t *f)
// {
//   f->l3_csum_delta = 0;
//   f->l4_csum_delta = 0;
//   if (f->ops & NAT_FLOW_OP_SADDR_REWRITE &&
//       f->rewrite.saddr.as_u32 != f->match.saddr.as_u32)
//     {
//       f->l3_csum_delta =
// 	ip_csum_add_even (f->l3_csum_delta, f->rewrite.saddr.as_u32);
//       f->l3_csum_delta =
// 	ip_csum_sub_even (f->l3_csum_delta, f->match.saddr.as_u32);
//     }
//   else
//     {
//       f->rewrite.saddr.as_u32 = f->match.saddr.as_u32;
//     }
//   if (f->ops & NAT_FLOW_OP_DADDR_REWRITE &&
//       f->rewrite.daddr.as_u32 != f->match.daddr.as_u32)
//     {
//       f->l3_csum_delta =
// 	ip_csum_add_even (f->l3_csum_delta, f->rewrite.daddr.as_u32);
//       f->l3_csum_delta =
// 	ip_csum_sub_even (f->l3_csum_delta, f->match.daddr.as_u32);
//     }
//   else
//     {
//       f->rewrite.daddr.as_u32 = f->match.daddr.as_u32;
//     }
//   if (f->ops & NAT_FLOW_OP_SPORT_REWRITE && f->rewrite.sport !=
//   f->match.sport)
//     {
//       f->l4_csum_delta = ip_csum_add_even (f->l4_csum_delta,
//       f->rewrite.sport); f->l4_csum_delta = ip_csum_sub_even
//       (f->l4_csum_delta, f->match.sport);
//     }
//   else
//     {
//       f->rewrite.sport = f->match.sport;
//     }
//   if (f->ops & NAT_FLOW_OP_DPORT_REWRITE && f->rewrite.dport !=
//   f->match.dport)
//     {
//       f->l4_csum_delta = ip_csum_add_even (f->l4_csum_delta,
//       f->rewrite.dport); f->l4_csum_delta = ip_csum_sub_even
//       (f->l4_csum_delta, f->match.dport);
//     }
//   else
//     {
//       f->rewrite.dport = f->match.dport;
//     }
//   if (f->ops & NAT_FLOW_OP_ICMP_ID_REWRITE &&
//       f->rewrite.icmp_id != f->match.sport)
//     {
//       f->l4_csum_delta =
// 	ip_csum_add_even (f->l4_csum_delta, f->rewrite.icmp_id);
//       f->l4_csum_delta = ip_csum_sub_even (f->l4_csum_delta,
//       f->match.sport);
//     }
//   else
//     {
//       f->rewrite.icmp_id = f->match.sport;
//     }
//   if (f->ops & NAT_FLOW_OP_TXFIB_REWRITE)
//     {
//     }
//   else
//     {
//       f->rewrite.fib_index = f->match.fib_index;
//     }
// }
//
//
//
