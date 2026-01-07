/*
 * Copyright (c) 2020-2025 Travelping GmbH
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

#ifndef UPF_RULES_UPF_CLASSIFY_INLINES_H_
#define UPF_RULES_UPF_CLASSIFY_INLINES_H_

#include <vnet/ip/ip.h>

#include "upf/upf.h"
#include "upf/utils/ip_mask.h"
#include "upf/adf/matcher.h"
#include "upf/rules/upf_classify.h"

#define UPF_DEBUG_ENABLE 0

static_always_inline bool
_upf_packet_match_pdr_acl4 (rules_acl4_t *acl4, ip4_address_t *ue_ip,
                            ip4_address_t *rmt_ip, u16 ue_port, u16 rmt_port,
                            u8 ip_proto, bool ue_ip_is_assigned)
{
  ASSERT (acl4->ue_ip_mask < ARRAY_LEN (ip4_mask_by_prefix));
  ASSERT (acl4->rmt_ip_mask < ARRAY_LEN (ip4_mask_by_prefix));

  ip4_address_t ue_masked = {
    .as_u32 = ue_ip->data_u32 & ip4_mask_by_prefix[acl4->ue_ip_mask].as_u32
  };
  ip4_address_t rmt_masked = {
    .as_u32 = rmt_ip->data_u32 & ip4_mask_by_prefix[acl4->rmt_ip_mask].as_u32
  };

  bool ip_ue_ok;
  if (PREDICT_TRUE (acl4->ue_ip_is_assigned)) // almost always the case
    ip_ue_ok = ue_ip_is_assigned;
  else
    ip_ue_ok = ip4_address_is_equal (&ue_masked, &acl4->ip[UPF_EL_UE]);

  bool ip_rmt_ok = ip4_address_is_equal (&rmt_masked, &acl4->ip[UPF_EL_RMT]);

  upf_debug ("ue  %U/%d => %U == %U || (is %d == want %d) - %s",
             format_ip4_address, ue_ip, acl4->ue_ip_mask, format_ip4_address,
             &ue_masked, format_ip4_address, &acl4->ip[UPF_EL_UE],
             ue_ip_is_assigned ? 1 : 0, acl4->ue_ip_is_assigned,
             ip_ue_ok ? "ok" : "fail");
  upf_debug ("rmt %U/%d => %U == %U  - %s", format_ip4_address, rmt_ip,
             acl4->rmt_ip_mask, format_ip4_address, &rmt_masked,
             format_ip4_address, &acl4->ip[UPF_EL_RMT],
             ip_rmt_ok ? "ok" : "fail");

  if (!ip_ue_ok || !ip_rmt_ok)
    return false;

  if (acl4->do_match_ip_proto && ip_proto != acl4->ip_proto)
    return false;

  if (ue_port < acl4->port_min[0] || ue_port > acl4->port_max[0] ||
      rmt_port < acl4->port_min[1] || rmt_port > acl4->port_max[1])
    return false;

  return true;
}

static_always_inline bool
_upf_packet_match_pdr_acl6 (rules_acl6_t *acl6, ip6_address_t *ue_ip,
                            ip6_address_t *rmt_ip, u16 ue_port, u16 rmt_port,
                            u8 ip_proto, bool ue_ip_is_assigned)
{
  ip6_address_t ue_masked = *ue_ip;
  ip6_address_t rmt_masked = *rmt_ip;

  ASSERT (acl6->ue_ip_mask < ARRAY_LEN (ip6_mask_by_prefix));
  ASSERT (acl6->rmt_ip_mask < ARRAY_LEN (ip6_mask_by_prefix));

  ip6_address_mask (&ue_masked, &ip6_mask_by_prefix[acl6->ue_ip_mask]);
  ip6_address_mask (&rmt_masked, &ip6_mask_by_prefix[acl6->rmt_ip_mask]);

  bool ip_ue_ok;
  if (PREDICT_TRUE (acl6->ue_ip_is_assigned)) // almost always the case
    ip_ue_ok = ue_ip_is_assigned;
  else
    ip_ue_ok = ip6_address_is_equal (&ue_masked, &acl6->ip[UPF_EL_UE]);

  bool ip_rmt_ok = ip6_address_is_equal (&rmt_masked, &acl6->ip[UPF_EL_RMT]);

  upf_debug ("ue  %U/%d => %U == %U (is %d == want %d) - %s",
             format_ip6_address, ue_ip, acl6->ue_ip_mask, format_ip6_address,
             &ue_masked, format_ip6_address, &acl6->ip[0],
             ue_ip_is_assigned ? 1 : 0, acl6->ue_ip_is_assigned,
             ip_ue_ok ? "ok" : "fail");
  upf_debug ("rmt %U/%d => %U == %U - %s", format_ip6_address, rmt_ip,
             acl6->rmt_ip_mask, format_ip6_address, &rmt_masked,
             format_ip6_address, &acl6->ip[1], ip_rmt_ok ? "ok" : "fail");

  if (!ip_ue_ok || !ip_rmt_ok)
    return false;

  if (acl6->do_match_ip_proto && ip_proto != acl6->ip_proto)
    return false;

  if (ue_port < acl6->port_min[0] || ue_port > acl6->port_max[0] ||
      rmt_port < acl6->port_min[1] || rmt_port > acl6->port_max[1])
    return false;

  return true;
}

static_always_inline bool
_upf_packet_match_pdr_acls4 (rules_pdr_t *pdr, ip4_address_t *ue_ip,
                             ip4_address_t *rmt_ip, u16 ue_port, u16 rmt_port,
                             u8 ip_proto, bool ue_ip_is_assigned)
{
  upf_main_t *um = &upf_main;

  ASSERT (pdr->can_recv_ip4);

  // If we do not have acls, then match any traffic.
  // This is needed in cases:
  // - gtp proxy - matching done by gtpu tunnel
  // - with application id - matching will be done by application
  if (PREDICT_FALSE (!pdr->acls4.len))
    {
      upf_debug ("match any hit");
      return true;
    }

  upf_hh_foreach (acl, um->heaps.acls4, &pdr->acls4)
    {
      if (_upf_packet_match_pdr_acl4 (acl, ue_ip, rmt_ip, ue_port, rmt_port,
                                      ip_proto, ue_ip_is_assigned))
        return true;
    }

  return false;
}

static_always_inline bool
_upf_packet_match_pdr_acls6 (rules_pdr_t *pdr, ip6_address_t *ue_ip,
                             ip6_address_t *rmt_ip, u16 ue_port, u16 rmt_port,
                             u8 ip_proto, bool ue_ip_is_assigned)
{
  upf_main_t *um = &upf_main;

  ASSERT (pdr->can_recv_ip6);

  // if we do not have acls, then match any
  if (PREDICT_FALSE (!pdr->acls6.len))
    {
      upf_debug ("match any hit");
      return true;
    }

  upf_hh_foreach (acl, um->heaps.acls6, &pdr->acls6)
    {
      if (_upf_packet_match_pdr_acl6 (acl, ue_ip, rmt_ip, ue_port, rmt_port,
                                      ip_proto, ue_ip_is_assigned))
        return true;
    }

  return false;
}

static_always_inline bool
_upf_packet_match_pdr_acls (rules_pdr_t *pdr, void *ue_ip, void *rmt_ip,
                            u16 ue_port, u16 rmt_port, u8 ip_proto,
                            bool ue_ip_is_assigned, bool is_ip4)
{
  if (is_ip4)
    return _upf_packet_match_pdr_acls4 (pdr, ue_ip, rmt_ip, ue_port, rmt_port,
                                        ip_proto, ue_ip_is_assigned);
  else
    return _upf_packet_match_pdr_acls6 (pdr, ue_ip, rmt_ip, ue_port, rmt_port,
                                        ip_proto, ue_ip_is_assigned);
}

__clib_warn_unused_result static_always_inline adf_result_t
_upf_classify_app_internal (rules_pdr_t *pdr, void *ue_ip, void *rmt_ip,
                            u8 ip_proto, u16 ue_port, u16 rmt_port,
                            bool is_ip4, bool has_uri, u8 *uri,
                            bool ue_ip_is_assigned)
{
  upf_main_t *um = &upf_main;

  upf_adf_app_t *app =
    pool_elt_at_index (upf_main.adf_main.apps, pdr->application_id);

  if (!is_valid_id (app->active_ver_idx))
    {
      upf_debug ("app match no commited application version");
      return ADR_FAIL;
    }

  upf_adf_app_version_t *ver =
    pool_elt_at_index (um->adf_main.versions, app->active_ver_idx);

  // by default fail if there are no IP or URI application rules
  bool matched = false;

  if (!ver->app_dpos)
    upf_debug ("app match no app dpos");
  else
    {
      ip4_address_t *ue_addr4 = ue_ip, *rmt_addr4 = rmt_ip;
      ip6_address_t *ue_addr6 = ue_ip, *rmt_addr6 = rmt_ip;

      if (is_ip4)
        {
          if (!upf_adf_ip_match4 (ver, ue_addr4, rmt_addr4, ue_port, rmt_port,
                                  ue_ip_is_assigned))
            return ADR_FAIL;
        }
      else
        {
          if (!upf_adf_ip_match6 (ver, ue_addr6, rmt_addr6, ue_port, rmt_port,
                                  ue_ip_is_assigned))
            return ADR_FAIL;
        }
      matched = true; // at least IP rules matched
    }

  if (ver->database != NULL)
    {
      // HTTP app detection needed
      if (ip_proto != IP_PROTOCOL_TCP)
        return ADR_FAIL;

      if (!has_uri)
        return ADR_NEED_MORE_DATA;

      upf_adf_app_t *app =
        pool_elt_at_index (um->adf_main.apps, pdr->application_id);

      matched = upf_adf_app_match_regex (app, uri, vec_len (uri), NULL);
      upf_debug ("Matched URI %v: matched=%d", uri, matched);
    }

  return matched ? ADR_OK : ADR_FAIL;
}

static_always_inline bool
_upf_classify_is_assigned (rules_tep_t *tep, void *ip, bool is_ip4)
{
  ip4_address_t *addr4 = ip;
  ip6_address_t *addr6 = ip;

  if (is_ip4)
    {
      if (tep->is_ue_ip4)
        // TODO: only /32 supported, support custom /xx
        return (tep->ue_addr4.as_u32 == addr4->as_u32);
      else if (!tep->is_ue_ip6)
        return true; // no ue ip at all
      else
        return false; // ue ip6 only
    }
  else
    {
      if (tep->is_ue_ip6)
        // compare only first 64 bytes, since we support only /64
        // networks
        return (tep->ue_addr6.as_u64[0] == addr6->as_u64[0]);
      else if (!tep->is_ue_ip4)
        return true; // no ue ip at all
      else
        return false; // ue ip4 only
    }
}

__clib_warn_unused_result static_always_inline bool
_upf_classify_pdr (rules_pdr_t *pdr, void *ue_ip, void *rmt_ip, u8 ip_proto,
                   u16 ue_port, u16 rmt_port, bool is_ip4,
                   bool ue_ip_is_assigned, bool has_uri, u8 *uri,
                   bool *need_more_data, u32 *result_app_id)
{
  bool acls_match =
    _upf_packet_match_pdr_acls (pdr, ue_ip, rmt_ip, ue_port, rmt_port,
                                ip_proto, ue_ip_is_assigned, is_ip4);

  if (!acls_match)
    // if not matched acls
    return false;

  if (PREDICT_TRUE (!is_valid_id (pdr->application_id)))
    // no application is configured
    return true;

  adf_result_t app_r = _upf_classify_app_internal (
    pdr, ue_ip, rmt_ip, ip_proto, ue_port, rmt_port, is_ip4, has_uri, uri,
    ue_ip_is_assigned);

  if (app_r == ADR_OK)
    {
      *result_app_id = pdr->application_id;
      return true;
    }

  if (app_r == ADR_NEED_MORE_DATA)
    *need_more_data = true;

  // application which needs more data should use next matching pdr
  return false;
}

__clib_unused __clib_warn_unused_result static_always_inline classify_result_t
_upf_classify_internal (upf_rules_t *rules, void *ue_ip, void *rmt_ip,
                        u8 ip_proto, u16 ue_port, u16 rmt_port,
                        upf_lidset_t pdr_lids, bool is_uplink, bool is_ip4,
                        bool has_uri, u8 *uri, upf_pdr_lid_t *result_pdr_lid,
                        u32 *result_app_id)
{
#ifdef CLIB_ASSERT_ENABLE
  u32 last_precedence = 0; // for sorting test
#endif

  upf_debug ("pdrs list %U", format_upf_lidset, &pdr_lids);

  bool need_more_data = false;

  upf_lidset_foreach (pdr_lid, &pdr_lids)
    {
      rules_pdr_t *pdr = upf_rules_get_pdr (rules, pdr_lid);
      rules_tep_t *tep = upf_rules_get_tep (rules, pdr->traffic_ep_lid);
      bool ue_ip_is_assigned = _upf_classify_is_assigned (tep, ue_ip, is_ip4);

#ifdef CLIB_ASSERT_ENABLE
      ASSERT (last_precedence <= pdr->precedence);
      last_precedence = pdr->precedence;
#endif

      ASSERT (is_ip4 ? pdr->can_recv_ip4 : pdr->can_recv_ip6);
      ASSERT (pdr->is_uplink == is_uplink);

      upf_debug (
        "ue_ip_is_assigned %d %U == %U is_ul=%d can_ip4=%d can_ip6=%d",
        ue_ip_is_assigned, is_ip4 ? format_ip4_address : format_ip6_address,
        ue_ip, is_ip4 ? format_ip4_address : format_ip6_address,
        is_ip4 ? (void *) &tep->ue_addr4 : (void *) &tep->ue_addr6, is_uplink,
        pdr->can_recv_ip4, pdr->can_recv_ip6);

      if (_upf_classify_pdr (pdr, ue_ip, rmt_ip, ip_proto, ue_port, rmt_port,
                             is_ip4, ue_ip_is_assigned, has_uri, uri,
                             &need_more_data, result_app_id))
        {
          *result_pdr_lid = pdr_lid;
          return need_more_data ? CLASSIFY_OK_NEED_DPI : CLASSIFY_OK;
        }
    }

  return CLASSIFY_FAIL;
}

// return true on match
static_always_inline bool
_upf_classify_flowless_internal (upf_rules_t *rules, void *ue_ip, void *rmt_ip,
                                 u8 ip_proto, void *l4hdr,
                                 upf_lidset_t pdr_lids, bool is_uplink,
                                 bool is_ip4, upf_lid_t *result_pdr_lid)
{

#ifdef CLIB_ASSERT_ENABLE
  u32 last_precedence = 0; // for sorting test
#endif

  upf_debug ("pdrs list %U", format_upf_lidset, &pdr_lids);

  u16 ue_port = 0, rmt_port = 0;
  if (ip_proto == IP_PROTOCOL_UDP || ip_proto == IP_PROTOCOL_TCP)
    {
      udp_header_t *tcpudp = l4hdr;
      ue_port =
        clib_net_to_host_u16 (is_uplink ? tcpudp->src_port : tcpudp->dst_port);
      rmt_port =
        clib_net_to_host_u16 (is_uplink ? tcpudp->dst_port : tcpudp->src_port);
    }

  upf_lidset_foreach (pdr_lid, &pdr_lids)
    {
      rules_pdr_t *pdr = upf_rules_get_pdr (rules, pdr_lid);
      rules_tep_t *tep = upf_rules_get_tep (rules, pdr->traffic_ep_lid);
      bool ue_ip_is_assigned = _upf_classify_is_assigned (tep, ue_ip, is_ip4);

#ifdef CLIB_ASSERT_ENABLE
      ASSERT (last_precedence <= pdr->precedence);
      last_precedence = pdr->precedence;
#endif

      bool match_any_ip = !tep->is_ue_ip4 && !tep->is_ue_ip6;
      ASSERT ((is_ip4 ? tep->is_ue_ip4 : tep->is_ue_ip6) || match_any_ip);
      ASSERT (pdr->is_uplink == is_uplink);
      ASSERT (!pdr->need_http_redirect);
      ASSERT (!is_valid_id (pdr->application_id));

      if (_upf_packet_match_pdr_acls (pdr, ue_ip, rmt_ip, ue_port, rmt_port,
                                      ip_proto, ue_ip_is_assigned, is_ip4))
        {
          *result_pdr_lid = pdr_lid;
          return true;
        }
    }

  return false;
}

__clib_warn_unused_result __clib_unused static_always_inline bool
upf_classify_flowless4_inline (upf_rules_t *rules, ip4_header_t *l3hdr,
                               void *l4hdr, upf_lidset_t pdr_lids,
                               bool is_uplink, upf_lid_t *result_pdr_lid)
{
  ip4_address_t *ue_ip = is_uplink ? &l3hdr->src_address : &l3hdr->dst_address;
  ip4_address_t *rmt_ip =
    is_uplink ? &l3hdr->dst_address : &l3hdr->src_address;
  return _upf_classify_flowless_internal (rules, ue_ip, rmt_ip,
                                          l3hdr->protocol, l4hdr, pdr_lids,
                                          is_uplink, true, result_pdr_lid);
}

__clib_warn_unused_result __clib_unused static_always_inline bool
upf_classify_flowless6_inline (upf_rules_t *rules, ip6_header_t *l3hdr,
                               void *l4hdr, upf_lidset_t pdr_lids,
                               bool is_uplink, upf_lid_t *result_pdr_lid)
{
  ip6_address_t *ue_ip = is_uplink ? &l3hdr->src_address : &l3hdr->dst_address;
  ip6_address_t *rmt_ip =
    is_uplink ? &l3hdr->dst_address : &l3hdr->src_address;
  return _upf_classify_flowless_internal (rules, ue_ip, rmt_ip,
                                          l3hdr->protocol, l4hdr, pdr_lids,
                                          is_uplink, false, result_pdr_lid);
}

__clib_unused static_always_inline bool
upf_classify_flow (upf_rules_t *rules, flow_entry_t *flow,
                   upf_packet_source_t source, upf_lid_t source_lid,
                   bool is_uplink, bool is_ip4, upf_pdr_lid_t *result_pdr_lid)
{
  upf_lidset_t pdr_lids;
  switch (source)
    {
    case UPF_PACKET_SOURCE_GTPU:
      {
        rules_ep_gtpu_t *ep_gtpu = upf_rules_get_ep_gtpu (rules, source_lid);
        upf_lidset_t *ipv_pdrs_mask =
          is_ip4 ? &rules->pdr_ip4_lids : &rules->pdr_ip6_lids;
        upf_lidset_and (&pdr_lids, &ep_gtpu->pdr_lids, ipv_pdrs_mask);

        upf_debug ("using gtpu %U & ip_mask %U = %U", format_upf_lidset,
                   &ep_gtpu->pdr_lids, format_upf_lidset, &ipv_pdrs_mask,
                   format_upf_lidset, &pdr_lids);
      }
      break;
    case UPF_PACKET_SOURCE_IP:
      {
        rules_ep_ip_t *ep_ip = is_ip4 ?
                                 upf_rules_get_ep_ip4 (rules, source_lid) :
                                 upf_rules_get_ep_ip6 (rules, source_lid);
        pdr_lids = ep_ip->pdr_lids;

        upf_debug ("using ip %U", format_upf_lidset, &pdr_lids);
      };
      break;
    case UPF_PACKET_SOURCE_TCP_STACK:
    case UPF_PACKET_SOURCE_NAT:
      {
        upf_lidset_t direction_mask;
        if (is_uplink)
          direction_mask = rules->pdr_ul_lids;
        else
          upf_lidset_not (&direction_mask, &rules->pdr_ul_lids);

        upf_lidset_and (&pdr_lids, &direction_mask,
                        is_ip4 ? &rules->pdr_ip4_lids : &rules->pdr_ip6_lids);

        upf_debug ("using ul=%d ip4=%d lids %U mask %U pdr_ul_lids %U",
                   is_uplink, is_ip4, format_upf_lidset, &pdr_lids,
                   format_upf_lidset, &direction_mask, format_upf_lidset,
                   &rules->pdr_ul_lids);
      }
      break;
    default:
      ASSERT (0 && "unknown packet source");
    }

  if (flow->is_ip4)
    return upf_classify_flow4 (rules, flow, pdr_lids, is_uplink,
                               result_pdr_lid);
  else
    return upf_classify_flow6 (rules, flow, pdr_lids, is_uplink,
                               result_pdr_lid);
}

#endif // UPF_RULES_UPF_CLASSIFY_INLINES_H_
