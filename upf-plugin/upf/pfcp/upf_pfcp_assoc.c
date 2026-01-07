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

#include <stdio.h>
#include <inttypes.h>
#include <search.h>
#include <netinet/ip.h>

#include <vlib/unix/plugin.h>
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

#include "upf/upf.h"
#include "upf/upf_stats.h"
#include "upf/pfcp/pfcp_proto.h"
#include "upf/pfcp/upf_pfcp_assoc.h"
#include "upf/pfcp/upf_pfcp_server.h"
#include "upf/utils/upf_timer.h"
#include "upf/upf_limits.h"

#define UPF_DEBUG_ENABLE 0

upf_assoc_t *
upf_assoc_get_by_nodeid (pfcp_ie_node_id_t *node_id)
{
  upf_main_t *um = &upf_main;
  uword *p = NULL;

  switch (node_id->type)
    {
    case PFCP_NID_IPv4:
    case PFCP_NID_IPv6:
      p = mhash_get (&um->assoc_index_by_ip, &node_id->ip);
      break;

    case PFCP_NID_FQDN:
      p = hash_get_mem (um->assoc_index_by_fqdn, node_id->fqdn);
      break;
    }

  if (!p)
    return 0;

  upf_assoc_t *assoc = pool_elt_at_index (um->assocs, p[0]);
  if (assoc->is_released)
    return 0;

  return assoc;
}

upf_assoc_t *
upf_assoc_create (session_handle_t session_handle, ip46_address_t *lcl_addr,
                  ip46_address_t *rmt_addr, pfcp_ie_node_id_t *node_id)
{
  upf_main_t *um = &upf_main;
  upf_assoc_t *assoc;

  pool_get_aligned_zero (um->assocs, assoc, CLIB_CACHE_LINE_BYTES);
  upf_assoc_sessions_list_init (&assoc->sessions);
  upf_assoc_requests_list_init (&assoc->requests);
  upf_smfset_assocs_list_anchor_init (assoc);
  assoc->smf_set.id = ~0;
  assoc->node_id = *node_id;
  assoc->session_handle = session_handle;
  assoc->lcl_addr = *lcl_addr;
  assoc->rmt_addr = *rmt_addr;

  switch (node_id->type)
    {
    case PFCP_NID_IPv4:
    case PFCP_NID_IPv6:
      mhash_set (&um->assoc_index_by_ip, &node_id->ip, assoc - um->assocs,
                 NULL);
      break;

    case PFCP_NID_FQDN:
      assoc->node_id.fqdn = vec_dup (node_id->fqdn);
      hash_set_mem (um->assoc_index_by_fqdn, assoc->node_id.fqdn,
                    assoc - um->assocs);
      break;
    }

  upf_stats_get_generic ()->associations_count += 1;

  vlib_log_info (um->log_class,
                 "PFCP Association established: node %U, local IP %U, remote "
                 "IP %U (UDP session handle %d)\n",
                 format_pfcp_ie_node_id, &assoc->node_id, format_ip46_address,
                 &assoc->lcl_addr, IP46_TYPE_ANY, format_ip46_address,
                 &assoc->rmt_addr, IP46_TYPE_ANY, session_handle);
  return assoc;
}

void
upf_assoc_delete (upf_assoc_t *assoc, const char *reason)
{
  upf_main_t *um = &upf_main;
  u32 assoc_id = assoc - um->assocs;
  upf_assoc_sessions_list_t *sessions = &assoc->sessions;
  u32 *smf_alt_node_ids = NULL;
  pfcp_server_main_t *psm = &pfcp_server_main;

  // caller should be aware of state
  ASSERT (!assoc->is_released);

  vlib_log_info (um->log_class,
                 "PFCP Association released: node %U, local IP %U, remote IP "
                 "%U, reason: %s\n",
                 format_pfcp_ie_node_id, &assoc->node_id, format_ip46_address,
                 &assoc->lcl_addr, IP46_TYPE_ANY, format_ip46_address,
                 &assoc->rmt_addr, IP46_TYPE_ANY, reason);

  assoc->is_released = true;
  upf_timer_stop_safe (0, &assoc->heartbeat_timer);

  switch (assoc->node_id.type)
    {
    case PFCP_NID_IPv4:
    case PFCP_NID_IPv6:
      mhash_unset (&um->assoc_index_by_ip, &assoc->node_id.ip, NULL);
      break;

    case PFCP_NID_FQDN:
      hash_unset_mem (um->assoc_index_by_fqdn, assoc->node_id.fqdn);
      vec_free (assoc->node_id.fqdn);
      break;
    }

  if (is_valid_id (assoc->smf_set.id))
    {
      smf_alt_node_ids = pfcp_assoc_exit_smf_set (assoc);
#if UPF_DEBUG_ENABLE > 0
      u32 *set_node_id;
      vec_foreach (set_node_id, smf_alt_node_ids)
        {
          upf_assoc_t *assoc = pool_elt_at_index (um->assocs, *set_node_id);
          upf_debug ("smf_set remaining %d node: %U",
                     (u32) (assoc - um->assocs), format_pfcp_ie_node_id,
                     &assoc->node_id);
        }
#endif
    }

  if (vec_len (smf_alt_node_ids))
    {
      /* migrate sessions to peers in smf set */
      u32 alt_node_count = vec_len (smf_alt_node_ids);
      u32 rand_seed = unix_time_now_nsec ();

      upf_llist_foreach (sx, um->sessions, assoc.anchor, sessions)
        {
          ASSERT (sx->assoc.id == assoc_id);

          u32 random_idx = random_u32 (&rand_seed) % alt_node_count;
          u32 new_assoc_id = vec_elt (smf_alt_node_ids, random_idx);
          upf_assoc_t *new_assoc =
            pool_elt_at_index (um->assocs, new_assoc_id);

          sx->is_lost_smfset_cp = 1;

          sx->assoc.id = new_assoc_id;
          upf_assoc_sessions_list_remove (um->sessions, &assoc->sessions, sx);
          upf_assoc_sessions_list_insert_tail (um->sessions,
                                               &new_assoc->sessions, sx);

          /* mark all in-flight session requests */
          upf_llist_foreach (req, pfcp_server_main.requests, session.anchor,
                             &sx->requests)
            {
              req->flags.is_migrated_in_smfset = 1;
              req->assoc.id = new_assoc_id;
              upf_assoc_requests_list_remove (psm->requests, &assoc->requests,
                                              req);
              upf_assoc_requests_list_insert_tail (psm->requests,
                                                   &new_assoc->requests, req);
            };
        };

      ASSERT (upf_assoc_sessions_list_is_empty (sessions));
    }
  vec_free (smf_alt_node_ids);

  /* remove report requests and echo requests */
  upf_llist_foreach (req, psm->requests, assoc.anchor, &assoc->requests)
    {
      ASSERT (req->assoc.id == assoc_id);
      upf_pfcp_request_delete (req);
    };

  /* remove sessions */
  upf_llist_foreach (sx, um->sessions, assoc.anchor, sessions)
    {
      ASSERT (sx->assoc.id == assoc_id);

      upf_session_trigger_deletion (
        sx, UPF_SESSION_TERMINATION_REASON_ASSOCIATION_LOST);
    };

  if (upf_assoc_sessions_list_is_empty (sessions))
    pool_put (um->assocs, assoc);

  upf_stats_get_generic ()->associations_count -= 1;
}

u32
pfcp_new_smf_set (u8 *fqdn)
{
  upf_main_t *um = &upf_main;
  upf_smf_set_t *smfs;
  u32 smfs_idx;

  ASSERT (pool_elts (um->smf_sets) < UPF_LIMIT_MAX_SMFSETS);

  pool_get_zero (um->smf_sets, smfs);
  smfs->fqdn = vec_dup (fqdn);
  upf_smfset_assocs_list_init (&smfs->nodes);

  smfs_idx = smfs - um->smf_sets;
  hash_set_mem (um->smf_set_by_fqdn, smfs->fqdn, smfs_idx);

  upf_debug ("new smf set %U", format_pfcp_dns_labels, smfs->fqdn);

  return smfs_idx;
}

bool
pfcp_can_ensure_smf_set (u8 *fqdn)
{
  upf_main_t *um = &upf_main;
  ASSERT (fqdn);

  uword *smfs_idx = hash_get_mem (um->smf_set_by_fqdn, fqdn);
  if (smfs_idx)
    return true;

  return pool_elts (um->smf_sets) < UPF_LIMIT_MAX_SMFSETS;
}

u32
pfcp_ensure_smf_set (u8 *fqdn)
{
  upf_main_t *um = &upf_main;
  ASSERT (fqdn);

  uword *smfs_idx = hash_get_mem (um->smf_set_by_fqdn, fqdn);
  if (smfs_idx)
    return *smfs_idx;
  else
    return pfcp_new_smf_set (fqdn);
}

void
pfcp_free_smf_set (upf_smf_set_t *smfs)
{
  upf_main_t *um = &upf_main;

  ASSERT (upf_llist_list_is_empty (&smfs->nodes));
  vec_free (smfs->fqdn);

  pool_put (um->smf_sets, smfs);
}

void
pfcp_assoc_enter_smf_set (upf_assoc_t *assoc, u8 *fqdn)
{
  upf_main_t *um = &upf_main;

  ASSERT (fqdn);
  ASSERT (!is_valid_id (assoc->smf_set.id));

  u32 smfs_idx = pfcp_ensure_smf_set (fqdn);

  upf_smf_set_t *smfs = pool_elt_at_index (um->smf_sets, smfs_idx);

  upf_smfset_assocs_list_insert_tail (um->assocs, &smfs->nodes, assoc);
  assoc->smf_set.id = smfs_idx;

  upf_debug ("node %d %U entered set %U", assoc - um->assocs,
             format_pfcp_ie_node_id, &assoc->node_id, format_pfcp_dns_labels,
             smfs->fqdn);
}

/* returns vector of alternative node indexes */
u32 *
pfcp_assoc_exit_smf_set (upf_assoc_t *n)
{
  upf_main_t *um = &upf_main;
  u32 *alternatives = NULL;
  ASSERT (is_valid_id (n->smf_set.id));

  upf_smf_set_t *smfs = pool_elt_at_index (um->smf_sets, n->smf_set.id);

  upf_smfset_assocs_list_remove (um->assocs, &smfs->nodes, n);
  n->smf_set.id = ~0;

  if (upf_smfset_assocs_list_is_empty (&smfs->nodes))
    {
      pfcp_free_smf_set (smfs);
      return NULL;
    }
  else
    {
      upf_llist_foreach (el, um->assocs, smf_set.anchor, &smfs->nodes)
        vec_add1 (alternatives, el - um->assocs);
      return alternatives;
    }
}

static u8 *
format_time_stamp (u8 *s, va_list *args)
{
  u32 *v = va_arg (*args, u32 *);
  struct timeval tv = { .tv_sec = *v, .tv_usec = 0 };

  return format (s, "%U", format_timeval, NULL, &tv);
}

u8 *
format_upf_assoc (u8 *s, va_list *args)
{
  upf_assoc_t *assoc = va_arg (*args, upf_assoc_t *);
  u8 verbose = va_arg (*args, int);
  upf_main_t *um = &upf_main;
  upf_assoc_sessions_list_t *sessions = &assoc->sessions;
  u32 i = 0;

  if (assoc->is_released)
    s = format (s, " (REMOVING)");

  s = format (s,
              "Node: %U "
              "  Recovery Time Stamp: %U",
              format_pfcp_ie_node_id, &assoc->node_id, format_time_stamp,
              &assoc->recovery_time_stamp);

  if (verbose)
    s = format (s, "\n Sessions:\n", i);

  upf_llist_foreach (sx, um->sessions, assoc.anchor, sessions)
    {
      if (verbose)
        {
          if (i > 0 && (i % 8) == 0)
            s = format (s, "\n            ");

          s = format (s, " 0x%016" PRIx64, sx->up_seid);
        }

      i++;
    };

  if (verbose)
    s = format (s, "\nTotal sessions: %u", i);
  else
    s = format (s, " Sessions: %u", i);

  return s;
}

u8 *
format_pfcp_endpoint_key (u8 *s, va_list *args)
{
  upf_pfcp_endpoint_key_t *key = va_arg (*args, upf_pfcp_endpoint_key_t *);

  s = format (s, "%U [@%u]", format_ip46_address, &key->addr, IP46_TYPE_ANY,
              key->fib_index);

  return s;
}
