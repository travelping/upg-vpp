/*
 * Copyright (c) 2024-2025 Travelping GmbH
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

#include "upf/upf.h"
#include "upf/upf_stats.h"

#include "upf/flow/flowtable.h"
#include "upf/utils/upf_timer.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/rules/upf_session_dpo.h"
#include "upf/pfcp/upf_pfcp_server.h"
#include "upf/proxy/upf_proxy.h"
#include "upf/adf/adf.h"
#include "upf/nat/nat.h"

// update every second
#define PERIODIC_STATS_PERIOD 1.0

static void
_upf_periodic_stats_timer_handler (u16 thread_id, upf_timer_kind_t kind,
                                   u32 opaque, u16 opaque2)
{
  upf_main_t *um = &upf_main;
  upf_acl_main_t *uam = &upf_acl_main;
  upf_main_wk_t *uwk = vec_elt_at_index (um->workers, thread_id);

  // restart timer
  upf_timer_stop_safe (thread_id, &uwk->periodic_stats_timer);
  uwk->periodic_stats_timer =
    upf_timer_start_secs (uwk - um->workers, PERIODIC_STATS_PERIOD,
                          UPF_TIMER_KIND_PERIODIC_STATS, 0, 0);

  upf_stats_wk_generic_t *uswg = upf_stats_get_wk_generic (thread_id);

#define _pool_stat(stat_name, pool)                                           \
  {                                                                           \
    typeof (pool) _p = (pool);                                                \
    uswg->pool_##stat_name##_used = pool_elts (_p);                           \
    uswg->pool_##stat_name##_capacity = pool_max_len (_p);                    \
  }

  _pool_stat (timers, upf_timer_main.workers[thread_id].timers);
  _pool_stat (flows, flowtable_main.workers[thread_id].flows);
  _pool_stat (proxy_sessions, upf_proxy_main.workers[thread_id].sessions);
  if (upf_nat_main.initialized)
    {
      _pool_stat (nat_flows, upf_nat_main.workers[thread_id].flows);
      _pool_stat (nat_icmp_flows, upf_nat_main.workers[thread_id].icmp_flows);
    }

#undef _pool_stat

  if (thread_id != 0)
    return;

  // Update main thread stats as well

  // main thread additional stats
  upf_stats_generic_t *usg = upf_stats_get_generic ();

#define _pool_stat(stat_name, pool)                                           \
  {                                                                           \
    typeof (pool) _p = (pool);                                                \
    usg->pool_##stat_name##_used = pool_elts (_p);                            \
    usg->pool_##stat_name##_capacity = pool_max_len (_p);                     \
  }

  _pool_stat (sessions, um->sessions);
  _pool_stat (dp_sessions, um->dp_sessions);
  _pool_stat (nwis, um->nwis);
  _pool_stat (associations, um->assocs);
  _pool_stat (smf_sets, um->smf_sets);
  _pool_stat (cached_f_seids, um->cached_fseid_pool);
  _pool_stat (gtpu_endpoints, upf_gtpu_main.endpoints);
  _pool_stat (pfcp_requests, pfcp_server_main.requests);
  _pool_stat (pfcp_responses, pfcp_server_main.responses);
  _pool_stat (session_dpo_results, upf_dpo_main.cp_dpos_results);
  _pool_stat (forwarding_policies, um->forwarding_policies);
  _pool_stat (adf_apps, um->adf_main.apps);
  _pool_stat (adf_versions, um->adf_main.versions);
  _pool_stat (nat_pools, upf_nat_main.nat_pools);
  _pool_stat (capture_lists, um->netcap.capture_lists);
  _pool_stat (captures, um->netcap.captures);
  _pool_stat (acl_cached_entries, uam->cache_entries);
#undef _pool_stat

  usg->pool_nat_bindings_used = vec_len (upf_nat_main.bindings) -
                                upf_worker_pool_len (upf_nat_main.bindings);
  usg->pool_nat_bindings_capacity = vec_len (upf_nat_main.bindings);

#define _(name, plural)                                                       \
  usg->heap_##plural##_capacity = vec_max_len (um->heaps.plural);
  foreach_upf_rules_heap
#undef _
}

void
upf_periodic_stats_init ()
{
  upf_main_t *um = &upf_main;

  upf_timer_set_handler (UPF_TIMER_KIND_PERIODIC_STATS,
                         _upf_periodic_stats_timer_handler);

  vlib_worker_thread_barrier_sync (vlib_get_main ());

  upf_main_wk_t *uwk;
  vec_foreach (uwk, um->workers)
    {
      uwk->periodic_stats_timer =
        upf_timer_start_secs (uwk - um->workers, PERIODIC_STATS_PERIOD,
                              UPF_TIMER_KIND_PERIODIC_STATS, 0, 0);
    }

  vlib_worker_thread_barrier_release (vlib_get_main ());
}