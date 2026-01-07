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

#include <math.h>

#include "upf/flow/flowtable.h"
#include "upf/utils/upf_mt.h"
#include "upf/pfcp/upf_session.h"
#include "upf/sxu/upf_session_update.h"
#include "upf/pfcp/upf_pfcp_server.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/rules/upf_acl.h"
#include "upf/rules/upf_ipfilter.h"
#include "upf/adf/adf.h"
#include "upf/upf.h"
#include "upf/utils/ip_helpers.h"
#include "upf/integrations/upf_ipfix.h"
#include "upf/upf_stats.h"
#include "upf/nat/nat.h"

#define UPF_DEBUG_ENABLE 0

upf_session_t *
upf_session_get_by_up_seid (uint64_t up_seid)
{
  upf_main_t *um = &upf_main;
  uword *p;

  p = hash_get (um->session_by_up_seid, up_seid);
  if (!p)
    return NULL;

  return pool_elt_at_index (um->sessions, p[0]);
}

upf_session_t *
upf_session_get_by_cached_f_seid (u32 cached_f_seid_id, u64 cp_seid)
{
  upf_main_t *um = &upf_main;

  upf_cp_fseid_key_t key = {
    .seid = cp_seid,
    .cached_f_seid_id = cached_f_seid_id,
  };

  uword *p = mhash_get (&um->mhash_cp_fseid_to_session_idx, &key);
  if (!p)
    return NULL;

  return pool_elt_at_index (um->sessions, p[0]);
}

upf_session_t *
upf_session_get_by_cp_f_seid (pfcp_ie_f_seid_t *f_seid)
{
  upf_main_t *um = &upf_main;

  upf_cached_f_seid_key_t key = {
    .flags = f_seid->flags,
    .ip4 = f_seid->ip4,
    .ip6 = f_seid->ip6,
  };

  uword *p = mhash_get (&um->mhash_cached_fseid_id, &key);
  if (!p)
    return NULL;

  return upf_session_get_by_cached_f_seid (p[0], f_seid->seid);
}

static void
_upf_session_unref_cp_fseid (upf_session_t *sx)
{
  upf_main_t *um = &upf_main;
  upf_cached_f_seid_t *cached_fseid;

  ASSERT (is_valid_id (sx->cached_fseid_id));
  upf_cp_fseid_key_t cp_key = {
    .seid = sx->cp_seid,
    .cached_f_seid_id = sx->cached_fseid_id,
  };

  uword old_mhash_result = ~0;
  bool ok0 = mhash_unset (&um->mhash_cp_fseid_to_session_idx, &cp_key,
                          &old_mhash_result);
  ASSERT (ok0);
  ASSERT (old_mhash_result == sx - um->sessions);

  cached_fseid =
    pool_elt_at_index (um->cached_fseid_pool, sx->cached_fseid_id);
  cached_fseid->refcount -= 1;

  if (cached_fseid->refcount == 0)
    {
      bool ok1 =
        mhash_unset (&um->mhash_cached_fseid_id, &cached_fseid->key, NULL);
      ASSERT (ok1);

      pool_put (um->cached_fseid_pool, cached_fseid);
    }
  sx->cached_fseid_id = ~0;
}

void
upf_session_set_cp_fseid (upf_session_t *sx, pfcp_ie_f_seid_t *f_seid)
{
  upf_main_t *um = &upf_main;

  if (is_valid_id (sx->cached_fseid_id))
    _upf_session_unref_cp_fseid (sx);

  upf_cached_f_seid_key_t key = {};
  key.flags = f_seid->flags;
  key.ip4 = f_seid->ip4;
  key.ip6 = f_seid->ip6;

  uword *existing_f_seid;
  upf_cached_f_seid_t *cached_f_seid;

  existing_f_seid = mhash_get (&um->mhash_cached_fseid_id, &key);
  if (existing_f_seid)
    {
      cached_f_seid =
        pool_elt_at_index (um->cached_fseid_pool, existing_f_seid[0]);
    }
  else
    {
      pool_get_zero (um->cached_fseid_pool, cached_f_seid);
      cached_f_seid->key = key;
      mhash_set (&um->mhash_cached_fseid_id, &key,
                 cached_f_seid - um->cached_fseid_pool, NULL);
      ASSERT (mhash_get (&um->mhash_cached_fseid_id, &key));
    }

  sx->cached_fseid_id = cached_f_seid - um->cached_fseid_pool;
  sx->cp_seid = f_seid->seid;
  cached_f_seid->refcount += 1;

  upf_cp_fseid_key_t cp_key = {};
  cp_key.seid = sx->cp_seid;
  cp_key.cached_f_seid_id = sx->cached_fseid_id;
  mhash_set (&um->mhash_cp_fseid_to_session_idx, &cp_key, sx - um->sessions,
             NULL);
}

u64
upf_session_generate_up_seid (u64 cp_seid)
{
  // This will be true almost always anyways
  if (PREDICT_TRUE (cp_seid && !upf_session_get_by_up_seid (cp_seid)))
    {
      // Reuse cp_seid as up_seid to simplify search in wireshark
      return cp_seid;
    }

  u64 seed = unix_time_now_nsec () ^ cp_seid;
  u8 retry_cnt = 10;

  // Randomly search for unused seid
  do
    {
      u64 up_seid = random_u64 (&seed);
      if (up_seid == 0 || up_seid == ~0)
        continue;

      if (!upf_session_get_by_up_seid (up_seid))
        return up_seid;
    }
  while (retry_cnt--);

  return 0;
}

static void
_upf_session_imsi_list_add_del (upf_session_t *sx, bool is_add)
{
  upf_main_t *um = &upf_main;

  ASSERT (sx->user_id.imsi_len);

  upf_imsi_t imsi_key = { 0 };
  memcpy (imsi_key.tbcd, sx->user_id.imsi, sx->user_id.imsi_len);

  upf_imsi_sessions_list_t *imsi_list =
    (upf_imsi_sessions_list_t *) mhash_get (&um->mhash_imsi_to_session_list,
                                            &imsi_key);

  upf_imsi_capture_list_id_t *p_capture_list_id =
    (upf_imsi_capture_list_id_t *) mhash_get (
      &um->mhash_imsi_to_capture_list_id, &imsi_key);

  if (is_add)
    {
      ASSERT (!upf_imsi_sessions_list_el_is_part_of_list (sx));

      // init list if not exists
      if (!imsi_list)
        {
          upf_imsi_sessions_list_t empty_list;
          upf_imsi_sessions_list_init (&empty_list);
          mhash_set_mem (&um->mhash_imsi_to_session_list, &imsi_key,
                         (uword *) &empty_list, NULL);

          // get pointer directly from mhash memory
          imsi_list = (upf_imsi_sessions_list_t *) mhash_get (
            &um->mhash_imsi_to_session_list, &imsi_key);
          ASSERT (imsi_list);
        }

      upf_imsi_sessions_list_insert_tail (um->sessions, imsi_list, sx);

      if (p_capture_list_id)
        {
          upf_imsi_capture_list_id_t capture_list_id = *p_capture_list_id;
          ASSERT (is_valid_id (capture_list_id));
          ASSERT (
            !pool_is_free_index (um->netcap.capture_lists, capture_list_id));

          vlib_log_info (um->log_class,
                         "added session %d to netcap stream for imsi %U",
                         sx - um->sessions, format_pfcp_tbcd, &imsi_key.tbcd,
                         sizeof (imsi_key.tbcd));

          sx->imsi_capture_list_id = capture_list_id;
        }
    }
  else
    {
      ASSERT (upf_imsi_sessions_list_el_is_part_of_list (sx));
      ASSERT (imsi_list);

      if (is_valid_id (sx->imsi_capture_list_id))
        {
          ASSERT (!pool_is_free_index (um->netcap.capture_lists,
                                       sx->imsi_capture_list_id));
          sx->imsi_capture_list_id = ~0;
        }

      upf_imsi_sessions_list_remove (um->sessions, imsi_list, sx);

      // destroy list, if empty
      if (upf_imsi_sessions_list_is_empty (imsi_list))
        mhash_unset (&um->mhash_imsi_to_session_list, &imsi_key, NULL);
    }
}

void
upf_session_set_user_id (upf_session_t *sx, pfcp_ie_user_id_t *new_id)
{
  if (sx->user_id.imsi_len)
    _upf_session_imsi_list_add_del (sx, false);

  free_pfcp_ie_user_id (&sx->user_id);

  if (new_id == NULL)
    {
      clib_memset (&sx->user_id, 0, sizeof (sx->user_id));
      return;
    }

  // switch to new value
  sx->user_id = *new_id;
  sx->user_id.nai = vec_dup (new_id->nai);

  if (sx->user_id.imsi_len)
    _upf_session_imsi_list_add_del (sx, true);
}

upf_session_t *
upf_session_new (u64 up_seid)
{
  upf_main_t *um = &upf_main;
  upf_mt_main_t *umm = &upf_mt_main;
  upf_session_t *sx;

  // Worker threads can access this structure read-only to get some information
  // like IMSI for ipfix reporting.
  bool barrier = pool_get_will_expand (um->sessions);
  if (barrier)
    vlib_worker_thread_barrier_sync (vlib_get_main ());

  pool_get (um->sessions, sx);

  if (barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());

  u16 session_generation = sx->session_generation;
  memset (sx, 0, sizeof (upf_session_t));
  sx->session_generation = session_generation;

  sx->up_seid = up_seid;
  sx->c_state = UPF_SESSION_STATE_INIT;

  sx->cp_seid = ~0;
  sx->cached_fseid_id = ~0;
  sx->assoc.id = ~0;
  sx->rules_id = ~0;
  sx->imsi_capture_list_id = ~0;

  upf_assoc_sessions_list_anchor_init (sx);
  upf_imsi_sessions_list_anchor_init (sx);

  upf_session_requests_list_init (&sx->requests);
  upf_session_procedures_list_init (&sx->procedures);

  if (vec_len (umm->workers) == 1)
    {
      // 1 main thread
      sx->thread_index = 0;
    }
  else
    {
      // random_u32 has terrible random (always odd or even),
      // so sprinkle some magic
      // TODO: some other random source

      static u32 _sequ_increase = 0;

      u32 value = random_u32 (&um->rand_base);
      value ^= _sequ_increase;
      value ^= (u32) (upf_time_now_main () * 1000.0);
      value ^= (value >> 16);

      _sequ_increase += 1;

      // Skip first thread which is main thread without graph nodes running
      sx->thread_index = 1 + (value % (vec_len (umm->workers) - 1));

      // TODO: choose thread index in more sophisticated way. For example using
      // threads current load
    }

  return sx;
}

void
upf_session_init (upf_session_t *sx, upf_assoc_t *assoc,
                  pfcp_ie_f_seid_t *cp_f_seid)
{
  upf_main_t *um = &upf_main;

  hash_set (um->session_by_up_seid, sx->up_seid, sx - um->sessions);

  sx->assoc.id = assoc - um->assocs;
  upf_assoc_sessions_list_insert_tail (um->sessions, &assoc->sessions, sx);

  upf_session_set_cp_fseid (sx, cp_f_seid);

  upf_dp_session_t *dsx;

  bool barrier = pool_get_will_expand (um->dp_sessions);
  if (barrier)
    vlib_worker_thread_barrier_sync (vlib_get_main ());

  pool_get (um->dp_sessions, dsx);
  ASSERT (dsx - um->dp_sessions == sx - um->sessions);

  u16 rules_generation = dsx->rules_generation;
  memset (dsx, 0, sizeof (*dsx));
  dsx->rules_generation = rules_generation + 1;
  session_flows_list_init (&dsx->flows);
  dsx->last_ul_traffic = 0;
  dsx->last_dl_traffic = 0;
  dsx->inactivity_timer_id.as_u32 = ~0;
  dsx->clear_traffic_by_ue_timer_id.as_u32 = ~0;
  dsx->urr_timer_id.as_u32 = ~0;
  dsx->thread_id = sx->thread_index;

  // Make generation invalid. It will be restored on worker thread on creation
  dsx->session_generation = sx->session_generation - 1;

  if (barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());

  upf_stats_get_thread (sx->thread_index)->sessions += 1;
}

void
upf_session_deinit (upf_session_t *sx)
{
  upf_main_t *um = &upf_main;
  pfcp_server_main_t *psm = &pfcp_server_main;

  u32 session_id = sx - um->sessions;

  // all procedures completed
  ASSERT (upf_session_procedures_list_is_empty (&sx->procedures));

  bool barrier = pool_put_will_expand (
    um->dp_sessions, pool_elt_at_index (um->dp_sessions, session_id));

  if (barrier)
    vlib_worker_thread_barrier_sync (vlib_get_main ());

  pool_put_index (um->dp_sessions, sx - um->sessions);

  if (barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());

  upf_session_set_user_id (sx, NULL);

  hash_unset (um->session_by_up_seid, sx->up_seid);

  upf_assoc_t *assoc = pool_elt_at_index (um->assocs, sx->assoc.id);
  upf_assoc_sessions_list_remove (um->sessions, &assoc->sessions, sx);
  sx->assoc.id = ~0;

  if (is_valid_id (sx->cached_fseid_id))
    _upf_session_unref_cp_fseid (sx);

  // Detach all requests. Requests will continue and corresponding handlers
  // will be called
  upf_llist_foreach (req, psm->requests, session.anchor, &sx->requests)
    upf_pfcp_request_unlink_session (req);

  upf_stats_get_thread (sx->thread_index)->sessions -= 1;
}

void
upf_session_send_next_procedure (upf_session_t *sx)
{
  upf_main_t *um = &upf_main;

  upf_session_procedure_t *procedure =
    upf_session_procedures_list_head (um->session_procedures, &sx->procedures);
  if (procedure == NULL)
    return;

  if (procedure->is_sent)
    return;

  if (procedure->has_sxu)
    upf_sxu_stage_4_before_rpc (&procedure->sxu);

  upf_mt_event_t ev = {
    .kind = UPF_MT_EVENT_M2W_SESSION_REQ,
    .m2w_session_req =
      (upf_mt_session_req_t){
        .up_seid = sx->up_seid,
        .session_id = procedure->session.id,
        .procedure_id = procedure - um->session_procedures,
        .kind = procedure->mt_req_kind,
        .new_rules_id = ~0,
        .is_terminated_by_up = procedure->is_up_termination,
        .immediate_report_urrs = procedure->immediate_report_urrs,
      },
  };

  if (procedure->has_sxu)
    {
      upf_sxu_t *sxu = &procedure->sxu;

      ev.m2w_session_req.new_rules_id = sxu->new_rules_id;

      ev.m2w_session_req.created_pdr_lids = sxu->created_pdr_lids;
      ev.m2w_session_req.created_urr_lids = sxu->created_urr_lids;
      ev.m2w_session_req.removed_urr_lids = sxu->removed_urr_lids;
    }

  procedure->is_sent = true;
  upf_mt_enqueue_to_wk (sx->thread_index, &ev, 1);
}

upf_session_procedure_t *
upf_session_enqueue_procedure (upf_session_t *sx,
                               upf_mt_session_req_kind_t req_kind,
                               upf_sxu_t *sxu,
                               upf_lidset_t *p_immediate_report_urrs,
                               bool is_up_termination)
{
  upf_main_t *um = &upf_main;

  ASSERT (sx->c_state != UPF_SESSION_STATE_DELETED);

  upf_session_procedure_t *procedure;
  pool_get (um->session_procedures, procedure);

  *procedure = (upf_session_procedure_t){
    .has_sxu = sxu ? true : false,
    .response_id = ~0,
    .session.id = sx - um->sessions,
    .prev_state = sx->c_state,
    .mt_req_kind = req_kind,
    .old_rules_id = sx->rules_id,
    .is_up_termination = is_up_termination,
  };
  upf_session_procedures_list_anchor_init (procedure);

  bool can_send = upf_session_procedures_list_is_empty (&sx->procedures);
  upf_session_procedures_list_insert_tail (um->session_procedures,
                                           &sx->procedures, procedure);

  if (sxu)
    {
      procedure->has_sxu = true;
      procedure->sxu = *sxu;

      // old rules still may be used by worker, they will be removed during MT
      // procedure response from worker
      sx->rules_id = sxu->new_rules_id;
    }

  if (p_immediate_report_urrs)
    procedure->immediate_report_urrs = *p_immediate_report_urrs;

  upf_debug ("created procedure........");

  // do not allow more then single procedure simultaneously
  if (can_send)
    upf_session_send_next_procedure (sx);

  return procedure;
}

void
upf_session_queue_rules_refresh (upf_session_t *sx)
{
  upf_main_t *um = &upf_main;

  if (sx->c_state != UPF_SESSION_STATE_CREATED)
    return;

  upf_sxu_t sxu;
  upf_sxu_init (&sxu, sx - um->sessions, sx->session_generation,
                sx->thread_index, sx->rules_id);

  if (upf_sxu_stage_2_update_dynamic (&sxu))
    {
      clib_warning ("BUG: rules update during rules refresh failed:\n%U",
                    format_upf_sxu, &sxu);
      ASSERT (0);
      return;
    }

  upf_sxu_stage_3_compile_rules (&sxu);

  upf_session_enqueue_procedure (sx, UPF_MT_SESSION_REQ_UPDATE, &sxu, NULL,
                                 false);
}

void
upf_session_trigger_deletion (upf_session_t *sx,
                              upf_session_termination_reason_t reason)
{
  upf_main_t *um = &upf_main;

  upf_debug ("in state %U", format_upf_session_state, sx->c_state);

  if (sx->c_state == UPF_SESSION_STATE_DELETED)
    return; // nothing to do

  sx->termination_reason = reason;

  upf_sxu_t sxu;
  upf_sxu_init (&sxu, sx - um->sessions, sx->session_generation,
                sx->thread_index, sx->rules_id);

  upf_sxu_stage_1_provide_delete_actions (&sxu);
  upf_debug ("1 %U", format_upf_sxu, &sxu);

  if (upf_sxu_stage_2_update_dynamic (&sxu))
    {
      clib_warning (
        "BUG: rules update during triggered session removal failed:\n%U",
        format_upf_sxu, &sxu);
      ASSERT (0);
      return;
    }
  upf_debug ("2 %U", format_upf_sxu, &sxu);

  sx->is_up_terminated = 1;

  upf_sxu_stage_3_compile_rules (&sxu);
  upf_debug ("3 %U", format_upf_sxu, &sxu);

  upf_session_enqueue_procedure (sx, UPF_MT_SESSION_REQ_DELETE, &sxu, NULL,
                                 true);

  sx->c_state = UPF_SESSION_STATE_DELETED;
}

void
upf_session_free (upf_session_t *sx)
{
  upf_main_t *um = &upf_main;

  ASSERT (upf_session_requests_list_is_empty (&sx->requests));
  ASSERT (upf_session_procedures_list_is_empty (&sx->procedures));
  ASSERT (!is_valid_id (sx->assoc.id));
  ASSERT (!is_valid_id (sx->cached_fseid_id));

  sx->session_generation += 1;

  bool barrier = pool_put_will_expand (um->sessions, sx);
  if (barrier)
    vlib_worker_thread_barrier_sync (vlib_get_main ());

  pool_put (um->sessions, sx);

  if (barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());
}

always_inline upf_time_t
_urr_time_at (upf_time_t base, f64 offset, const char *name)
{
  // force floating math, to not round down time
  upf_time_t at = base + (f64) offset;
#if CLIB_DEBUG > 0
  upf_time_t now = upf_time_now (vlib_get_thread_index ());
  ASSERT (at >= now);
  upf_debug ("timer at %U = %U + %.4f (%s) in %.4f", format_upf_time, at,
             format_upf_time, base, offset, name, at - now);
#endif
  return at;
}

static void
_upf_urr_update_timer_next (rules_urr_t *urr, upf_time_t now, u32 thread_id)
{
  upf_main_t *um = &upf_main;

  upf_time_t at = INFINITY;

  if (urr->measurement_method_duration && !urr->status.out_of_time_quota)
    {
      // Time measure doesn't contain fractional part of time. Calculate it
      // here.
      ASSERT (now >= urr->time.time_of_last_measure_update);
      f64 since_last_measure =
        _upf_sub_to_zero (now, urr->time.time_of_last_measure_update);

      f64 fractional_measure =
        urr->time.measure + fmod (since_last_measure, 1);

      if (urr->has_quota_time && urr->time.quota_set)
        {
          u32 q_hit_in =
            _upf_sub_to_zero ((f64) urr->time.quota_left, fractional_measure);
          at = clib_min (at, _urr_time_at (now, q_hit_in, "TQ"));
        }

      if (urr->time.threshold_set)
        {
          u32 t_hit_in = _upf_sub_to_zero ((f64) urr->time.threshold_left,
                                           fractional_measure);
          at = clib_min (at, _urr_time_at (now, t_hit_in, "TT"));
        }
    }

  if (urr->quota_holding_time.period &&
      !urr->status.disarmed_quota_holding_time)
    {
      // covers case when holding time was installed during update
      // covers case when multiple reports been sent in between
      upf_time_t base =
        clib_max (urr->timestamps.last_packet, urr->quota_holding_time.base);
      at = clib_min (
        at, _urr_time_at (base, urr->quota_holding_time.period, "QHT"));
    }

  if (urr->quota_validity_time.period &&
      !urr->status.disarmed_quota_validity_time)
    at = clib_min (at, _urr_time_at (urr->quota_validity_time.base,
                                     urr->quota_validity_time.period, "QVT"));

  if (urr->measurement_period.period)
    at = clib_min (at, _urr_time_at (urr->measurement_period.base,
                                     urr->measurement_period.period, "MP"));

  if (urr->monitoring_time && !urr->status.disarmed_monitoring_time)
    at = clib_min (at, urr->monitoring_time);

  urr->next_timer_at = at;

  if (at != INFINITY)
    {
      upf_debug ("next timer at %U", format_upf_time, at);

      if (at + 1 <= now)
        {
          vlib_log_info (
            um->log_class, "URR#%u timer scheduled in past at %U, now %U",
            urr->pfcp_id, format_upf_time, at, format_upf_time, now);
          ASSERT (at >= now - 1);
        }

      // can sometimes happen due to integer values and rounding
      if (at < now)
        at = now;
    }
}

static void
_upf_dp_session_reschedule_inactivity_timer (upf_dp_session_t *dsx,
                                             upf_rules_t *rules,
                                             upf_time_t now)
{
  upf_main_t *um = &upf_main;

  upf_timer_stop_safe (dsx->thread_id, &dsx->inactivity_timer_id);
  if (dsx->is_dp_terminated)
    return; // do not generate reports

  if (!rules->inactivity_timeout || dsx->inactivity_timeout_sent)
    return;

  upf_time_t last_ul_active;
  if (dsx->last_ul_traffic)
    // check only for UL traffic (UE originated)
    last_ul_active = dsx->last_ul_traffic;
  else
    last_ul_active = dsx->creation_time;

  upf_time_t at = last_ul_active + rules->inactivity_timeout;
  f64 in_secs = clib_max (at - now, 0);

  dsx->inactivity_timer_id = upf_timer_start_secs (
    dsx->thread_id, in_secs, UPF_TIMER_KIND_UP_INVACTIVITY,
    dsx - um->dp_sessions, -1);
}

static void
_upf_dp_session_reschedule_urr_timer (upf_dp_session_t *dsx,
                                      upf_rules_t *rules, upf_time_t now)
{
  upf_main_t *um = &upf_main;

  upf_timer_stop_safe (dsx->thread_id, &dsx->urr_timer_id);
  if (dsx->is_dp_terminated)
    return; // do not generate reports

  upf_time_t at = INFINITY;
  upf_lidset_foreach (urr_lid, &rules->slots.urrs)
    {
      rules_urr_t *urr = upf_rules_get_urr (rules, urr_lid);
      at = clib_min (at, urr->next_timer_at);
    }

  if (at == INFINITY)
    {
      upf_debug ("timer reschedule not needed");
      return;
    }

  upf_time_t in = at - now;
  if (in < 0.0)
    {
      if (in < -1.0)
        {
          vlib_log_err (um->log_class,
                        "timer schedule off by %d sec (%.4f - %.4f)", in, at,
                        now);
          ASSERT (0);
        }
      in = 0;
    }

  upf_debug ("starting timer at %U in %.4f (%.4f)", format_upf_time, at,
             (f32) in, (f32) (at - now));

  dsx->urr_timer_id = upf_timer_start_secs (
    dsx->thread_id, in, UPF_TIMER_KIND_URR, dsx - um->dp_sessions, -1);
}

static void
_upf_dp_session_reschedule_timers (upf_dp_session_t *dsx, upf_rules_t *rules,
                                   upf_time_t now)
{
  _upf_dp_session_reschedule_urr_timer (dsx, rules, now);
  _upf_dp_session_reschedule_inactivity_timer (dsx, rules, now);
}

static void
_upf_urr_update_timers_base (rules_urr_t *urr, upf_time_t now)
{
  upf_main_t *um = &upf_main;

  if (urr->update_flags & URR_UPDATE_F_MEASUREMENT_PERIOD)
    if (urr->measurement_period.period)
      urr->measurement_period.base = now;

  if (urr->update_flags & URR_UPDATE_F_QUOTA_HOLDING_TIME)
    {
      urr->status.disarmed_quota_holding_time = 0;
      if (urr->quota_holding_time.period)
        urr->quota_holding_time.base = now;
    }

  if (urr->update_flags & URR_UPDATE_F_QUOTA_VALIDITY_TIME)
    {
      urr->status.disarmed_quota_validity_time = 0;
      if (urr->quota_validity_time.period)
        urr->quota_validity_time.base = now;
    }

  if (urr->update_flags & URR_UPDATE_F_MONITORING_TIME)
    {
      // We already may have split report which may be scheduled for report.
      // It's ok, since we may send split report before monitoring time and be
      // ready for new report at required time.
      urr->status.disarmed_monitoring_time = 0;

      // When timer in the past disarm it
      if (urr->monitoring_time && urr->monitoring_time < now)
        {
          // Do not warn if it's few second diff. Can happen if session
          // established close to monitoring time.
          if (urr->monitoring_time + 2 < now)
            {
              vlib_log_err (
                um->log_class, "Monitoring Time scheduled in past: %U now: %U",
                format_upf_time, urr->monitoring_time, format_upf_time, now);
            }
          urr->status.disarmed_monitoring_time = 1;
        }
    }
}

// Should be called before any URR updates affecting "out of quota" flags or
// using duration measure value
void
upf_urr_time_measure_advance (rules_urr_t *urr, upf_time_t now)
{
  upf_time_t period_start = urr->time.time_of_last_measure_update;

  if (!urr->measurement_method_duration)
    {
      // no need in measure, drop elapsed time
      urr->time.time_of_last_measure_update = now;
      return;
    }

  if (urr->status.out_of_time_quota || urr->status.out_of_volume_quota)
    {
      // out of quota, do drop elapsed measurement
      urr->time.time_of_last_measure_update = now;
      return;
    }

  // here we do conversion to integer, so fraction is lost
  u32 elapsed_measure = _upf_sub_to_zero (now, period_start);
  urr->time.measure += elapsed_measure;

  // here we try to conpensate fraction loss, so it will be added next update
  urr->time.time_of_last_measure_update += elapsed_measure;
}

static void
_upf_session_dp_urr_on_vol_quota_set (upf_dp_session_t *dsx, rules_urr_t *urr,
                                      upf_urr_lid_t urr_lid)
{
  urr_counter_t *meas_b = &urr->vol.measure.bytes;
  urr_counter_t *q_left = &urr->vol.quota_left;

  // > UP function shall discard any remaining quota
  // So just overwrite it. Notice that measurements are not discarded. And
  // notice that remaining of old quota is not added to new quota.
  *q_left = urr->vol.quota_set;
  urr->status.did_sent_volume_threshold = 0;

  // For UURs which had no quota before and it was added at this update we
  // will consume collected measurements since last usage report as usual.
  // Because we should not dicard measurements such corner case should be
  // handled by CP. CP can first clean measurements by setting quota to zero,
  // what will trigger report if there are any measurements. And only after
  // this set required quota.
  // But most probably such URRs will never exist anyways.

  // Check if new quota already been consumed
  bool hit_q_tot = urr->has_quota_tot && meas_b->tot >= q_left->tot;
  bool hit_q_ul = urr->has_quota_ul && meas_b->ul >= q_left->ul;
  bool hit_q_dl = urr->has_quota_dl && meas_b->dl >= q_left->dl;
  bool hit_q_any = hit_q_tot || hit_q_ul || hit_q_dl;

  // Will be false if not quota is not defined, allowing traffic processing for
  // not provided quotas (when they missed in IE)
  urr->status.out_of_volume_quota = hit_q_any;

  // Now try to send QUOTA usage report, if we used it immediately
  if (!(urr->enabled_triggers & PFCP_REPORTING_TRIGGER_VOLUME_QUOTA))
    return;
  if (!hit_q_any)
    return;

  bool has_measurements = meas_b->tot || meas_b->dl || meas_b->ul;
  // Do not send report if measurements are zero.
  // Can happen if new quota is zero
  if (!has_measurements)
    return;

  // > At receiving a quota with value set to zero, the UP function
  // > shall:
  // > report in a usage report the network resources usage measurement
  // > since the last usage report for that URR, if applicable.

  // Not clear which trigger we should use. QUOTA seems ok. Especially because
  // here also handled case when provided quota is smaller then usage from
  // previous quota.
  urr->next_report_triggers |= PFCP_USAGE_REPORT_TRIGGER_VOLUME_QUOTA;
  upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);
}

static void
_upf_session_dp_urr_on_time_quota_set (upf_dp_session_t *dsx, rules_urr_t *urr,
                                       upf_urr_lid_t urr_lid, upf_time_t now)
{
  // For comments reference to similar method for volume above
  urr->time.quota_left = urr->time.quota_set;
  urr->status.did_sent_time_threshold = 0;

  bool hit = urr->has_quota_time && urr->time.measure >= urr->time.quota_left;

  urr->status.out_of_time_quota = hit;

  if (!(urr->enabled_triggers & PFCP_REPORTING_TRIGGER_TIME_QUOTA))
    return;
  if (!hit)
    return;
  if (!urr->time.measure)
    return;

  urr->next_report_triggers |= PFCP_USAGE_REPORT_TRIGGER_TIME_QUOTA;
  upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);
}

static void
_upf_session_dp_urr_on_vol_threshold_set (upf_dp_session_t *dsx,
                                          rules_urr_t *urr,
                                          upf_urr_lid_t urr_lid)
{
  urr_counter_t *meas_b = &urr->vol.measure.bytes;
  urr_counter_t *t_left = &urr->vol.threshold_left;
  urr_counter_t *t_set = &urr->vol.threshold_set;

  if (!(urr->enabled_triggers & PFCP_REPORTING_TRIGGER_VOLUME_THRESHOLD))
    {
      *t_left = (urr_counter_t){};
      return;
    }

  bool hit_t_tot = t_set->tot && meas_b->tot >= t_set->tot;
  bool hit_t_ul = t_set->ul && meas_b->ul >= t_set->ul;
  bool hit_t_dl = t_set->dl && meas_b->dl >= t_set->dl;

  t_left->tot = t_set->tot ? _upf_sub_to_zero (t_set->tot, meas_b->tot) : 0;
  t_left->ul = t_set->ul ? _upf_sub_to_zero (t_set->ul, meas_b->ul) : 0;
  t_left->dl = t_set->dl ? _upf_sub_to_zero (t_set->dl, meas_b->dl) : 0;

  if (!(hit_t_tot || hit_t_ul || hit_t_dl))
    return;

  urr->next_report_triggers |= PFCP_USAGE_REPORT_TRIGGER_VOLUME_THRESHOLD;
  upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);
  // Left threshold will be reset during report
}

static void
_upf_session_dp_urr_on_time_threshold_set (upf_dp_session_t *dsx,
                                           rules_urr_t *urr,
                                           upf_urr_lid_t urr_lid,
                                           upf_time_t now)
{
  // For comments reference to similar method for volume above
  if (!(urr->enabled_triggers & PFCP_REPORTING_TRIGGER_TIME_THRESHOLD))
    return;

  if (!urr->time.threshold_set)
    {
      urr->time.threshold_left = 0;
      return;
    }

  bool hit = urr->time.measure >= urr->time.threshold_set;

  urr->time.threshold_left =
    _upf_sub_to_zero (urr->time.threshold_set, urr->time.measure);

  if (!hit)
    return;

  urr->next_report_triggers |= PFCP_USAGE_REPORT_TRIGGER_TIME_THRESHOLD;
  upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);
}

static void
_upf_session_dp_urr_on_create (upf_dp_session_t *dsx, upf_rules_t *rules,
                               upf_urr_lid_t urr_lid, upf_time_t now)
{
  rules_urr_t *urr = upf_rules_get_urr (rules, urr_lid);

  urr->timestamps.start = now;
  urr->timestamps.first_packet = 0;
  urr->timestamps.last_packet = 0;
  urr->time.time_of_last_measure_update = now;
  urr->next_timer_at = INFINITY;
  urr->seq_no = 0;
  urr->montioring_split_measurement_id = ~0;

  _upf_session_dp_urr_on_vol_quota_set (dsx, urr, urr_lid);
  _upf_session_dp_urr_on_time_quota_set (dsx, urr, urr_lid, now);
  _upf_session_dp_urr_on_vol_threshold_set (dsx, urr, urr_lid);
  _upf_session_dp_urr_on_time_threshold_set (dsx, urr, urr_lid, now);

  _upf_urr_update_timers_base (urr, now);
  _upf_urr_update_timer_next (urr, now, dsx->thread_id);
}

static void
_upf_session_dp_urr_on_update (upf_dp_session_t *dsx, upf_rules_t *old_rules,
                               upf_rules_t *new_rules, upf_urr_lid_t urr_lid,
                               upf_time_t now)
{
  rules_urr_t *n_urr = upf_rules_get_urr (new_rules, urr_lid);
  rules_urr_t *o_urr = upf_rules_get_urr (old_rules, urr_lid);

  n_urr->next_report_triggers = o_urr->next_report_triggers;
  n_urr->seq_no = o_urr->seq_no;
  n_urr->status = o_urr->status;
  n_urr->next_timer_at = o_urr->next_timer_at;
  n_urr->montioring_split_measurement_id =
    o_urr->montioring_split_measurement_id;

  n_urr->timestamps = o_urr->timestamps;
  n_urr->measurement_period.base = o_urr->measurement_period.base;
  n_urr->quota_holding_time.base = o_urr->quota_holding_time.base;
  n_urr->quota_validity_time.base = o_urr->quota_validity_time.base;

  n_urr->mhash_traffic_by_ue = o_urr->mhash_traffic_by_ue;
  o_urr->mhash_traffic_by_ue = NULL; // now owned by new urr
  n_urr->events_start_of_traffic = o_urr->events_start_of_traffic;
  o_urr->events_start_of_traffic = NULL; // now owned by new urr

  n_urr->vol.measure = o_urr->vol.measure;
  n_urr->vol.threshold_left = o_urr->vol.threshold_left;
  n_urr->vol.quota_left = o_urr->vol.quota_left;

  n_urr->time.measure = o_urr->time.measure;
  n_urr->time.threshold_left = o_urr->time.threshold_left;
  n_urr->time.quota_left = o_urr->time.quota_left;
  n_urr->time.time_of_last_measure_update =
    o_urr->time.time_of_last_measure_update;

  if (o_urr->has_pdr_references && !n_urr->has_pdr_references)
    {
      // > due to the removal of the URR or dissociated from the last PDR
      n_urr->next_report_triggers |=
        PFCP_USAGE_REPORT_TRIGGER_TERMINATION_REPORT;
      upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);
    }

  upf_debug ("n_urr->update flags: %x [vol %u dura %u even %u]",
             n_urr->update_flags, n_urr->measurement_method_volume,
             n_urr->measurement_method_duration,
             n_urr->measurement_method_event);

  if (n_urr->update_flags & URR_UPDATE_F_VOLUME_QUOTA)
    _upf_session_dp_urr_on_vol_quota_set (dsx, n_urr, urr_lid);
  if (n_urr->update_flags & URR_UPDATE_F_TIME_QUOTA)
    _upf_session_dp_urr_on_time_quota_set (dsx, n_urr, urr_lid, now);
  if (n_urr->update_flags & URR_UPDATE_F_VOLUME_THRESHOLD)
    _upf_session_dp_urr_on_vol_threshold_set (dsx, n_urr, urr_lid);
  if (n_urr->update_flags & URR_UPDATE_F_TIME_THRESHOLD)
    _upf_session_dp_urr_on_time_threshold_set (dsx, n_urr, urr_lid, now);

  _upf_urr_update_timers_base (n_urr, now);
  _upf_urr_update_timer_next (n_urr, now, dsx->thread_id);
}

static void
_upf_session_dp_urr_on_delete (upf_dp_session_t *dsx, upf_rules_t *rules,
                               upf_urr_lid_t urr_lid, upf_time_t now,
                               bool is_terminated_by_up)
{
  rules_urr_t *urr = upf_rules_get_urr (rules, urr_lid);

  upf_urr_time_measure_advance (urr, now);

  if (is_terminated_by_up)
    urr->next_report_triggers |=
      PFCP_USAGE_REPORT_TRIGGER_TERMINATION_BY_UP_FUNCTION_REPORT;
  else
    urr->next_report_triggers |= PFCP_USAGE_REPORT_TRIGGER_TERMINATION_REPORT;
  upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);

  // this URR is removed, so no new event reports are needed anyways
  if (urr->mhash_traffic_by_ue)
    {
      mhash_free (urr->mhash_traffic_by_ue);
      clib_mem_free (urr->mhash_traffic_by_ue);
      urr->mhash_traffic_by_ue = NULL;
    }
  vec_free (urr->events_start_of_traffic);
}

static void
_upf_session_dp_urr_free (upf_dp_session_t *dsx, upf_rules_t *rules,
                          upf_urr_lid_t urr_lid)
{
  upf_main_t *um = &upf_main;
  rules_urr_t *urr = upf_rules_get_urr (rules, urr_lid);

  if (is_valid_id (urr->montioring_split_measurement_id))
    {
      upf_main_wk_t *wk = vec_elt_at_index (um->workers, dsx->thread_id);
      pool_put_index (wk->split_measurements,
                      urr->montioring_split_measurement_id);
      urr->montioring_split_measurement_id = ~0;
    }
}

void
handle_mt_event_m2w_session_req (u16 wk_thread_id, upf_mt_session_req_t *ev)
{
  ASSERT (vlib_get_thread_index () == wk_thread_id);

  upf_main_t *um = &upf_main;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  flowtable_main_t *fm = &flowtable_main;
  flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, wk_thread_id);
  upf_time_t now = upf_time_now (wk_thread_id);
  upf_debug ("now: %U", format_upf_time, now);
  upf_main_wk_t *uwk = vec_elt_at_index (um->workers, wk_thread_id);

  u32 session_id = ev->session_id;
  ASSERT (is_valid_id (session_id));

  bool is_create = ev->kind == UPF_MT_SESSION_REQ_CREATE;
  bool is_delete = ev->kind == UPF_MT_SESSION_REQ_DELETE;
  bool is_update = ev->kind == UPF_MT_SESSION_REQ_UPDATE;

  upf_dp_session_t *dsx = pool_elt_at_index (um->dp_sessions, session_id);

  if (is_create)
    {
      ASSERT (dsx->thread_id == wk_thread_id);
      ASSERT (is_valid_id (ev->new_rules_id));

      // all fields zeroed by main thread in advance
      dsx->up_seid = ev->up_seid;
      dsx->creation_time = now;
      dsx->session_generation += 1; // restore proper generation

      upf_pool_claim_set_id (&uwk->dp_session_claims, session_id);
    }
  else
    {
      ASSERT (dsx->up_seid == ev->up_seid);
    }

  upf_debug ("creat PDR lids:%U", format_upf_lidset, &ev->created_pdr_lids);
  upf_debug ("creat URR lids:%U", format_upf_lidset, &ev->created_urr_lids);
  upf_debug ("remov URR lids:%U", format_upf_lidset, &ev->removed_urr_lids);

  upf_mt_event_t *events_vec = uwk->cached_events_vec;

  if (is_delete)
    ASSERT (!is_valid_id (ev->new_rules_id));

  if (is_valid_id (ev->new_rules_id))
    dsx->rules_generation = dsx->rules_generation + 1;

  // update URRs, prepare usage reports and etc
  if (is_create)
    {
      upf_pool_claim_set_id (&uwk->rule_claims, ev->new_rules_id);
      upf_rules_t *n_rules = upf_wk_get_rules (wk_thread_id, ev->new_rules_id);

      upf_lidset_foreach (urr_lid, &ev->created_urr_lids)
        _upf_session_dp_urr_on_create (dsx, n_rules, urr_lid, now);

      if (is_valid_id (n_rules->nat_binding_id))
        upf_nat_binding_set_netcap (n_rules->nat_binding_id,
                                    n_rules->want_netcap);

      dsx->rules_id = ev->new_rules_id;
      dsx->is_created = 1;

      _upf_dp_session_reschedule_timers (dsx, n_rules, now);

      if (n_rules->is_flowless_optimized)
        dsx->flow_mode = UPF_SESSION_FLOW_MODE_DISABLED;
      else
        dsx->flow_mode = UPF_SESSION_FLOW_MODE_CREATE;
    }
  else if (is_update)
    {
      upf_rules_t *o_rules = upf_wk_get_rules (wk_thread_id, dsx->rules_id);

      // update OLD URRs time measurement to reflect its change in reports and
      // transfer it to new URRs state
      upf_lidset_foreach (urr_lid, &o_rules->slots.urrs)
        {
          rules_urr_t *o_urr = upf_rules_get_urr (o_rules, urr_lid);
          upf_urr_time_measure_advance (o_urr, now);
        }

      upf_lidset_foreach (urr_lid, &ev->immediate_report_urrs)
        {
          rules_urr_t *o_urr = upf_rules_get_urr (o_rules, urr_lid);
          o_urr->next_report_triggers |=
            PFCP_USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT;
          upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);
        }

      upf_rules_t *n_rules;
      if (!is_valid_id (ev->new_rules_id))
        {
          // no new rules provided, so new rules are equal to old ones
          n_rules = o_rules;
        }
      else
        {
          upf_pool_claim_set_id (&uwk->rule_claims, ev->new_rules_id);
          n_rules = upf_wk_get_rules (wk_thread_id, ev->new_rules_id);

          if (n_rules->flag_inactivity_timeout_reset)
            dsx->inactivity_timeout_sent = 0;

          upf_hh_foreach (n_far, um->heaps.fars, &n_rules->fars)
            {
              if (!n_far->forward.do_send_end_marker)
                continue;

              u8 far_lid = (n_far - um->heaps.fars) - n_rules->fars.base;
              rules_far_t *o_far = upf_rules_get_far (o_rules, far_lid);

              if (!o_far->forward.has_outer_header_creation)
                continue;

              upf_nwi_t *nwi =
                pool_elt_at_index (um->nwis, o_far->forward.nwi_id);
              u16 nwif_id = nwi->interfaces_ids[o_far->forward.dst_intf];
              upf_interface_t *nwif =
                pool_elt_at_index (um->nwi_interfaces, nwif_id);
              upf_gtpu_endpoint_t *gtpu_ep = pool_elt_at_index (
                ugm->endpoints, o_far->forward.ohc.src_gtpu_endpoint_id);

              upf_gtpu_send_end_marker (
                vlib_get_main (), gtpu_ep, nwif, &o_far->forward.ohc.addr4,
                &o_far->forward.ohc.addr6, o_far->forward.ohc.teid);
            }

          // figure out updated (not created, not removed) URR lids:
          // updated_urrs = new_rules->all_urrs & ~created_urrs
          upf_lidset_t updated_urr_lids, _not_created_urr_lids;
          upf_lidset_not (&_not_created_urr_lids, &ev->created_urr_lids);
          upf_lidset_and (&updated_urr_lids, &n_rules->slots.urrs,
                          &_not_created_urr_lids);

          upf_debug ("URR: created: %U removed: %U updated: %U old: %U new %U",
                     format_upf_lidset, &ev->created_urr_lids,
                     format_upf_lidset, &ev->removed_urr_lids,
                     format_upf_lidset, &updated_urr_lids, format_upf_lidset,
                     &o_rules->slots.urrs, format_upf_lidset,
                     &n_rules->slots.urrs);

          upf_lidset_foreach (urr_lid, &ev->removed_urr_lids)
            _upf_session_dp_urr_on_delete (dsx, o_rules, urr_lid, now, false);

          // send reports against old state, since some URRs may be removed
          // after rule change
          upf_usage_reports_trigger (wk_thread_id, dsx, o_rules, now,
                                     &events_vec);

          upf_lidset_foreach (urr_lid, &ev->removed_urr_lids)
            _upf_session_dp_urr_free (dsx, o_rules, urr_lid);

          // Transfer state of URRs from old rules to new rules.
          // Make sure it is called after removed rules report trigger, since
          // we want to transfer already modified state
          upf_lidset_foreach (urr_lid, &updated_urr_lids)
            _upf_session_dp_urr_on_update (dsx, o_rules, n_rules, urr_lid,
                                           now);

          if (n_rules->nat_binding_id != o_rules->nat_binding_id)
            if (is_valid_id (o_rules->nat_binding_id))
              upf_nat_binding_remove_flows (wk_thread_id,
                                            o_rules->nat_binding_id);

          if (is_valid_id (n_rules->nat_binding_id))
            upf_nat_binding_set_netcap (n_rules->nat_binding_id,
                                        n_rules->want_netcap);

          upf_pool_claim_free_id (&uwk->rule_claims, dsx->rules_id);
          dsx->rules_id = ev->new_rules_id;

          upf_lidset_foreach (urr_lid, &ev->created_urr_lids)
            _upf_session_dp_urr_on_create (dsx, n_rules, urr_lid, now);

          if (n_rules->is_flowless_optimized)
            {
              if (session_flows_list_is_empty (&dsx->flows))
                // no flows, safely transition entirely to flowless
                dsx->flow_mode = UPF_SESSION_FLOW_MODE_DISABLED;
              else
                // first expire previous flows with first lookup in flow node
                dsx->flow_mode = UPF_SESSION_FLOW_MODE_NO_CREATE;
            }
          else
            dsx->flow_mode = UPF_SESSION_FLOW_MODE_CREATE;
        }

      // Report immediate reports. Also, some additional reports may be
      // requested right after update, like when already out of newly provided
      // quota.
      upf_usage_reports_trigger (wk_thread_id, dsx, n_rules, now, &events_vec);
      _upf_dp_session_reschedule_timers (dsx, n_rules, now);
    }
  else if (is_delete)
    {
      upf_rules_t *rules = upf_wk_get_rules (wk_thread_id, dsx->rules_id);

      upf_lidset_foreach (urr_lid, &rules->slots.urrs)
        _upf_session_dp_urr_on_delete (dsx, rules, urr_lid, now,
                                       ev->is_terminated_by_up);

      upf_usage_reports_trigger (wk_thread_id, dsx, rules, now, &events_vec);

      upf_lidset_foreach (urr_lid, &rules->slots.urrs)
        _upf_session_dp_urr_free (dsx, rules, urr_lid);

      upf_llist_foreach (f, fwk->flows, session_anchor, &dsx->flows)
        flowtable_entry_delete (fwk, f, now);

      ASSERT (session_flows_list_is_empty (&dsx->flows));

      upf_timer_stop_safe (wk_thread_id, &dsx->urr_timer_id);
      upf_timer_stop_safe (wk_thread_id, &dsx->inactivity_timer_id);
      upf_timer_stop_safe (wk_thread_id, &dsx->clear_traffic_by_ue_timer_id);

      if (is_valid_id (rules->nat_binding_id))
        upf_nat_binding_remove_flows (wk_thread_id, rules->nat_binding_id);

      if (!dsx->is_dp_terminated) // if generation is valid
        // Invalidate generation. Use high bits, so we do not collide with
        // neighbor sessions in case if cp creates them in fast sequence
        dsx->session_generation ^= 0x8000;

      upf_pool_claim_free_id (&uwk->rule_claims, dsx->rules_id);
      upf_pool_claim_free_id (&uwk->dp_session_claims, session_id);

      dsx->is_removed = 1;
      dsx->rules_id = ~0;
    }

  upf_mt_event_t resp_ev = {
    .kind = UPF_MT_EVENT_W2M_SESSION_RESP,
    .w2m_session_resp =
      (upf_mt_session_resp_t){
        .up_seid = ev->up_seid,
        .session_id = ev->session_id,
        .kind = ev->kind,
        .procedure_id = ev->procedure_id,
        .new_rules_id = ev->new_rules_id,
        .usage_reports_count = vec_len (events_vec),
        .is_dp_terminated_before = dsx->is_dp_terminated,
      },
  };
  vec_add1 (events_vec, resp_ev);

  upf_mt_enqueue_to_main (wk_thread_id, events_vec, vec_len (events_vec));

  vec_reset_length (events_vec);
  uwk->cached_events_vec = events_vec;
}

static void
_upf_session_dp_terminate_on_wk (u16 thread_id, upf_dp_session_t *dsx)
{
  upf_main_t *um = &upf_main;
  upf_main_wk_t *uwk = vec_elt_at_index (um->workers, thread_id);
  upf_time_t now = upf_time_now (thread_id);
  upf_rules_t *rules = upf_wk_get_rules (thread_id, dsx->rules_id);

  upf_lidset_foreach (urr_lid, &rules->slots.urrs)
    _upf_session_dp_urr_on_delete (dsx, rules, urr_lid, now, true);

  upf_mt_event_t *events_vec = uwk->cached_events_vec;
  upf_usage_reports_trigger (thread_id, dsx, rules, now, &events_vec);

  upf_mt_event_t ev = {
    .kind = UPF_MT_EVENT_W2M_SESSION_REPORT,
    .w2m_session_report =
      (upf_mt_session_report_t){
        .session_id = dsx - um->dp_sessions,
        .up_seid = dsx->up_seid,
        .report.type = PFCP_REPORT_TYPE_UISR, // termination
        .report.usage_reports_count = vec_len (events_vec),
      },
  };

  vec_add1 (events_vec, ev);
  upf_mt_enqueue_to_main (thread_id, events_vec, vec_len (events_vec));
  vec_reset_length (events_vec);

  uwk->cached_events_vec = events_vec;

  // block traffic and mark as terminated
  dsx->is_removed = 1;
  dsx->is_dp_terminated = 1;

  dsx->session_generation ^=
    0x8000; // now no traffic will reach URR processing

  // and no timers will trigger usage reports
  upf_timer_stop_safe (dsx->thread_id, &dsx->urr_timer_id);
  upf_timer_stop_safe (dsx->thread_id, &dsx->inactivity_timer_id);
}

static_always_inline void
_urr_discard_remaining_quota (rules_urr_t *urr)
{
  urr->vol.quota_left = (urr_counter_t){};
  urr->time.quota_left = 0;

  if (urr->has_quota_ul || urr->has_quota_dl || urr->has_quota_tot)
    urr->status.out_of_volume_quota = 1;
  if (urr->has_quota_time)
    urr->status.out_of_time_quota = 1;
}

static void
_upf_dp_session_urr_timer (u16 thread_id, upf_timer_kind_t kind, u32 opaque,
                           u16 opaque2)
{
  upf_main_t *um = &upf_main;
  upf_main_wk_t *uwk = vec_elt_at_index (um->workers, thread_id);
  u32 session_id = opaque;

  upf_time_t now = upf_time_now (thread_id);

  upf_dp_session_t *dsx = upf_wk_get_dp_session (thread_id, session_id);

  upf_timer_stop_safe (thread_id, &dsx->urr_timer_id);

  upf_debug ("urrs timer at %U", format_upf_time, now);

  upf_rules_t *rules = upf_wk_get_rules (thread_id, dsx->rules_id);

#define debug_timer1(N, T)                                                    \
  if (T.period)                                                               \
    {                                                                         \
      upf_debug ("- " N " base %U perio %d in %.4f", format_upf_time,         \
                 (T).base, (T).period, (f64) ((T).base + (T).period - now));  \
    }

#define debug_timer2(N, period, base, left)                                   \
  if (period)                                                                 \
    {                                                                         \
      upf_debug ("- " N " base %U perio %d left %d in %.4f", format_upf_time, \
                 base, period, left, (f64) (base + ((f64) period) - now));    \
    }

#define is_timer_expired2(WHEN) ((WHEN) <= now)
#define is_timer_expired1(T)                                                  \
  ((T).period && is_timer_expired2 ((T).base + (T).period))

  upf_lidset_foreach (urr_lid, &rules->slots.urrs)
    {
      rules_urr_t *urr = upf_rules_get_urr (rules, urr_lid);

      bool discard_quota = false;

      upf_debug ("urr lid %d, pfcp_id %d next timer at %U (in %.4f)", urr_lid,
                 urr->pfcp_id, format_upf_time, urr->next_timer_at,
                 (float) urr->next_timer_at - now);
      debug_timer1 ("measurement period", urr->measurement_period);
      debug_timer2 ("time threshold", urr->time.threshold_set,
                    urr->time.threshold_left, urr->timestamps.start);
      debug_timer2 ("time quota", urr->time.quota_set, urr->time.quota_left,
                    urr->timestamps.start);
      debug_timer1 ("quota holding time", urr->quota_holding_time);
      debug_timer1 ("quota validity time", urr->quota_validity_time);

      if (urr->next_timer_at > now)
        continue;

      if (urr->measurement_method_duration)
        {
          upf_urr_time_measure_advance (urr, now);

          if (urr->enabled_triggers & PFCP_REPORTING_TRIGGER_TIME_THRESHOLD)
            if (urr->time.threshold_set &&
                urr->time.measure >= urr->time.threshold_left)
              {
                urr->next_report_triggers |=
                  PFCP_USAGE_REPORT_TRIGGER_TIME_THRESHOLD;
                upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);
              }

          if (urr->has_quota_time && urr->time.measure >= urr->time.quota_left)
            if (!urr->status.out_of_time_quota)
              {
                if (urr->time.measure > urr->time.quota_left)
                  vlib_log_err (um->log_class,
                                "time quota timer late for %d (%d-%d)",
                                urr->time.measure - urr->time.quota_left,
                                urr->time.measure, urr->time.quota_left);
                urr->status.out_of_time_quota = 1;

                if (!(urr->enabled_triggers &
                      PFCP_REPORTING_TRIGGER_TIME_QUOTA))
                  continue;

                // TODO: make it conditional like (um->pfcp_spec_version >= 16)
                // For now keep old behavior, since this requires CP testing
                bool is_release_15_or_older = false;

                if (is_release_15_or_older &&
                    urr->status.did_sent_time_threshold)
                  // threshold report already sent
                  continue;

                // quota_left will be modified during report
                urr->next_report_triggers |=
                  PFCP_USAGE_REPORT_TRIGGER_TIME_QUOTA;
                upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);
              }
        }

      if (!urr->status.disarmed_monitoring_time && urr->monitoring_time &&
          is_timer_expired2 (urr->monitoring_time))
        {
          upf_debug ("- monitoring time %U split id %d", format_upf_time,
                     urr->monitoring_time,
                     urr->montioring_split_measurement_id);

          if (is_valid_id (urr->montioring_split_measurement_id))
            {
              // nowhere to store sec ond report, remove session
              _upf_session_dp_terminate_on_wk (thread_id, dsx);
              return;
            }

          upf_main_wk_t *wk = vec_elt_at_index (um->workers, thread_id);
          urr_split_measurement_t *split;
          pool_get (wk->split_measurements, split);

          *split = (urr_split_measurement_t){
            .split_time = now,
            .time_measure = urr->time.measure,
            .vol_measure = urr->vol.measure,
            .first_packet = urr->timestamps.first_packet,
            .last_packet = urr->timestamps.last_packet,
          };

          // do not modify measures, since they should be matched against
          // quotas and thresholds
          urr->timestamps.first_packet = 0;

          urr->montioring_split_measurement_id =
            split - wk->split_measurements;
          urr->status.disarmed_monitoring_time = 1;
        }

      if (urr->enabled_triggers & PFCP_REPORTING_TRIGGER_PERIODIC_REPORTING)
        if (is_timer_expired1 (urr->measurement_period))
          {
            urr->next_report_triggers |=
              PFCP_USAGE_REPORT_TRIGGER_PERIODIC_REPORTING;
            upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);

            urr->measurement_period.base = now;
          }

      if (!urr->status.disarmed_quota_holding_time &&
          urr->quota_holding_time.period)
        {
          upf_time_t base = clib_max (urr->timestamps.last_packet,
                                      urr->quota_holding_time.base);
          if (is_timer_expired2 (base + urr->quota_holding_time.period))
            {
              urr->next_report_triggers |=
                PFCP_USAGE_REPORT_TRIGGER_QUOTA_HOLDING_TIME;
              upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);

              // > any remaining quota for the URR is discarded in the UP
              // function
              discard_quota = true;
              urr->status.disarmed_quota_holding_time = 1;
            }
        }

      if (!urr->status.disarmed_quota_validity_time &&
          is_timer_expired1 (urr->quota_validity_time))
        {
          if (urr->enabled_triggers &
              PFCP_REPORTING_TRIGGER_QUOTA_VALIDITY_TIME)
            {
              urr->next_report_triggers |=
                PFCP_USAGE_REPORT_TRIGGER_QUOTA_VALIDITY_TIME;
              upf_lidset_set (&dsx->scheduled_usage_reports_lids, urr_lid);
            }

          // > any remaining quota for the URR is discarded in the UP
          // function
          discard_quota = true;
          urr->status.disarmed_quota_validity_time = 1;
        }

      if (discard_quota)
        _urr_discard_remaining_quota (urr);

      _upf_urr_update_timer_next (urr, now, thread_id);
    }

  upf_mt_event_t *events_vec = uwk->cached_events_vec;
  upf_usage_reports_trigger (thread_id, dsx, rules, now, &events_vec);
  if (vec_len (events_vec))
    {
      upf_mt_event_t ev = {
        .kind = UPF_MT_EVENT_W2M_SESSION_REPORT,
        .w2m_session_report =
          (upf_mt_session_report_t){
            .session_id = session_id,
            .up_seid = dsx->up_seid,
            .report.type = PFCP_REPORT_TYPE_USAR,
            .report.usage_reports_count = vec_len (events_vec),
          },
      };

      vec_add1 (events_vec, ev);
      upf_mt_enqueue_to_main (thread_id, events_vec, vec_len (events_vec));
      vec_reset_length (events_vec);
      uwk->cached_events_vec = events_vec;

      upf_stats_get_wk_generic (thread_id)->session_reports_generated += 1;
    }

  _upf_dp_session_reschedule_urr_timer (dsx, rules, now);
}

static void
_upf_dp_session_inactivity_timer (u16 thread_id, upf_timer_kind_t kind,
                                  u32 opaque, u16 opaque2)
{
  u32 session_id = opaque;

  upf_time_t now = upf_time_now (thread_id);

  upf_dp_session_t *dsx = upf_wk_get_dp_session (thread_id, session_id);
  upf_rules_t *rules = upf_wk_get_rules (thread_id, dsx->rules_id);

  upf_debug ("inactivity timer at %U", format_upf_time, now);

  upf_timer_stop_safe (thread_id, &dsx->inactivity_timer_id);

  if (!rules->inactivity_timeout || dsx->inactivity_timeout_sent)
    return;

  upf_time_t last_ul_active;
  if (dsx->last_ul_traffic)
    // check only for UL traffic (UE originated)
    last_ul_active = dsx->last_ul_traffic;
  else
    last_ul_active = dsx->creation_time;

  upf_time_t at = last_ul_active + rules->inactivity_timeout;
  if (now < at)
    {
      _upf_dp_session_reschedule_inactivity_timer (dsx, rules, now);
      return;
    }

  upf_mt_event_t ev = {
    .kind = UPF_MT_EVENT_W2M_SESSION_REPORT,
    .w2m_session_report =
      (upf_mt_session_report_t){
        .session_id = session_id,
        .up_seid = dsx->up_seid,
        .report.type = PFCP_REPORT_TYPE_UPIR,
      },
  };

  upf_stats_get_wk_generic (thread_id)->session_reports_generated += 1;
  upf_mt_enqueue_to_main (thread_id, &ev, 1);

  // > the UPF shall behave as if the User Plane Inactivity Timer has not
  // been provisioned
  dsx->inactivity_timeout_sent = 1;
}

void
_upf_usage_report_enqueue_event_reports (u16 thread_id, rules_urr_t *urr,
                                         upf_mt_event_t **events_vec)
{
  if (!vec_len (urr->events_start_of_traffic))
    return;

  urr_start_of_traffic_ev_t *sot;
  vec_foreach (sot, urr->events_start_of_traffic)
    {
      upf2_usage_report_t sot_ur = {
        .urr_id = urr->pfcp_id,
        .seq = urr->seq_no,
        .usage_report_trigger = PFCP_USAGE_REPORT_TRIGGER_START_OF_TRAFFIC,
        .start_of_traffic =
          (upf2_usage_report_start_of_traffic_t){
            .nwi_id = sot->nwi_id,
            .ue_ip_address = sot->ue_ip,
          },
      };

      upf_mt_event_t ev = {
        .kind = UPF_MT_EVENT_W2M_USAGE_REPORT,
        .w2m_usage_report.report = sot_ur,
      };
      vec_add1 (*events_vec, ev);

      urr->seq_no += 1;
    }
  vec_free (urr->events_start_of_traffic);
}

void
_upf_usage_report_enqueue_usage_report (u16 thread_id, rules_urr_t *urr,
                                        upf_time_t now,
                                        upf_mt_event_t **events_vec)
{
  upf_main_t *um = &upf_main;

  pfcp_ie_usage_report_trigger_t usage_report_triggers =
    urr->next_report_triggers;

  if (usage_report_triggers == 0)
    // can happen during events processing
    return;

  urr->next_report_triggers = 0;

  bool with_monitoring_split =
    is_valid_id (urr->montioring_split_measurement_id);

  upf_time_t urr_timestamp_start = urr->timestamps.start;

  if (with_monitoring_split)
    {
      upf_main_t *um = &upf_main;
      upf_main_wk_t *wk = vec_elt_at_index (um->workers, thread_id);

      urr_split_measurement_t *split = pool_elt_at_index (
        wk->split_measurements, urr->montioring_split_measurement_id);

      urr_timestamp_start = split->split_time;

      upf2_usage_report_t split_ur = (upf2_usage_report_t){
        .urr_id = urr->pfcp_id,
        .seq = urr->seq_no,
        .usage_report_trigger = PFCP_USAGE_REPORT_TRIGGER_MONITORING_TIME,
        .measurment =
          (upf2_usage_report_measurment_t){
            .volume_measurments.bytes.total = split->vol_measure.bytes.tot,
            .volume_measurments.bytes.dl = split->vol_measure.bytes.dl,
            .volume_measurments.bytes.ul = split->vol_measure.bytes.ul,
            .volume_measurments.packets.total = split->vol_measure.packets.tot,
            .volume_measurments.packets.dl = split->vol_measure.packets.dl,
            .volume_measurments.packets.ul = split->vol_measure.packets.ul,
            .duration_measurement = split->time_measure,

            .time_of_first_packet = split->first_packet,
            .time_of_last_packet =
              (split->first_packet != 0) ? split->last_packet : 0,
            .time_start = urr->timestamps.start,
            .time_end = split->split_time,
            .usage_information = PFCP_USAGE_INFORMATION_BEFORE,
          },
      };

      upf_mt_event_t ev = {
        .kind = UPF_MT_EVENT_W2M_USAGE_REPORT,
        .w2m_usage_report.report = split_ur,
      };
      vec_add1 (*events_vec, ev);

      urr->seq_no += 1;

      urr_counter_t *m_vol_b = &urr->vol.measure.bytes;
      urr_counter_t *m_vol_p = &urr->vol.measure.packets;
      urr_counter_t *m_split_b = &split->vol_measure.bytes;
      urr_counter_t *m_split_p = &split->vol_measure.packets;

      ASSERT (m_vol_b->tot >= m_split_b->tot);
      ASSERT (m_vol_b->ul >= m_split_b->ul);
      ASSERT (m_vol_b->dl >= m_split_b->dl);
      ASSERT (m_vol_p->tot >= m_split_p->tot);
      ASSERT (m_vol_p->ul >= m_split_p->ul);
      ASSERT (m_vol_p->dl >= m_split_p->dl);
      ASSERT (urr->time.measure >= split->time_measure);

      // substract split measurements from total URR measurements
      urr->time.measure =
        _upf_sub_to_zero (urr->time.measure, split->time_measure);
      m_vol_b->tot = _upf_sub_to_zero (m_vol_b->tot, m_split_b->tot);
      m_vol_b->ul = _upf_sub_to_zero (m_vol_b->ul, m_split_b->ul);
      m_vol_b->dl = _upf_sub_to_zero (m_vol_b->dl, m_split_b->dl);
      m_vol_p->tot = _upf_sub_to_zero (m_vol_p->tot, m_split_p->tot);
      m_vol_p->ul = _upf_sub_to_zero (m_vol_p->ul, m_split_p->ul);
      m_vol_p->dl = _upf_sub_to_zero (m_vol_p->dl, m_split_p->dl);

      pool_put (wk->split_measurements, split);
      urr->montioring_split_measurement_id = ~0;
    }

  upf2_usage_report_t ur = (upf2_usage_report_t){
    .urr_id = urr->pfcp_id,
    .seq = urr->seq_no,
    .usage_report_trigger = usage_report_triggers,
    .measurment =
      (upf2_usage_report_measurment_t){
        .volume_measurments.bytes.total = urr->vol.measure.bytes.tot,
        .volume_measurments.bytes.dl = urr->vol.measure.bytes.dl,
        .volume_measurments.bytes.ul = urr->vol.measure.bytes.ul,
        .volume_measurments.packets.total = urr->vol.measure.packets.tot,
        .volume_measurments.packets.dl = urr->vol.measure.packets.dl,
        .volume_measurments.packets.ul = urr->vol.measure.packets.ul,
        .duration_measurement = urr->time.measure,

        .time_of_first_packet = urr->timestamps.first_packet,
        .time_of_last_packet = (urr->timestamps.first_packet != 0) ?
                                 urr->timestamps.last_packet :
                                 0,
        .time_start = urr_timestamp_start,
        .time_end = now,
      },
  };

  if (with_monitoring_split)
    ur.measurment.usage_information = PFCP_USAGE_INFORMATION_AFTER;

  upf_mt_event_t ev = {
    .kind = UPF_MT_EVENT_W2M_USAGE_REPORT,
    .w2m_usage_report.report = ur,
  };
  vec_add1 (*events_vec, ev);
  urr->seq_no += 1;

  // Now reset URR state

  urr->timestamps.first_packet = 0;
  urr->timestamps.start = now;

  urr_counter_t *vol_m = &urr->vol.measure.bytes;

  if (usage_report_triggers & PFCP_USAGE_REPORT_TRIGGER_VOLUME_THRESHOLD)
    urr->status.did_sent_volume_threshold = 1;
  if (usage_report_triggers & PFCP_USAGE_REPORT_TRIGGER_TIME_THRESHOLD)
    urr->status.did_sent_time_threshold = 1;

  if (usage_report_triggers & (PFCP_USAGE_REPORT_TRIGGER_VOLUME_THRESHOLD |
                               PFCP_USAGE_REPORT_TRIGGER_TIME_THRESHOLD |
                               PFCP_USAGE_REPORT_TRIGGER_EVENT_THRESHOLD))
    {
      // > re-apply all the thresholds (Volume/Time/Event Threshold)
      // > provisioned for the related URR, if the usage report was
      // > triggered due to one of the thresholds being reached
      urr->vol.threshold_left = urr->vol.threshold_set;
      urr->time.threshold_left = urr->time.threshold_set;
    }
  else
    {
      // > if the usage report was triggered for other reporting triggers,
      // > adjust the thresholds
      urr_counter_t *vol_t_set = &urr->vol.threshold_set;
      urr_counter_t *vol_t_left = &urr->vol.threshold_left;
      urr_counter_t *vol_m = &urr->vol.measure.bytes;

      if (vol_t_set->tot)
        vol_t_left->tot = _upf_sub_to_zero (vol_t_left->tot, vol_m->tot);
      if (vol_t_set->ul)
        vol_t_left->ul = _upf_sub_to_zero (vol_t_left->ul, vol_m->ul);
      if (vol_t_set->dl)
        vol_t_left->dl = _upf_sub_to_zero (vol_t_left->dl, vol_m->dl);

      if (urr->time.threshold_set)
        urr->time.threshold_left =
          _upf_sub_to_zero (urr->time.threshold_left, urr->time.measure);
    }

  urr_counter_t *vol_Q_left = &urr->vol.quota_left;

  // > adjust the quota for volume/time/event respectively by subtracting
  // > the (volume/time/event) reported usage in the usage report
  if (urr->has_quota_tot)
    {
      ASSERT (!vol_Q_left->tot || vol_m->tot <= vol_Q_left->tot);
      vol_Q_left->tot = _upf_sub_to_zero (vol_Q_left->tot, vol_m->tot);
    }
  if (urr->has_quota_ul)
    {
      ASSERT (!vol_Q_left->ul || vol_m->ul <= vol_Q_left->ul);
      vol_Q_left->ul = _upf_sub_to_zero (vol_Q_left->ul, vol_m->ul);
    }
  if (urr->has_quota_dl)
    {
      ASSERT (!vol_Q_left->dl || vol_m->dl <= vol_Q_left->dl);
      vol_Q_left->dl = _upf_sub_to_zero (vol_Q_left->dl, vol_m->dl);
    }
  if (urr->has_quota_time && urr->time.quota_left)
    {
      // don't do exact math, timer can be late sometimes
      if (urr->time.measure > urr->time.quota_left + 1)
        {
          vlib_log_err (um->log_class,
                        "URR#%u time measure larger than quota: %u > %u",
                        urr->pfcp_id, urr->time.measure, urr->time.quota_left);
          ASSERT (urr->time.measure > urr->time.quota_left);
        }

      urr->time.quota_left =
        _upf_sub_to_zero (urr->time.quota_left, urr->time.measure);
    }

  // now reset URR based on 5.2.2.3.1 of TS 29.244
  // > reset its ongoing measurement counts for the related URR
  urr->vol.measure.bytes = (urr_counter_t){ 0 };
  urr->vol.measure.packets = (urr_counter_t){ 0 };
  urr->time.measure = 0;
}

void
upf_usage_reports_trigger (u16 thread_id, upf_dp_session_t *dsx,
                           upf_rules_t *rules, upf_time_t now,
                           upf_mt_event_t **events_vec)
{
  upf_lidset_t report_urrs = dsx->scheduled_usage_reports_lids;
  upf_lidset_clear (&dsx->scheduled_usage_reports_lids);

  // first loop over urrs to find out linked usage reportings
  upf_lidset_foreach (urr_lid, &report_urrs)
    {
      rules_urr_t *urr = upf_rules_get_urr (rules, urr_lid);

      upf_lidset_foreach (liusa_lid, &urr->liusa_urrs_lids)
        {
          rules_urr_t *liusa_urr = upf_rules_get_urr (rules, liusa_lid);

          if (liusa_urr->enabled_triggers &
              PFCP_REPORTING_TRIGGER_LINKED_USAGE_REPORTING)
            {
              // account linked urr time
              upf_urr_time_measure_advance (liusa_urr, now);

              liusa_urr->next_report_triggers |=
                PFCP_USAGE_REPORT_TRIGGER_LINKED_USAGE_REPORTING;
              upf_lidset_set (&report_urrs, liusa_lid);
            }
        }
    }

  upf_debug ("reporting %U", format_upf_lidset, &report_urrs);

  upf_lidset_foreach (urr_lid, &report_urrs)
    {
      rules_urr_t *urr = upf_rules_get_urr (rules, urr_lid);

      _upf_usage_report_enqueue_event_reports (thread_id, urr, events_vec);
      _upf_usage_report_enqueue_usage_report (thread_id, urr, now, events_vec);
    }
}

static void
_upf_dp_session_clear_traffic_by_ue_timer (u16 thread_id,
                                           upf_timer_kind_t kind, u32 opaque,
                                           u16 opaque2)
{
  upf_main_t *um = &upf_main;

  u32 session_id = opaque;

  upf_time_t now = upf_time_now (thread_id);
  upf_dp_session_t *dsx = upf_wk_get_dp_session (thread_id, session_id);
  upf_rules_t *rules = upf_wk_get_rules (thread_id, dsx->rules_id);

  upf_debug ("clear traffic_by_ue timer at %U", format_upf_time, now);

  upf_timer_stop_safe (thread_id, &dsx->clear_traffic_by_ue_timer_id);

  bool has_more = false;

  upf_lidset_foreach (urr_lid, &rules->slots.urrs)
    {
      rules_urr_t *urr = upf_rules_get_urr (rules, urr_lid);
      if (!urr->mhash_traffic_by_ue)
        continue;

      upf_time_t timeout = um->start_of_traffic_event_timeout_s;
      urr_start_of_traffic_ev_t *to_remove = NULL, *key;
      uword *v; // invalid, should be f64

      mhash_foreach (key, v, urr->mhash_traffic_by_ue, {
        upf_time_t last_sent = *((upf_time_t *) v);
        if (now > (last_sent + timeout))
          vec_add1 (to_remove, *key);
        else
          has_more = true;
      });

      for (int i = 0; i < vec_len (to_remove); i++)
        mhash_unset (urr->mhash_traffic_by_ue, &to_remove[i], NULL);

      vec_free (to_remove);
    }

  if (has_more)
    {
      dsx->clear_traffic_by_ue_timer_id = upf_timer_start_secs (
        dsx->thread_id, um->start_of_traffic_event_timeout_s,
        UPF_TIMER_KIND_UE_TRAFFIC_HASH_CLEANUP, dsx - um->dp_sessions, -1);
    }
}

u8 *
format_upf_session_state (u8 *s, va_list *args)
{
  upf_session_state_t state = va_arg (*args, upf_session_state_t);

  static const char *strs[] = {
    [UPF_SESSION_STATE_INIT] = "INIT",
    [UPF_SESSION_STATE_CREATED] = "CREATED",
    [UPF_SESSION_STATE_DELETED] = "DELETED",
  };
  return format (s, "%s", strs[state]);
}

u8 *
format_upf_session (u8 *s, va_list *args)
{
  upf_session_t *sx = va_arg (*args, upf_session_t *);

  upf_main_t *um = &upf_main;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  upf_nat_main_t *unm = &upf_nat_main;
  upf_acl_main_t *uam = &upf_acl_main;

  upf_rules_t *rules = pool_elt_at_index (um->rules, sx->rules_id);
  upf_assoc_t *assoc = pool_elt_at_index (um->assocs, sx->assoc.id);
  upf_dp_session_t *dsx =
    pool_elt_at_index (um->dp_sessions, sx - um->sessions);

  static const char *flow_mode_strs[] = {
    [UPF_SESSION_FLOW_MODE_CREATE] = "create",
    [UPF_SESSION_FLOW_MODE_NO_CREATE] = "no_create",
    [UPF_SESSION_FLOW_MODE_DISABLED] = "disabled",
  };

  s = format (s, "Session id=%u SEIDs UP:0x%016llx CP:0x%016llx peer=%U\n",
              (u32) (sx - um->sessions), sx->up_seid, sx->cp_seid,
              format_ip46_address, &assoc->rmt_addr, IP46_TYPE_ANY);
  s = format (s, "Status: flow_mode=%s", flow_mode_strs[dsx->flow_mode]);
  if (sx->c_state != UPF_SESSION_STATE_CREATED)
    s = format (s, " state=%U", format_upf_session_state, sx->c_state);
  if (rules->inactivity_timeout)
    s = format (s, " inactivity=%us", rules->inactivity_timeout);
  s = format (s, " thread=%u created: %U\n", sx->thread_index, format_upf_time,
              dsx->creation_time);

  u8 *s_user_id = format (0, "%U", format_pfcp_ie_user_id, &sx->user_id);
  if (vec_len (s_user_id))
    s = format (s, "User ID: %v\n", s_user_id);
  vec_free (s_user_id);
  s = format (s, "Last packets UL: %U DL: %U\n", format_upf_time,
              dsx->last_ul_traffic, format_upf_time, dsx->last_dl_traffic);

  upf_lid_t tep_lid = 0;
  upf_hh_foreach (tep, um->heaps.teps, &rules->teps)
    {
      upf_nwi_t *nwi = pool_elt_at_index (um->nwis, tep->nwi_id);

      s = format (s, "- Endpoint[%u]: nwi=%U intf=%U %s", tep_lid,
                  format_upf_nwi_name, nwi->name, format_upf_interface_type,
                  tep->intf, tep->is_destination_ip ? "DL" : "UL");

      if (!tep->is_gtpu)
        {
          if (tep->is_ue_ip4 && is_valid_id (tep->match.ip.traffic_ep4_lid))
            {
              rules_ep_ip_t *ep4 =
                upf_rules_get_ep_ip4 (rules, tep->match.ip.traffic_ep4_lid);
              s = format (s, " fib4=%u", ep4->fib_index);
            }
          if (tep->is_ue_ip6 && is_valid_id (tep->match.ip.traffic_ep6_lid))
            {
              rules_ep_ip_t *ep6 =
                upf_rules_get_ep_ip6 (rules, tep->match.ip.traffic_ep6_lid);
              s = format (s, " fib6=%u", ep6->fib_index);
            }
        }

      if (tep->is_ue_ip4)
        s = format (s, " ue_ip4=%U", format_ip4_address, &tep->ue_addr4);
      if (tep->is_ue_ip6)
        s = format (s, " ue_ip6=%U", format_ip6_address, &tep->ue_addr6);
      s = format (s, "\n");

      if (tep->is_gtpu)
        {
          rules_ep_gtpu_t *ep_gtpu =
            upf_rules_get_ep_gtpu (rules, tep->match.gtpu.gtpu_ep_lid);
          upf_gtpu_endpoint_t *gtpu_ep =
            pool_elt_at_index (ugm->endpoints, ep_gtpu->gtpu_ep_id);

          s = format (s, "    gtpu: teid=0x%08X", ep_gtpu->teid);
          if (is_valid_id (tep->match.gtpu.fteid_allocation_lid))
            {
              rules_f_teid_t *f_teid = upf_rules_get_f_teid (
                rules, tep->match.gtpu.fteid_allocation_lid);
              s = format (s, " choose=0x%02X", f_teid->choose_id);
            }
          if (gtpu_ep->has_ip4)
            s = format (s, " ep4=%U", format_ip4_address, &gtpu_ep->ip4);
          if (gtpu_ep->has_ip6)
            s = format (s, " ep6=%U", format_ip6_address, &gtpu_ep->ip6);
          s = format (s, "\n");
        }

      /* PDRs for this endpoint */
      upf_lid_t pdr_lid = 0;
      upf_hh_foreach (pdr, um->heaps.pdrs, &rules->pdrs)
        {
          if (pdr->traffic_ep_lid != tep_lid)
            {
              pdr_lid++;
              continue;
            }

          s = format (s, "  - PDR#%u[%u]: prec=%u", pdr->pfcp_id, pdr_lid,
                      pdr->precedence);

          if (is_valid_id (pdr->far_lid))
            {
              rules_far_t *far = upf_rules_get_far (rules, pdr->far_lid);
              s = format (s, " far=#%u", far->pfcp_id);
            }

          if (!upf_lidset_is_empty (&pdr->urr_lids))
            s = format (s, " urrs=%U", format_upf_rules_urr_lidset, rules,
                        &pdr->urr_lids);

          if (!upf_lidset_is_empty (&pdr->qer_lids))
            s = format (s, " qers=%U", format_upf_rules_qer_lidset, rules,
                        &pdr->qer_lids);

          s = format (s, "\n");

          if (is_valid_id (pdr->application_id))
            {
              upf_adf_app_t *app = pool_elt_at_index (upf_main.adf_main.apps,
                                                      pdr->application_id);
              if (app && vec_len (app->name))
                s = format (s, "      app: %v(%u)\n", app->name,
                            pdr->application_id);
              else
                s = format (s, "      app: (%u)\n", pdr->application_id);
            }

          if (is_valid_id (pdr->acl_cached_id))
            {
              upf_acl_cache_entry_t *ace =
                pool_elt_at_index (uam->cache_entries, pdr->acl_cached_id);

              for (u32 j = 0; j < vec_len (ace->rules); j++)
                {
                  s = format (s, "      match: %U\n", format_upf_ipfilter,
                              &ace->rules[j]);
                }
            }

          pdr_lid++;
        }

      tep_lid++;
    }

  /* FARs */
  upf_lid_t far_lid = 0;
  upf_hh_foreach (far, um->heaps.fars, &rules->fars)
    {
      s = format (s, "- FAR#%u[%u]:", far->pfcp_id, far_lid);

      if (far->apply_action == UPF_FAR_ACTION_FORWARD)
        {
          upf_nwi_t *nwi = pool_elt_at_index (um->nwis, far->forward.nwi_id);

          s = format (s, " FORWARD nwi=%U intf=%U", format_upf_nwi_name,
                      nwi->name, format_upf_interface_type,
                      far->forward.dst_intf);

          if (far->forward.do_nat)
            s = format (s, " nat");
          if (far->ipfix_policy_set != UPF_IPFIX_POLICY_NONE &&
              far->ipfix_policy_set != UPF_IPFIX_POLICY_UNSPECIFIED)
            s = format (s, " ipfix=%U", format_upf_ipfix_policy,
                        far->ipfix_policy_set);

          s = format (s, "\n");

          if (far->forward.has_outer_header_creation)
            {
              s = format (s, "    gtpu: teid=0x%08X", far->forward.ohc.teid);
              if (!ip4_address_is_zero (&far->forward.ohc.addr4))
                s = format (s, " addr4=%U", format_ip4_address,
                            &far->forward.ohc.addr4);
              if (!ip6_address_is_zero (&far->forward.ohc.addr6))
                s = format (s, " addr6=%U", format_ip6_address,
                            &far->forward.ohc.addr6);
              s = format (s, "\n");
            }

          if (far->forward.redirect_uri && vec_len (far->forward.redirect_uri))
            s = format (s, "    redirect: %v\n", far->forward.redirect_uri);

          if (is_valid_id (far->forward.forwarding_policy_id))
            {
              upf_forwarding_policy_t *fp = pool_elt_at_index (
                um->forwarding_policies, far->forward.forwarding_policy_id);
              s = format (s, "    policy: %v\n", fp->policy_id);
            }
        }
      else if (far->apply_action == UPF_FAR_ACTION_DROP)
        {
          s = format (s, " DROP\n");
        }

      far_lid++;
    }

  /* QERs */
  upf_lid_t qer_lid = 0;
  upf_hh_foreach (qer, um->heaps.qers, &rules->qers)
    {
      s = format (s, "- QER#%u[%u]: gate=%s/%s mbr=%u/%u bps\n", qer->pfcp_id,
                  qer_lid, qer->gate_closed_ul ? "CLOSED" : "OPEN",
                  qer->gate_closed_dl ? "CLOSED" : "OPEN",
                  qer->maximum_bitrate[UPF_DIR_UL],
                  qer->maximum_bitrate[UPF_DIR_DL]);
      qer_lid++;
    }

  /* URRs */
  upf_time_t now = upf_time_now_main ();
  upf_lid_t urr_lid = 0;
  upf_hh_foreach (urr, um->heaps.urrs, &rules->urrs)
    {
      if (urr->measurement_method_duration)
        upf_urr_time_measure_advance (urr, now);

      s = format (s, "- %U", format_upf_urr, rules, urr, urr_lid,
                  sx->thread_index);
      urr_lid++;
    }

  /* NAT */
  if (is_valid_id (rules->nat_binding_id))
    {
      upf_nat_pool_t *np =
        pool_elt_at_index (unm->nat_pools, rules->nat_pool_id);
      upf_nat_binding_t *binding =
        upf_worker_pool_elt_at_index (unm->bindings, rules->nat_binding_id);

      u32 port_start =
        np->port_min + binding->port_block_id * np->ports_per_block;
      u32 port_end = port_start + np->ports_per_block - 1;

      s = format (s, "- NAT: pool=%v addr4=%U ports=%u-%u binding_id=%u\n",
                  np->name, format_ip4_address, &binding->external_addr,
                  port_start, port_end, rules->nat_binding_id);
    }

  /* NetCap */
  if (rules->want_netcap)
    {
      upf_lid_t nc_lid = 0;
      upf_hh_foreach (nc_set, um->heaps.netcap_sets, &rules->netcap_sets)
        {
          upf_nwi_t *nwi = pool_elt_at_index (um->nwis, nc_set->nwi_id);
          s = format (s, "- NetCap[%u]: nwi=%U intf=%U streams=[", nc_lid,
                      format_upf_nwi_name, nwi->name,
                      format_upf_interface_type, nc_set->intf);

          for (u32 j = 0; j < vec_len (nc_set->streams); j++)
            {
              if (j > 0)
                s = format (s, ",");
              s = format (s, "%u:%u", nc_set->streams[j].netcap_stream_id,
                          nc_set->streams[j].packet_max_bytes);
            }
          s = format (s, "]\n");
          nc_lid++;
        }
    }

  return s;
}

static clib_error_t *
_upf_session_init (vlib_main_t *vm)
{
  upf_timer_set_handler (UPF_TIMER_KIND_URR, _upf_dp_session_urr_timer);
  upf_timer_set_handler (UPF_TIMER_KIND_UP_INVACTIVITY,
                         _upf_dp_session_inactivity_timer);
  upf_timer_set_handler (UPF_TIMER_KIND_UE_TRAFFIC_HASH_CLEANUP,
                         _upf_dp_session_clear_traffic_by_ue_timer);

  return 0;
}

VLIB_INIT_FUNCTION (_upf_session_init);
