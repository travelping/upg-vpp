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

#include "upf/sxu/upf_session_update.h"

#define UPF_DEBUG_ENABLE 0

void
upf_sxu_init (upf_sxu_t *sxu, u32 session_id, u16 session_generation,
              u16 thread_id, u32 old_rules_id)
{
  upf_main_t *um = &upf_main;

  upf_session_t *sx = pool_elt_at_index (um->sessions, session_id);

  *sxu = (upf_sxu_t){
    .new_rules_id = ~0,
    .session_id = session_id,
    .session_generation = session_generation,
    .thread_id = thread_id,
    .old_rules_id = old_rules_id,
    .capture_list_id = sx->imsi_capture_list_id,

    .inactivity_timeout = 0,
  };

#define _(name, plural) vec_reset_length (sxu->plural);
  foreach_sxu_type
#undef _

  if (is_valid_id (old_rules_id))
    {
      // restore rules from existing ones
      upf_sxu_1_init_from_rules (sxu,
                                 pool_elt_at_index (um->rules, old_rules_id));
    }
}

static void
_upf_rules_free (upf_rules_t *rules)
{
  upf_main_t *um = &upf_main;

  upf_hh_foreach (fars, um->heaps.fars, &rules->fars)
    vec_free (fars->forward.redirect_uri);

  // pdr acls freed after rpc

  upf_hh_foreach (cap_set, um->heaps.netcap_sets, &rules->netcap_sets)
    vec_free (cap_set->streams);

  upf_hh_free (um->heaps.pdrs, &rules->pdrs);
  upf_hh_free (um->heaps.fars, &rules->fars);
  upf_hh_free (um->heaps.urrs, &rules->urrs);
  upf_hh_free (um->heaps.qers, &rules->qers);
  upf_hh_free (um->heaps.teps, &rules->teps);
  upf_hh_free (um->heaps.ep_ips4, &rules->ep_ips4);
  upf_hh_free (um->heaps.ep_ips6, &rules->ep_ips6);
  upf_hh_free (um->heaps.f_teids, &rules->f_teids);
  upf_hh_free (um->heaps.ep_gtpus, &rules->ep_gtpus);
  upf_hh_free (um->heaps.netcap_sets, &rules->netcap_sets);

  bool barrier = pool_put_will_expand (um->rules, rules);
  if (barrier)
    vlib_worker_thread_barrier_sync (vlib_get_main ());

  pool_put (um->rules, rules);

  if (barrier)
    vlib_worker_thread_barrier_release (vlib_get_main ());
}

void
upf_sxu_deinit (upf_sxu_t *sxu)
{
  upf_main_t *um = &upf_main;

  sxu_slot_far_t *far;
  vec_foreach (far, sxu->fars)
    free_pfcp_ie_redirect_information (&far->val.fp.redirect_information);

  sxu_slot_pdr_t *pdr;
  vec_foreach (pdr, sxu->pdrs)
    vec_free (pdr->val.pdi.sdf_filters_new);

  sxu_slot_capture_set_t *cap_set;
  vec_foreach (cap_set, sxu->capture_sets)
    vec_free (cap_set->val.capture_streams);

#define _(name, plural) vec_free (sxu->plural);
  foreach_sxu_type
#undef _

  if (!sxu->is_compiled)
    // new rules have been not created, no need to remove old ones
    return;

  ASSERT (is_valid_id (sxu->new_rules_id) != sxu->is_session_deletion);

  if (is_valid_id (sxu->old_rules_id))
    _upf_rules_free (pool_elt_at_index (um->rules, sxu->old_rules_id));

  vec_free (sxu->error.message);
  vec_free (sxu->endpoint_conflicts);
}

static int
_upf_sxu_error_set (upf_sxu_t *sxu, upf_sxu_type_t type, upf_xid_t xid,
                    u32 pfcp_id, pfcp_ie_cause_t cause,
                    pfcp_ie_offending_ie_t offending_ie, const char *message)
{
  ASSERT (!sxu->has_error);
  upf_sxu_error_t e = {
    .type = type,
    .xid = xid,
    .cause = cause,
    .pfcp_id = pfcp_id,
    .offending_ie = offending_ie,
    .message = format (0, "%s", message),
  };

  sxu->error = e;
  sxu->has_error = 1;

  return -1;
}

static int
_upf_sxu_error_wrap (upf_sxu_t *sxu, upf_sxu_type_t type, upf_xid_t xid,
                     const char *message)
{
  ASSERT (sxu->has_error);
  upf_sxu_error_t *e = &sxu->error;

  if (!is_valid_id (e->type))
    e->type = type;
  if (!is_valid_id (e->xid))
    e->xid = xid;

  if (message)
    {
      if (e->message)
        {
          u8 *old_message = e->message;
          e->message = format (0, "%s: %v", message, old_message);
          vec_free (old_message);
        }
      else
        {
          e->message = format (0, "%s", message);
        }
    }

  return -1;
}

#define _(name, plural)                                                       \
  int upf_sxu_##name##_error_set_by_pfcp_id (                                 \
    upf_sxu_t *sxu, u32 pfcp_id, pfcp_ie_cause_t cause,                       \
    pfcp_ie_offending_ie_t offending_ie, const char *message)                 \
  {                                                                           \
    return _upf_sxu_error_set (sxu, UPF_SXU_TYPE_##name, ~0, pfcp_id, cause,  \
                               offending_ie, message);                        \
  };                                                                          \
                                                                              \
  int upf_sxu_##name##_error_wrap (upf_sxu_t *sxu, upf_xid_t xid,             \
                                   const char *message)                       \
  {                                                                           \
    return _upf_sxu_error_wrap (sxu, UPF_SXU_TYPE_##name, xid, message);      \
  };
foreach_sxu_pfcp_type
#undef _

#define _(name, plural)                                                       \
  int upf_sxu_##name##_error_set_by_xid (                                     \
    upf_sxu_t *sxu, upf_xid_t xid, pfcp_ie_cause_t cause,                     \
    pfcp_ie_offending_ie_t offending_ie, const char *message)                 \
  {                                                                           \
    return _upf_sxu_error_set (sxu, UPF_SXU_TYPE_##name, xid, ~0, cause,      \
                               offending_ie, message);                        \
  };
  foreach_sxu_type
#undef _

bool
upf_sxu_type_backwalk_to_pfcp_failed_rule_id (
  upf_sxu_t *sxu, upf_sxu_type_t t, upf_xid_t xid, u32 pfcp_id,
  pfcp_ie_failed_rule_id_t *r_failed_rule_id)
{
  if (!is_valid_id (pfcp_id))
    {
      if (!sxu_types_is_pfcp_type (t))
        if (!upf_sxu_type_backwalk_to_pfcp_type (sxu, t, xid, &t, &xid))
          {
            clib_warning ("BUG: couldn't find reference to %U from pfcp type",
                          format_upf_sxu_type, t);
            ASSERT (0);
            return false;
          }

      switch (t)
        {
        case UPF_SXU_TYPE_pdr:
          pfcp_id = vec_elt_at_index (sxu->pdrs, xid)->key;
          break;
        case UPF_SXU_TYPE_far:
          pfcp_id = vec_elt_at_index (sxu->fars, xid)->key;
          break;
        case UPF_SXU_TYPE_qer:
          pfcp_id = vec_elt_at_index (sxu->qers, xid)->key;
          break;
        case UPF_SXU_TYPE_urr:
          pfcp_id = vec_elt_at_index (sxu->urrs, xid)->key;
          break;
        default:
          ASSERT (0);
          return false;
        }
    }

  static u8 _type_to_failed_rule_id_type[] = {
    [UPF_SXU_TYPE_pdr] = PFCP_FAILED_RULE_TYPE_PDR,
    [UPF_SXU_TYPE_far] = PFCP_FAILED_RULE_TYPE_FAR,
    [UPF_SXU_TYPE_qer] = PFCP_FAILED_RULE_TYPE_QER,
    [UPF_SXU_TYPE_urr] = PFCP_FAILED_RULE_TYPE_URR,
  };
  ASSERT (t < ARRAY_LEN (_type_to_failed_rule_id_type));

  r_failed_rule_id->type = _type_to_failed_rule_id_type[t];
  r_failed_rule_id->id = pfcp_id;
  return true;
}
