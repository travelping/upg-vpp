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

#include "upf/sxu/upf_session_update.h"

#define UPF_DEBUG_ENABLE 0

#define _field(type_name, field, ref_type_name, _is_lidset)                   \
  {                                                                           \
    .offset = offsetof (sxu_slot_##type_name##_t, field),                     \
    .type = UPF_SXU_TYPE_##ref_type_name, .is_lidset = _is_lidset,            \
  }

static upf_sxu_type_meta_ref_t _sxu_pdr_refs[] = {
  _field (pdr, val.pdi.ref_traffic_ep_xid, traffic_ep, 0),
  _field (pdr, val.pdi.ref_application_xid, adf_application, 0),
  _field (pdr, val.ref_far_xid, far, 0),
  _field (pdr, val.refs_urr_xids, urr, 1),
  _field (pdr, val.refs_qer_xids, qer, 1),
};

static upf_sxu_type_meta_ref_t _sxu_far_refs[] = {
  _field (far, val.nat_binding_xid, nat_binding, 0),
};

static upf_sxu_type_meta_ref_t _sxu_urr_refs[] = {
  _field (urr, val.refs_linked_urr_xids, urr, 1),
};

static upf_sxu_type_meta_ref_t _sxu_qer_refs[] = {};

static upf_sxu_type_meta_ref_t _sxu_traffic_ep_refs[] = {
  _field (traffic_ep, key.ref_f_teid_allocation_xid, f_teid_allocation, 0),
  _field (traffic_ep, key.ref_gtpu_ep_xid, gtpu_ep, 0),
  _field (traffic_ep, val.ref_ue_ip4_xid, ue_ip_ep4, 0),
  _field (traffic_ep, val.ref_ue_ip6_xid, ue_ip_ep6, 0),
};

static upf_sxu_type_meta_ref_t _sxu_f_teid_allocation_refs[] = {
  _field (f_teid_allocation, val.ref_gtpu_ep_xid, gtpu_ep, 0),
};

static upf_sxu_type_meta_ref_t _sxu_gtpu_ep_refs[] = {};
static upf_sxu_type_meta_ref_t _sxu_ue_ip_ep4_refs[] = {};
static upf_sxu_type_meta_ref_t _sxu_ue_ip_ep6_refs[] = {};
static upf_sxu_type_meta_ref_t _sxu_capture_set_refs[] = {};
static upf_sxu_type_meta_ref_t _sxu_adf_application_refs[] = {};
static upf_sxu_type_meta_ref_t _sxu_nat_binding_refs[] = {};
static upf_sxu_type_meta_ref_t _sxu_imsi_capture_refs[] = {};
static upf_sxu_type_meta_ref_t _sxu_nwi_stat_refs[] = {};
static upf_sxu_type_meta_ref_t _sxu_policy_ref_refs[] = {};
static upf_sxu_type_meta_ref_t _sxu_gtpu_ep_stat_refs[] = {};

#undef _field

// array with index being upf_sxu_type_t
const upf_sxu_type_meta_t sxu_types_meta_walk[UPF_SXU_N_TYPES] = {
#define _(name, plural)                                                       \
  {                                                                           \
    .refs = _sxu_##name##_refs,                                               \
    .ref_count = ARRAY_LEN (_sxu_##name##_refs),                              \
    .slot_size = sizeof (sxu_slot_##name##_t),                                \
  },
  foreach_sxu_type
#undef _
};

static u32 _upf_sxu_type_backwalk_recursion_counter = 0;

static bool
_upf_sxu_type_backwalk_to_pfcp_type_internal (upf_sxu_t *sxu,
                                              upf_sxu_type_t search_t,
                                              upf_xid_t search_xid,
                                              upf_sxu_type_t *result_t,
                                              upf_xid_t *result_xid)
{
  _upf_sxu_type_backwalk_recursion_counter += 1;
  if (_upf_sxu_type_backwalk_recursion_counter > 10)
    {
      clib_warning (
        "stopped ref backwalk search due to recursion (t %s, xid %d)",
        search_t, search_xid);
      ASSERT (_upf_sxu_type_backwalk_recursion_counter <= 10);
      return false;
    }

  // walk all types in hope to find reference to our type
  for (upf_sxu_type_t loop_t = 0; loop_t < UPF_SXU_N_TYPES; loop_t++)
    {
      const upf_sxu_type_meta_t *m = &sxu_types_meta_walk[loop_t];
      for (u16 i_ref = 0; i_ref < m->ref_count; i_ref++)
        {
          const upf_sxu_type_meta_ref_t *r = &m->refs[i_ref];

          if (r->type == search_t)
            {
              // check all objects if they have reference to dependent object
              for (upf_xid_t loop_xid = 0;
                   loop_xid < vec_len (sxu->slots_array[loop_t]); loop_xid++)
                {
                  void *obj = ((u8 *) sxu->slots_array[loop_t]) +
                              ((u32) r->offset) * ((u32) loop_xid);
                  void *ref_field = (u8 *) obj + r->offset;

                  if (r->is_lidset)
                    {
                      upf_lidset_t *lidset = ref_field;
                      upf_debug ("checking lidset ref %U[%d]+0x%x = %U for "
                                 "xid %d of type %U",
                                 format_upf_sxu_type, loop_t, loop_xid,
                                 r->offset, format_upf_lidset, lidset,
                                 search_xid, format_upf_sxu_type, search_t);

                      if (!upf_lidset_get (lidset, search_xid))
                        continue;
                    }
                  else
                    {
                      upf_xid_t xid = *((upf_xid_t *) ref_field);

                      upf_debug ("checking    xid ref %U[%d]+0x%x = %d for "
                                 "xid %d of type %U",
                                 format_upf_sxu_type, loop_t, loop_xid,
                                 r->offset, xid, search_xid,
                                 format_upf_sxu_type, search_t);

                      if (xid != search_xid)
                        continue;
                    }

                  // found reference to target object
                  if (sxu_types_is_pfcp_type (loop_t))
                    {
                      *result_t = loop_t;
                      *result_xid = loop_xid;
                      return true;
                    }
                  else
                    {
                      // recursively continue search to pfcp type
                      if (_upf_sxu_type_backwalk_to_pfcp_type_internal (
                            sxu, loop_t, loop_xid, result_t, result_xid))
                        return true;
                    }
                }
            }
        }
    }

  return false;
}

bool
upf_sxu_type_backwalk_to_pfcp_type (upf_sxu_t *sxu, upf_sxu_type_t search_t,
                                    upf_xid_t search_xid,
                                    upf_sxu_type_t *result_t,
                                    upf_xid_t *result_xid)
{
  _upf_sxu_type_backwalk_recursion_counter = 0;
  return _upf_sxu_type_backwalk_to_pfcp_type_internal (
    sxu, search_t, search_xid, result_t, result_xid);
}
