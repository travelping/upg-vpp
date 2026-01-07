/*
 * Copyright (c) 2019-2025 Travelping GmbH
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

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/interface_output.h>

#include "upf/upf.h"
#include "upf/utils/ip_helpers.h"
#include "upf/rules/upf_session_dpo.h"
#include "upf/integrations/upf_ueip_export.h"

#define UPF_DEBUG_ENABLE 0

dpo_type_t upf_session_dpo_type;

static fib_source_t upf_fib_source;

upf_dpo_main_t upf_dpo_main = { 0 };

index_t
upf_dpo_result_create (u16 thread_id, u32 session_id, u16 session_generation,
                       upf_lid_t ueip_lid, bool is_src_ue)
{
  upf_dpo_main_t *udm = &upf_dpo_main;
  vlib_main_t *vm = vlib_get_main ();

  ASSERT (vm->thread_index == 0);

  upf_dpo_result_cp_t *r_cp = NULL;
  pool_get_zero (udm->cp_dpos_results, r_cp);

  index_t id = r_cp - udm->cp_dpos_results;

  bool barrier = false;
  if (id >= vec_len (udm->dp_dpos_results))
    {
      // example: new_id: 5, vec_len: 5, difference: +1
      index_t diff = id - vec_len (udm->dp_dpos_results) + 1;
      ASSERT (diff == 1);
      barrier = vec_resize_will_expand (udm->dp_dpos_results, diff);
    }

  if (barrier)
    vlib_worker_thread_barrier_sync (vm);

  vec_validate (udm->dp_dpos_results, id);
  upf_dpo_result_dp_t *r_dp = vec_elt_at_index (udm->dp_dpos_results, id);

  if (barrier)
    vlib_worker_thread_barrier_release (vm);

  upf_debug ("created dpo result %u, new cp len %u, new dp len %u", id,
             pool_elts (udm->cp_dpos_results), vec_len (udm->dp_dpos_results));

  upf_dpo_result_dp_t dpr = {
    .thread_id = thread_id,
    .is_src_ue = is_src_ue ? 1 : 0,
    .session_id = session_id,
    .is_active = 0,
    .ue_ip_lid = ueip_lid,
    .session_generation = session_generation,
  };

  clib_atomic_store_relax_n (&r_dp->as_u64, dpr.as_u64);

  r_cp->dpo_locks = 0;
  r_cp->session_id = session_id;

  return id;
}

void
upf_dpo_result_activate (index_t id)
{
  upf_dpo_main_t *udm = &upf_dpo_main;

  upf_dpo_result_dp_t dpr = {
    .as_u64 = clib_atomic_load_relax_n (&udm->dp_dpos_results[id].as_u64),
  };

  dpr.is_active = 1;

  clib_atomic_store_rel_n (&udm->dp_dpos_results[id].as_u64, dpr.as_u64);
}

void
upf_dpo_result_delete (index_t id)
{
  upf_dpo_main_t *udm = &upf_dpo_main;

  ASSERT (id < vec_len (udm->dp_dpos_results));

  upf_dpo_result_dp_t dpr = {
    .as_u64 = clib_atomic_load_relax_n (&udm->dp_dpos_results[id].as_u64),
  };

  dpr.is_active = 0;

  clib_atomic_store_rel_n (&udm->dp_dpos_results[id].as_u64, dpr.as_u64);

  upf_dpo_result_cp_t *r_cp = pool_elt_at_index (udm->cp_dpos_results, id);
  ASSERT (r_cp->dpo_locks == 0);

  *r_cp = (upf_dpo_result_cp_t){};
  pool_put (udm->cp_dpos_results, r_cp);
}

static inline upf_dpo_result_cp_t *
_upf_session_dpo_result_cp_get (const dpo_id_t *dpo)
{
  upf_dpo_main_t *udm = &upf_dpo_main;
  ASSERT (upf_session_dpo_type == dpo->dpoi_type);
  return pool_elt_at_index (udm->cp_dpos_results, dpo->dpoi_index);
}

static void
upf_session_dpo_lock (dpo_id_t *dpo)
{
  upf_dpo_result_cp_t *r = _upf_session_dpo_result_cp_get (dpo);
  r->dpo_locks++;
}

static void
upf_session_dpo_unlock (dpo_id_t *dpo)
{
  upf_dpo_result_cp_t *r = _upf_session_dpo_result_cp_get (dpo);
  r->dpo_locks--;
}

u8 *
format_upf_session_dpo (u8 *s, va_list *ap)
{
  index_t index = va_arg (*ap, index_t);

  upf_dpo_main_t *udm = &upf_dpo_main;
  upf_main_t *um = &upf_main;

  upf_dpo_result_cp_t *r_cp = pool_elt_at_index (udm->cp_dpos_results, index);
  upf_dpo_result_dp_t *r_dp = vec_elt_at_index (udm->dp_dpos_results, index);

  if (pool_is_free_index (um->sessions, r_cp->session_id))
    return format (s, "UPF session invalid id");

  upf_session_t *sx = pool_elt_at_index (um->sessions, r_cp->session_id);

  s = format (s, "UPF session UP SEID: 0x%016" PRIx64 " id%d t%d (@%p)",
              sx->up_seid, r_cp->session_id, r_dp->thread_id, sx);
  return s;
}

const static dpo_vft_t upf_session_dpo_vft = {
  .dv_lock = upf_session_dpo_lock,
  .dv_unlock = upf_session_dpo_unlock,
  .dv_format = format_upf_session_dpo,
};

const static char *const upf_session_dpo_ip4_nodes[] = {
  "upf-ip4-session-dpo",
  NULL,
};

const static char *const upf_session_dpo_ip6_nodes[] = {
  "upf-ip6-session-dpo",
  NULL,
};

const static char *const *const upf_session_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = upf_session_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = upf_session_dpo_ip6_nodes,
};

dpo_type_t
upf_session_dpo_get_type ()
{
  return (upf_session_dpo_type);
}

static void
_upf_session_prefix_from_addr4 (ip4_address_t addr, fib_prefix_t *pfx)
{
  memset (pfx, 0, sizeof (*pfx));
  pfx->fp_addr.ip4 = addr;
  if (!ip4_address_is_zero (&addr))
    pfx->fp_len = 32; // TODO: support any mask provided from pfcp
  else
    pfx->fp_len = 0; // support wildcard matching for TDF
  pfx->fp_proto = FIB_PROTOCOL_IP4;
}

static void
_upf_session_prefix_from_addr6 (ip6_address_t addr, fib_prefix_t *pfx)
{
  memset (pfx, 0, sizeof (*pfx));
  pfx->fp_addr.ip6 = addr;
  if (!ip6_address_is_zero (&addr))
    pfx->fp_len = 64; // TODO: support any mask provided from pfcp
  else
    pfx->fp_len = 0; // support wildcard matching for TDF
  pfx->fp_proto = FIB_PROTOCOL_IP6;
}

static int
_upf_session_match_src_dpo_add_del (u32 tdf_fib_id, fib_prefix_t *pfx,
                                    index_t result_id, bool is_add)
{
  if (is_add)
    {
      dpo_id_t sxd = DPO_INVALID;
      dpo_set (&sxd, upf_session_dpo_type, fib_proto_to_dpo (pfx->fp_proto),
               result_id);
      fib_table_entry_special_dpo_add (tdf_fib_id, pfx, FIB_SOURCE_SPECIAL,
                                       FIB_ENTRY_FLAG_ATTACHED, &sxd);
      dpo_reset (&sxd);
    }
  else
    {
      fib_table_entry_special_remove (tdf_fib_id, pfx, FIB_SOURCE_SPECIAL);
    }

  return 0;
}

static int
_upf_session_match_dst_dpo_add_del (u32 fib_id, fib_prefix_t *pfx,
                                    index_t result_id, bool is_add)
{
  if (is_add)
    {
      dpo_id_t sxd = DPO_INVALID;

      dpo_set (&sxd, upf_session_dpo_type, fib_proto_to_dpo (pfx->fp_proto),
               result_id);
      fib_table_entry_special_dpo_add (
        fib_id, pfx, FIB_SOURCE_SPECIAL,
        FIB_ENTRY_FLAG_EXCLUSIVE | FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, &sxd);
      dpo_reset (&sxd);

      upf_ueip_export_add_ueip_hook (&pfx->fp_addr);
    }
  else
    {
      fib_table_entry_special_remove (fib_id, pfx, FIB_SOURCE_SPECIAL);

      upf_ueip_export_del_ueip_hook (&pfx->fp_addr);
    }
  return 0;
}

int
upf_session_match4_dpo_add_del (u32 fib_id, ip4_address_t addr,
                                index_t result_id, bool is_source_matching,
                                bool is_add)
{
  fib_prefix_t pfx;
  _upf_session_prefix_from_addr4 (addr, &pfx);
  if (is_source_matching)
    return _upf_session_match_src_dpo_add_del (fib_id, &pfx, result_id,
                                               is_add);
  else
    return _upf_session_match_dst_dpo_add_del (fib_id, &pfx, result_id,
                                               is_add);
}

int
upf_session_match6_dpo_add_del (u32 fib_id, ip6_address_t addr,
                                index_t result_id, bool is_source_matching,
                                bool is_add)
{
  fib_prefix_t pfx;
  _upf_session_prefix_from_addr6 (addr, &pfx);
  if (is_source_matching)
    return _upf_session_match_src_dpo_add_del (fib_id, &pfx, result_id,
                                               is_add);
  else
    return _upf_session_match_dst_dpo_add_del (fib_id, &pfx, result_id,
                                               is_add);
}

static const dpo_id_t *
_upf_session_match_dpo_lookup_fib (u32 fib_id, fib_prefix_t *pfx)
{
  dpo_type_t session_dpo_type = upf_session_dpo_get_type ();

  fib_node_index_t fei = fib_table_lookup_exact_match (fib_id, pfx);
  if (fei == FIB_NODE_INDEX_INVALID)
    return NULL;

  const dpo_id_t *dpo = fib_entry_contribute_ip_forwarding (fei);
  // upf_debug ("dpo: %U", format_dpo_id, dpo, 0);

  if (PREDICT_FALSE (dpo->dpoi_type == session_dpo_type))
    {
      ASSERT (0); // always shuld have loadbalance in front
      return dpo;
    }

  if (dpo->dpoi_type != DPO_LOAD_BALANCE)
    return NULL;

  load_balance_t *lb = load_balance_get (dpo->dpoi_index);
  for (u16 i = 0; i < lb->lb_n_buckets; i++)
    {
      const dpo_id_t *next_dpo = load_balance_get_bucket_i (lb, i);
      // upf_debug ("> dpo: %U", format_dpo_id, dpo, 0);

      if (next_dpo->dpoi_type == session_dpo_type)
        return next_dpo;
    }

  return NULL;
}

index_t
upf_session_match4_dpo_lookup (u32 fib_id, ip4_address_t addr,
                               bool is_source_matching)
{
  upf_dpo_main_t *udm = &upf_dpo_main;

  fib_prefix_t pfx;
  _upf_session_prefix_from_addr4 (addr, &pfx);
  const dpo_id_t *dpo = _upf_session_match_dpo_lookup_fib (fib_id, &pfx);
  if (dpo == NULL)
    return ~0;

  ASSERT (!pool_is_free_index (udm->cp_dpos_results, dpo->dpoi_index));
  return dpo->dpoi_index;
}

index_t
upf_session_match6_dpo_lookup (u32 fib_id, ip6_address_t addr,
                               bool is_source_matching)
{
  upf_dpo_main_t *udm = &upf_dpo_main;

  fib_prefix_t pfx;
  _upf_session_prefix_from_addr6 (addr, &pfx);
  const dpo_id_t *dpo = _upf_session_match_dpo_lookup_fib (fib_id, &pfx);
  if (dpo == NULL)
    return ~0;

  ASSERT (!pool_is_free_index (udm->cp_dpos_results, dpo->dpoi_index));
  return dpo->dpoi_index;
}

vnet_api_error_t
upf_tdf_ul_table_add_del (u32 vrf, fib_protocol_t fproto, u32 table_id, u8 add)
{
  u32 fib_index, vrf_fib_index;
  upf_main_t *um = &upf_main;

  if (add)
    {
      vrf_fib_index = fib_table_find (fproto, vrf);
      if (~0 == vrf_fib_index)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      fib_index =
        fib_table_find_or_create_and_lock (fproto, table_id, upf_fib_source);

      vec_validate_init_empty (um->tdf_ul_table[fproto], vrf_fib_index, ~0);
      vec_elt (um->tdf_ul_table[fproto], vrf_fib_index) = fib_index;
    }
  else
    {
      vrf_fib_index = fib_table_find (fproto, vrf);
      if (~0 == vrf_fib_index)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (vrf_fib_index >= vec_len (um->tdf_ul_table[fproto]))
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      fib_index = fib_table_find (fproto, table_id);
      if (~0 == fib_index)
        return VNET_API_ERROR_NO_SUCH_FIB;

      if (vec_elt (um->tdf_ul_table[fproto], vrf_fib_index) != fib_index)
        return VNET_API_ERROR_NO_SUCH_TABLE;

      vec_elt (um->tdf_ul_table[fproto], vrf_fib_index) = ~0;
      fib_table_unlock (fib_index, fproto, upf_fib_source);

      return (0);
    }

  return 0;
}

static int
_upf_tdf_ul_lookup_add_i (u32 tdf_ul_fib_index, const fib_prefix_t *pfx,
                          u32 ue_fib_index)
{
  dpo_id_t dpo = DPO_INVALID;

  // create DPO object to perform the source address lookup in the TDF FIB
  lookup_dpo_add_or_lock_w_fib_index (
    tdf_ul_fib_index, fib_proto_to_dpo (pfx->fp_proto), LOOKUP_UNICAST,
    LOOKUP_INPUT_SRC_ADDR, LOOKUP_TABLE_FROM_CONFIG, &dpo);

  // add the entry to the destination FIB that uses the lookup DPO
  fib_table_entry_special_dpo_add (ue_fib_index, pfx, upf_fib_source,
                                   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);

  // the DPO is locked by the FIB entry, and we have no further need for it
  dpo_unlock (&dpo);

  return 0;
}

int
upf_tdf_ul_enable_disable (fib_protocol_t fproto, u32 sw_if_index, int is_en)
{
  upf_main_t *um = &upf_main;

  u32 fib_index = fib_table_get_index_for_sw_if_index (fproto, sw_if_index);

  if (fib_index >= vec_len (um->tdf_ul_table[fproto]))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (!is_valid_id (vec_elt (um->tdf_ul_table[fproto], fib_index)))
    return VNET_API_ERROR_NO_SUCH_FIB;

  if (is_en)
    {
      fib_prefix_t pfx = {
        .fp_proto = fproto,
      };

      // now we know which interface the table will serve, we can add the
      // default route to use the table that the interface is bound to
      _upf_tdf_ul_lookup_add_i (vec_elt (um->tdf_ul_table[fproto], fib_index),
                                &pfx, fib_index);
    }
  else
    {
      return VNET_API_ERROR_UNIMPLEMENTED; // TODO: Implement disable
    }
  return 0;
}

static clib_error_t *
upf_dpo_init (vlib_main_t *vm)
{
  upf_dpo_main_t *udm = &upf_dpo_main;

  upf_fib_source = fib_source_allocate (
    "upf-tdf-route", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_SIMPLE);

  upf_session_dpo_type =
    dpo_register_new_type (&upf_session_dpo_vft, upf_session_dpo_nodes);

  udm->fq_dpo4_handoff_index =
    vlib_frame_queue_main_init (upf_ip4_session_dpo_node.index, 0);
  udm->fq_dpo6_handoff_index =
    vlib_frame_queue_main_init (upf_ip6_session_dpo_node.index, 0);

  return (NULL);
}

VLIB_INIT_FUNCTION (upf_dpo_init);
