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

#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/ip/format.h>

#include "upf/upf.h"
#include "upf/adf/adf.h"
#include "upf/adf/matcher.h"

#define FIB_TABLE_ID_START 10000000

#define UPF_DEBUG_ENABLE 0

/**
 * DPO type registered for app
 */
dpo_type_t upf_app_dpo_type;
static fib_source_t app_fib_source;

static index_t
_upf_app_dpo_lookup4 (upf_adf_app_version_t *ver, ip4_address_t *addr4)
{
  index_t lb_index = ip4_fib_forwarding_lookup (ver->fib_index_ip4, addr4);
  ASSERT (lb_index != INDEX_INVALID);

  const load_balance_t *lb = load_balance_get (lb_index);
  const dpo_id_t *dpo = load_balance_get_bucket_i (lb, 0);
  if (dpo->dpoi_type != upf_app_dpo_type)
    {
      upf_debug ("invalid dpo type");
      return INDEX_INVALID;
    }

  upf_debug ("FIB %d MATCH: %U dpo index %d", ver->fib_index_ip4,
             format_ip4_address, addr4, dpo->dpoi_index);
  return dpo->dpoi_index;
}

static index_t
_upf_app_dpo_lookup6 (upf_adf_app_version_t *ver, ip6_address_t *addr6)
{
  index_t lb_index = ip6_fib_table_fwding_lookup (ver->fib_index_ip6, addr6);
  ASSERT (lb_index != INDEX_INVALID);

  const load_balance_t *lb = load_balance_get (lb_index);
  const dpo_id_t *dpo = load_balance_get_bucket_i (lb, 0);
  if (dpo->dpoi_type != upf_app_dpo_type)
    {
      upf_debug ("invalid dpo type");
      return INDEX_INVALID;
    }

  upf_debug ("FIB %d MATCH: %U dpo index %d", ver->fib_index_ip6,
             format_ip6_address, addr6, dpo->dpoi_index);
  return dpo->dpoi_index;
}

static int
ip4_equal_with_prefix_len (ip4_address_t *a1, ip4_address_t *a2, int len)
{
  int shift = 32 - len;
  return a1->as_u32 >> shift == a2->as_u32 >> shift;
}

static int
ip6_equal_with_prefix_len (ip6_address_t *a1, ip6_address_t *a2, int len)
{
  int shift;
  if (len > 64)
    {
      if (a1->as_u64[0] != a2->as_u64[0])
        return 0;
      shift = 128 - len;
      return a1->as_u64[1] >> shift == a2->as_u64[1] >> shift;
    }
  shift = 64 - len;
  return a1->as_u64[0] >> shift == a2->as_u64[0] >> shift;
}

static int
_acl_rule_port_in_range (u16 port, ipfilter_rule_t *rule, upf_el_t field)
{
  ipfilter_port_t *match = &rule->ports[field];
  return port >= match->min && port <= match->max;
}

static int
_src_mask_cmp (void *a1, void *a2)
{
  upf_app_dpo_t *ad1 = (upf_app_dpo_t *) a1, *ad2 = (upf_app_dpo_t *) a2;
  if (ad1->src_preflen < ad2->src_preflen)
    return -1;
  else if (ad1->src_preflen == ad2->src_preflen)
    return 0;
  else
    return 1;
}

static void
_app_add_dpo (upf_adf_app_version_t *ver, ipfilter_rule_t *rule, u8 is_ip4)
{
  upf_app_dpo_t *app_dpo;
  vec_add2 (ver->app_dpos, app_dpo, 1);
  app_dpo->rule_index = rule - ver->acl;
  app_dpo->next = INDEX_INVALID;
  app_dpo->dpoi_index = INDEX_INVALID;
  app_dpo->src_preflen = rule->mask_rmt;
  app_dpo->is_ip4 = is_ip4;
}

clib_error_t *
upf_adf_ip_matcher_prepare (upf_adf_app_version_t *ver)
{
  ipfilter_rule_t *rule;
  upf_app_dpo_t *app_dpo;

  static int next_table_id = FIB_TABLE_ID_START; /* FIXME */

  if (!ver->acl || ver->app_dpos)
    return NULL;

  /* table_id = FIB_TABLE_ID_START + (app - um->upf_apps); */
  if (!is_valid_id (ver->fib_index_ip4))
    {
      ver->fib_index_ip4 = fib_table_find_or_create_and_lock (
        FIB_PROTOCOL_IP4, next_table_id++, app_fib_source);
      ver->fib_index_ip6 = fib_table_find_or_create_and_lock (
        FIB_PROTOCOL_IP6, next_table_id++, app_fib_source);
    }

  vec_foreach (rule, ver->acl)
    {
      bool is_any = !rule->is_ip4 && !rule->is_ip6;

      if (is_any || rule->is_ip4)
        _app_add_dpo (ver, rule, 1);
      if (is_any || rule->is_ip6)
        _app_add_dpo (ver, rule, 0);
    }

  /* shorter prefixes should go first */
  vec_sort_with_function (ver->app_dpos, _src_mask_cmp);
  vec_foreach (app_dpo, ver->app_dpos)
    {
      dpo_id_t dpo = DPO_INVALID;
      fib_prefix_t pfx;
      /*
       * At this point, all of the app_dpos that have been already added
       * to the FIB table have either shorter or same IP prefix length
       * as this app_dpo. So, if we find another entry that intersects
       * with the this app_dpo, we link it from this one, as the FIB
       * table can yield just one match per address
       */
      rule = vec_elt_at_index (ver->acl, app_dpo->rule_index);

      if (app_dpo->is_ip4)
        app_dpo->next = _upf_app_dpo_lookup4 (ver, &rule->address_rmt.ip4);
      else
        app_dpo->next = _upf_app_dpo_lookup6 (ver, &rule->address_rmt.ip6);

      pfx.fp_addr = rule->address_rmt;
      pfx.fp_proto = app_dpo->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
      pfx.fp_len = app_dpo->src_preflen;
      upf_debug ("add pfx: FIB %d is_ip4 %d fp_len %d IP %U dpo_index %d",
                 app_dpo->is_ip4 ? ver->fib_index_ip4 : ver->fib_index_ip6,
                 app_dpo->is_ip4, pfx.fp_len, format_ip46_address,
                 &pfx.fp_addr, IP46_TYPE_ANY, app_dpo - ver->app_dpos);
      dpo_set (&dpo, upf_app_dpo_type, fib_proto_to_dpo (pfx.fp_proto),
               app_dpo - ver->app_dpos);

      app_dpo->dpoi_index = dpo.dpoi_index;
      fib_table_entry_special_dpo_add (
        app_dpo->is_ip4 ? ver->fib_index_ip4 : ver->fib_index_ip6, &pfx,
        FIB_SOURCE_SPECIAL,
        FIB_ENTRY_FLAG_EXCLUSIVE | FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, &dpo);
    }

  return 0;
}

static_always_inline bool
_upf_do_ip_rule_match (upf_adf_app_version_t *ver, ip4_address_t *ue_addr4,
                       ip6_address_t *ue_addr6, ip4_address_t *rmt_addr4,
                       ip6_address_t *rmt_addr6, u16 ue_port, u16 rmt_port,
                       bool ue_addr_is_assigned, bool is_ip4)
{
  index_t dpo_index;
  if (is_ip4)
    dpo_index = _upf_app_dpo_lookup4 (ver, rmt_addr4);
  else
    dpo_index = _upf_app_dpo_lookup6 (ver, rmt_addr6);

  bool rv = false;

  while (dpo_index != INDEX_INVALID)
    {
      upf_app_dpo_t *app_dpo = vec_elt_at_index (ver->app_dpos, dpo_index);
      dpo_index = app_dpo->next;

      ipfilter_rule_t *rule = vec_elt_at_index (ver->acl, app_dpo->rule_index);

      upf_debug ("matching against %U", format_upf_ipfilter, rule);

      if (rule->is_ue_assigned)
        {
          if (!ue_addr_is_assigned)
            continue;
        }
      else
        {
          if (is_ip4)
            {
              if (!ip4_equal_with_prefix_len (ue_addr4, &rule->address_ue.ip4,
                                              rule->mask_ue))
                continue;
            }
          else
            {
              if (!ip6_equal_with_prefix_len (ue_addr6, &rule->address_ue.ip6,
                                              rule->mask_ue))
                continue;
            }
        }

      if (_acl_rule_port_in_range (rmt_port, rule, UPF_EL_RMT) &&
          _acl_rule_port_in_range (ue_port, rule, UPF_EL_UE))
        {
          rv = true;
          break;
        }
    }

  if (is_ip4)
    upf_debug ("%s: ue %U:%d rmt %U:%d assigned %d", rv ? "MATCH" : "MISMATCH",
               format_ip4_address, ue_addr4, ue_port, format_ip4_address,
               rmt_addr4, rmt_port, ue_addr_is_assigned);
  else
    upf_debug ("%s: ue %U:%d rmt %U:%d assigned %d", rv ? "MATCH" : "MISMATCH",
               format_ip6_address, ue_addr6, ue_port, format_ip6_address,
               rmt_addr6, rmt_port, ue_addr_is_assigned);

  return rv;
}

bool
upf_adf_ip_match4 (upf_adf_app_version_t *ver, ip4_address_t *ue_addr4,
                   ip4_address_t *rmt_addr4, u16 ue_port, u16 rmt_port,
                   bool ue_addr_is_assigned)
{
  if (!is_valid_id (ver->fib_index_ip4))
    return false;

  return _upf_do_ip_rule_match (ver, ue_addr4, NULL, rmt_addr4, NULL, ue_port,
                                rmt_port, ue_addr_is_assigned, true);
}

bool
upf_adf_ip_match6 (upf_adf_app_version_t *ver, ip6_address_t *ue_addr6,
                   ip6_address_t *rmt_addr6, u16 ue_port, u16 rmt_port,
                   bool ue_addr_is_assigned)
{
  if (!is_valid_id (ver->fib_index_ip6))
    return false;

  return _upf_do_ip_rule_match (ver, NULL, ue_addr6, NULL, rmt_addr6, ue_port,
                                rmt_port, ue_addr_is_assigned, false);
}

const static char *const upf_app_dpo_ip4_nodes[] = {
  "error-drop",
  NULL,
};

const static char *const upf_app_dpo_ip6_nodes[] = {
  "error-drop",
  NULL,
};

const static char *const *const upf_app_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = upf_app_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = upf_app_dpo_ip6_nodes,
};

dpo_type_t
upf_app_dpo_get_type (void)
{
  return (upf_app_dpo_type);
}

static void
upf_app_dpo_lock (dpo_id_t *dpo)
{
  /* NOOP */
}

static void
upf_app_dpo_unlock (dpo_id_t *dpo)
{
  /* NOOP */
}

static void
upf_app_dpo_interpose (const dpo_id_t *original, const dpo_id_t *parent,
                       dpo_id_t *clone)
{
  /* NOOP */
}

u8 *
format_upf_app_dpo (u8 *s, va_list *ap)
{
  return format (s, "<UPF APP DPO>");
}

const static dpo_vft_t upf_app_dpo_vft = {
  .dv_lock = upf_app_dpo_lock,
  .dv_unlock = upf_app_dpo_unlock,
  .dv_format = format_upf_app_dpo,
  //.dv_get_urpf = upf_app_dpo_get_urpf,
  .dv_mk_interpose = upf_app_dpo_interpose,
};

static clib_error_t *
upf_app_dpo_module_init (vlib_main_t *vm)
{
  app_fib_source = fib_source_allocate ("upf-app", FIB_SOURCE_PRIORITY_HI,
                                        FIB_SOURCE_BH_SIMPLE);

  upf_app_dpo_type =
    dpo_register_new_type (&upf_app_dpo_vft, upf_app_dpo_nodes);

  return (NULL);
}

int
upf_app_ip_rule_match (u32 app_idx, flow_entry_t *flow,
                       ip46_address_t *assigned)
{
  upf_adf_main_t *am = &upf_main.adf_main;

  upf_adf_app_t *app = pool_elt_at_index (am->apps, app_idx);

  if (!is_valid_id (app->active_ver_idx))
    {
      upf_debug ("app match no commited application version");
      return 0;
    }

  upf_debug ("app match using application version idx %d",
             app->active_ver_idx);

  upf_adf_app_version_t *ver =
    pool_elt_at_index (am->versions, app->active_ver_idx);

  return ver->app_dpos && upf_adf_ip_match (ver, flow, assigned);
}

VLIB_INIT_FUNCTION (upf_app_dpo_module_init);

/*
  TODO:
  define "dummy" DPO type

  setting dpo:

  dpo_set (dpo, upf_app_dpo_type, dproto, app_dpo_index);

  app_index = index to upf_main's upf_apps

  non-exact match

  dpo's node with ip4-drop

  check if we need FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT

  fib_table_entry_special_dpo_add (appentry->fib_index, &pfx,
  FIB_SOURCE_SPECIAL,
  FIB_ENTRY_FLAG_EXCLUSIVE |
  FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
  &dpo_id);

  conflicts:
  adding more specific route:
  add link to parent.

  adding less specific route:
  should not happen:
  SORT ACLs BY INCREASING PREFIX SIZE!

  When app rules change:
  invalidate the fib table

  Build fib table when a session is created

  Later: rebuild db upon 'commit' if there are active sessions

  hashtables with multiple prefix lengths as part of the key:
  that's how IPv6 FIB works
  mtrie may be faster

  tuple space search classifier
  https://pchaigno.github.io/ebpf/2020/09/29/bpf-isnt-just-about-speed.html
  http://cseweb.ucsd.edu/~varghese/PAPERS/Sigcomm99.pdf
*/
