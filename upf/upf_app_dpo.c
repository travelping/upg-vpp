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

#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/load_balance.h>

#include "upf.h"
#include "upf_app_dpo.h"

#define FIB_TABLE_ID_START 10000000

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)                                                        \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

/**
 * DPO type registered for app
 */
dpo_type_t upf_app_dpo_type;
static fib_source_t app_fib_source;

static index_t
upf_app_dpo_lookup (upf_adf_entry_t *appentry, ip46_address_t *addr)
{
  const load_balance_t *lb;
  const dpo_id_t *dpo;
  index_t lb_index =
    ip46_address_is_ip4 (addr) ?
      ip4_fib_table_lookup_lb (ip4_fib_get (appentry->fib_index_ip4),
                               &addr->ip4) :
      ip6_fib_table_fwding_lookup (appentry->fib_index_ip6, &addr->ip6);
  ASSERT (lb_index != INDEX_INVALID);
  lb = load_balance_get (lb_index);
  dpo = load_balance_get_bucket_i (lb, 0);
  if (dpo->dpoi_type != upf_app_dpo_type)
    return INDEX_INVALID;

  upf_debug ("FIB %d MATCH: %U dpo index %d",
             ip46_address_is_ip4 (addr) ? appentry->fib_index_ip4 :
                                          appentry->fib_index_ip6,
             format_ip46_address, addr, IP46_TYPE_ANY, dpo->dpoi_index);
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
ip_equal_with_prefix_len (ip46_address_t *a1, ip46_address_t *a2, int len)
{
  return ip46_address_is_ip4 (a1) ?
           ip4_equal_with_prefix_len (&a1->ip4, &a2->ip4, len) :
           ip6_equal_with_prefix_len (&a1->ip6, &a2->ip6, len);
}

static int
acl_rule_port_in_range (u16 port, acl_rule_t *rule, u8 field)
{
  ipfilter_port_t *match = &rule->port[field];
  return port >= match->min && port <= match->max;
}

static int
upf_do_ip_rule_match (upf_adf_entry_t *appentry, ip46_address_t *src,
                      u16 sport, ip46_address_t *dst, u16 dport,
                      ip46_address_t *assigned)
{
  /*
   * IP app rules for server XX are written like this:
   *   from XX to assigned
   * Here XX is src, 'assigned' is dst
   * src is matched using FIB, then sport is matched against the
   * port ranges of the entries found
   * dst and dport are matched by plain comparison
   */
  index_t dpo_index = upf_app_dpo_lookup (appentry, src);
  while (dpo_index != INDEX_INVALID)
    {
      upf_app_dpo_t *app_dpo =
        vec_elt_at_index (appentry->app_dpos, dpo_index);
      acl_rule_t *rule = vec_elt_at_index (appentry->acl, app_dpo->rule_index);
      ipfilter_address_t *dst_rule_addr =
        &rule->address[IPFILTER_RULE_FIELD_DST];
      ip46_address_t *dst_match = &dst_rule_addr->address;
      u8 dst_prefix_len = dst_rule_addr->mask;
      if (!acl_addr_is_any (dst_rule_addr))
        {
          if (acl_addr_is_assigned (dst_rule_addr))
            {
              dst_match = assigned;
              dst_prefix_len = ip46_address_is_ip4 (dst) ? 32 : 128;
            }
          if (!ip_equal_with_prefix_len (dst, dst_match, dst_prefix_len))
            {
              dpo_index = app_dpo->next;
              continue;
            }
        }
      if (acl_rule_port_in_range (sport, rule, IPFILTER_RULE_FIELD_SRC) &&
          acl_rule_port_in_range (dport, rule, IPFILTER_RULE_FIELD_DST))
        {
          upf_debug ("MATCH: src %U sport %d dst %U dport %d assigned %U",
                     format_ip46_address, src, IP46_TYPE_ANY, sport,
                     format_ip46_address, dst, IP46_TYPE_ANY, dport,
                     format_ip46_address, assigned, IP46_TYPE_ANY);
          return 1;
        }
      dpo_index = app_dpo->next;
    }

  upf_debug ("MISMATCH: src %U sport %d dst %U dport %d assigned %U",
             format_ip46_address, src, IP46_TYPE_ANY, sport,
             format_ip46_address, dst, IP46_TYPE_ANY, dport,
             format_ip46_address, assigned, IP46_TYPE_ANY);
  return 0;
}

static int
src_mask_cmp (void *a1, void *a2)
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
add_app_dpo (upf_adf_entry_t *appentry, acl_rule_t *rule, u8 is_ip4)
{
  upf_app_dpo_t *app_dpo;
  vec_add2 (appentry->app_dpos, app_dpo, 1);
  app_dpo->rule_index = rule - appentry->acl;
  app_dpo->next = INDEX_INVALID;
  app_dpo->dpoi_index = INDEX_INVALID;
  app_dpo->src_preflen = rule->address[IPFILTER_RULE_FIELD_SRC].mask;
  app_dpo->is_ip4 = is_ip4;
}

void
upf_ensure_app_fib_if_needed (upf_adf_entry_t *appentry)
{
  acl_rule_t *rule;
  upf_app_dpo_t *app_dpo;
  /* upf_main_t * gtm = &upf_main; */
  static int next_table_id = FIB_TABLE_ID_START; /* FIXME */
  /* u32 table_id; */

  if (!appentry->acl || appentry->app_dpos)
    return;

  /* table_id = FIB_TABLE_ID_START + (app - gtm->upf_apps); */
  if (appentry->fib_index_ip4 == ~0)
    {
      appentry->fib_index_ip4 = fib_table_find_or_create_and_lock (
        FIB_PROTOCOL_IP4, next_table_id++, app_fib_source);
      appentry->fib_index_ip6 = fib_table_find_or_create_and_lock (
        FIB_PROTOCOL_IP6, next_table_id++, app_fib_source);
    }

  vec_foreach (rule, appentry->acl)
    {
      int has_ip4 = 0, has_ip6 = 0;
      ipfilter_address_t *src, *dst;

      src = &rule->address[IPFILTER_RULE_FIELD_SRC];
      dst = &rule->address[IPFILTER_RULE_FIELD_DST];

      /* TODO: fail to create 'from assigned' rules */
      if (acl_addr_is_assigned (src))
        continue;

      if (acl_addr_is_any (src))
        {
          if (acl_addr_is_assigned (dst) || acl_addr_is_any (dst))
            {
              has_ip4 = 1;
              has_ip6 = 1;
            }
          else if (ip46_address_is_ip4 (&dst->address))
            has_ip4 = 1;
          else
            has_ip6 = 1;
        }
      else if (ip46_address_is_ip4 (&src->address))
        has_ip4 = 1;
      else
        has_ip6 = 1;
      if (has_ip4)
        add_app_dpo (appentry, rule, 1);
      if (has_ip6)
        add_app_dpo (appentry, rule, 0);
    }

  /* shorter prefixes should go first */
  vec_sort_with_function (appentry->app_dpos, src_mask_cmp);
  vec_foreach (app_dpo, appentry->app_dpos)
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
      rule = vec_elt_at_index (appentry->acl, app_dpo->rule_index);
      app_dpo->next = upf_app_dpo_lookup (
        appentry, &rule->address[IPFILTER_RULE_FIELD_SRC].address);
      if (acl_addr_is_any (&rule->address[IPFILTER_RULE_FIELD_SRC]))
        {
          pfx.fp_addr.as_u64[0] = 0;
          pfx.fp_addr.as_u64[1] = 0;
        }
      else
        {
          pfx.fp_addr.as_u64[0] =
            rule->address[IPFILTER_RULE_FIELD_SRC].address.as_u64[0];
          pfx.fp_addr.as_u64[1] =
            rule->address[IPFILTER_RULE_FIELD_SRC].address.as_u64[1];
        }
      pfx.fp_proto = app_dpo->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
      pfx.fp_len = app_dpo->src_preflen;
      upf_debug ("add pfx: FIB %d is_ip4 %d fp_len %d IP %U dpo_index %d",
                 app_dpo->is_ip4 ? appentry->fib_index_ip4 :
                                   appentry->fib_index_ip6,
                 app_dpo->is_ip4, pfx.fp_len, format_ip46_address,
                 &pfx.fp_addr, IP46_TYPE_ANY, app_dpo - appentry->app_dpos);
      dpo_set (&dpo, upf_app_dpo_type, fib_proto_to_dpo (pfx.fp_proto),
               app_dpo - appentry->app_dpos);
      app_dpo->dpoi_index = dpo.dpoi_index;
      fib_table_entry_special_dpo_add (
        app_dpo->is_ip4 ? appentry->fib_index_ip4 : appentry->fib_index_ip6,
        &pfx, FIB_SOURCE_SPECIAL,
        FIB_ENTRY_FLAG_EXCLUSIVE | FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, &dpo);
    }
}

void
upf_app_fib_cleanup (upf_adf_entry_t *appentry)
{
  upf_app_dpo_t *app_dpo;

  if (!appentry->app_dpos)
    return;

  vec_foreach (app_dpo, appentry->app_dpos)
    {
      acl_rule_t *rule = vec_elt_at_index (appentry->acl, app_dpo->rule_index);
      fib_prefix_t pfx;
      if (acl_addr_is_any (&rule->address[IPFILTER_RULE_FIELD_SRC]))
        {
          pfx.fp_addr.as_u64[0] = 0;
          pfx.fp_addr.as_u64[1] = 0;
        }
      else
        {
          pfx.fp_addr.as_u64[0] =
            rule->address[IPFILTER_RULE_FIELD_SRC].address.as_u64[0];
          pfx.fp_addr.as_u64[1] =
            rule->address[IPFILTER_RULE_FIELD_SRC].address.as_u64[1];
        }
      pfx.fp_proto = app_dpo->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
      pfx.fp_len = app_dpo->src_preflen;
      upf_debug ("del pfx: is_ip4 %d fp_len %d IP %U", app_dpo->is_ip4,
                 pfx.fp_len, format_ip46_address, &pfx.fp_addr, IP46_TYPE_ANY);
      fib_table_entry_special_remove (
        app_dpo->is_ip4 ? appentry->fib_index_ip4 : appentry->fib_index_ip6,
        &pfx, FIB_SOURCE_SPECIAL);
    }

  /*
    FIXME: this crashes due to extra entries in the DPOs:
    fib_table_unlock (appentry->fib_index_ip4, FIB_PROTOCOL_IP4,
    app_fib_source); fib_table_unlock (appentry->fib_index_ip6,
    FIB_PROTOCOL_IP6, app_fib_source); appentry->fib_index_ip4 = ~0;
    appentry->fib_index_ip6 = ~0;
  */
  vec_free (appentry->app_dpos);

  appentry->app_dpos = 0;
}

u8
upf_app_dpo_match (upf_adf_entry_t *appentry, flow_entry_t *flow,
                   ip46_address_t *assigned)
{
  if (appentry->fib_index_ip4 == ~0)
    return 0;
  return upf_do_ip_rule_match (
    appentry,
    &flow->key.ip[FTK_EL_SRC ^ FT_RESPONDER ^ flow->flow_key_direction],
    clib_net_to_host_u16 (
      flow->key.port[FTK_EL_SRC ^ FT_RESPONDER ^ flow->flow_key_direction]),
    &flow->key.ip[FTK_EL_SRC ^ FT_INITIATOR ^ flow->flow_key_direction],
    clib_net_to_host_u16 (
      flow->key.port[FTK_EL_SRC ^ FT_INITIATOR ^ flow->flow_key_direction]),
    assigned);
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
  /* index_t index = va_arg (*ap, index_t); */
  /* upf_session_t *sx = upf_session_dpo_get (index); */

  /* s = */
  /*   format (s, "UPF session: UP SEID: 0x%016" PRIx64 " (@%p)", sx->cp_seid,
   */
  /*           sx); */
  /* return (s); */
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
