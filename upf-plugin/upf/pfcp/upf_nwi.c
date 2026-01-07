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

#include "upf/pfcp/upf_nwi.h"
#include "upf/integrations/upf_ipfix.h"
#include "upf/upf.h"
#include "upf/upf_stats.h"

static upf_nwi_t *
_upf_nwi_ensure_by_name (upf_nwi_name_t name)
{
  upf_main_t *um = &upf_main;

  upf_nwi_t *nwi = upf_nwi_get_by_name (name);
  if (nwi)
    return nwi;

  pool_get_zero (um->nwis, nwi);

  nwi->_default_interface_id = ~0;
  nwi->_default_gtpu_endpoint_id = ~0;
  memset (nwi->interfaces_ids, ~0, sizeof (nwi->interfaces_ids));
  memset (nwi->gtpu_endpoints_ids, ~0, sizeof (nwi->gtpu_endpoints_ids));
  nwi->nat_pool_id = ~0;

  nwi->name = vec_dup (name);

  hash_set_mem (um->nwi_index_by_name, nwi->name, nwi - um->nwis);

  upf_stats_ensure_nwi (nwi - um->nwis, name);

  return nwi;
}

static int
_upf_nwi_interface_create (
  upf_nwi_name_t name, upf_interface_type_t intf, u32 rx_ip4_table_id,
  u32 rx_ip6_table_id, u32 tx_ip4_table_id, u32 tx_ip6_table_id,
  upf_ipfix_policy_t ipfix_policy, ip_address_t *ipfix_collector_ip,
  u32 ipfix_report_interval, u32 observation_domain_id,
  u8 *observation_domain_name, u64 observation_point_id)
{
  upf_main_t *um = &upf_main;
  vlib_main_t *vm = vlib_get_main ();

  upf_nwi_t *nwi = _upf_nwi_ensure_by_name (name);

  bool is_default = !is_valid_id (intf);
  if (is_default)
    {
      if (is_valid_id (nwi->_default_interface_id))
        return VNET_API_ERROR_IF_ALREADY_EXISTS;
    }
  else
    {
      if (nwi->interfaces_ids[intf] != nwi->_default_interface_id)
        return VNET_API_ERROR_IF_ALREADY_EXISTS;
    }

  bool barrier = pool_get_will_expand (um->nwis);
  if (barrier)
    vlib_worker_thread_barrier_sync (vm);

  upf_interface_t *nwif;
  pool_get_zero (um->nwi_interfaces, nwif);

  if (barrier)
    vlib_worker_thread_barrier_release (vm);

  uword nwif_id = nwif - um->nwi_interfaces;

  memset (&nwif->rx_fib_index, ~0, sizeof (nwif->rx_fib_index));
  memset (&nwif->tx_fib_index, ~0, sizeof (nwif->tx_fib_index));

  nwif->nwi_id = nwi - um->nwis;
  nwif->intf = intf;
  nwif->ipfix.default_policy = ipfix_policy;

  if (ipfix_collector_ip)
    ip_address_copy (&nwif->ipfix.collector_ip, ipfix_collector_ip);

  u32 rx_fib4_id = fib_table_find (FIB_PROTOCOL_IP4, rx_ip4_table_id);
  u32 rx_fib6_id = fib_table_find (FIB_PROTOCOL_IP6, rx_ip6_table_id);
  u32 tx_fib4_id = fib_table_find (FIB_PROTOCOL_IP4, tx_ip4_table_id);
  u32 tx_fib6_id = fib_table_find (FIB_PROTOCOL_IP6, tx_ip6_table_id);

  nwif->rx_fib_index[FIB_PROTOCOL_IP4] = rx_fib4_id;
  nwif->rx_fib_index[FIB_PROTOCOL_IP6] = rx_fib6_id;
  nwif->tx_fib_index[FIB_PROTOCOL_IP4] = tx_fib4_id;
  nwif->tx_fib_index[FIB_PROTOCOL_IP6] = tx_fib6_id;

  nwif->ipfix.report_interval = ipfix_report_interval;
  nwif->ipfix.observation_domain_id = observation_domain_id;
  nwif->ipfix.observation_domain_name = vec_dup (observation_domain_name);
  nwif->ipfix.observation_point_id = observation_point_id;

  for (fib_protocol_t fproto = 0; fproto < FIB_PROTOCOL_IP_MAX; fproto++)
    for (upf_ipfix_policy_t pol = 0; pol < UPF_IPFIX_N_POLICIES; pol++)
      nwif->ipfix.contexts[fproto][pol] = ~0;

  // Try to precreate configured ipfix context to start sending ipfix templates
  if (ipfix_collector_ip && ipfix_policy != UPF_IPFIX_POLICY_NONE)
    {
      upf_ipfix_context_key_t context_key = { 0 };
      ip_address_copy (&context_key.collector_ip, &nwif->ipfix.collector_ip);
      context_key.observation_domain_id = nwif->ipfix.observation_domain_id;
      context_key.policy = ipfix_policy;

      context_key.is_ip4 = true;
      nwif->ipfix.contexts[FIB_PROTOCOL_IP4][ipfix_policy] =
        upf_ipfix_ensure_context (&context_key);

      context_key.is_ip4 = false;
      nwif->ipfix.contexts[FIB_PROTOCOL_IP6][ipfix_policy] =
        upf_ipfix_ensure_context (&context_key);
    }

  if (is_default)
    {
      nwi->_default_interface_id = nwif_id;

      for (int i = 0; i < UPF_INTERFACE_N_TYPE; i++)
        if (!is_valid_id (nwi->interfaces_ids[i]))
          nwi->interfaces_ids[i] = nwif_id;
    }
  else
    {
      nwi->interfaces_ids[intf] = nwif_id;
    }

  return 0;
}

static int
_upf_nwi_interface_remove (upf_nwi_name_t name, upf_interface_type_t intf)
{
  upf_main_t *um = &upf_main;
  vlib_main_t *vm = vlib_get_main ();

  upf_nwi_t *nwi = upf_nwi_get_by_name (name);
  if (!nwi)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  bool is_default = !is_valid_id (intf);
  u16 nwif_id =
    is_default ? nwi->_default_interface_id : nwi->interfaces_ids[intf];

  if (!is_valid_id (nwif_id))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  upf_interface_t *nwif = pool_elt_at_index (um->nwi_interfaces, nwif_id);

  if (is_default)
    {
      nwi->_default_interface_id = ~0;

      for (int i = 0; i < UPF_INTERFACE_N_TYPE; i++)
        if (nwi->interfaces_ids[i] == nwif_id)
          nwi->interfaces_ids[i] = ~0;
    }
  else
    {
      nwi->interfaces_ids[intf] = ~0;
    }

  vec_free (nwif->ipfix.observation_domain_name);

  bool barrier = pool_put_will_expand (um->nwi_interfaces, nwif);
  if (barrier)
    vlib_worker_thread_barrier_sync (vm);

  pool_put (um->nwi_interfaces, nwif);

  if (barrier)
    vlib_worker_thread_barrier_release (vm);

  clib_warning ("NWI Interface removal is unsafe. Session can become invalid");

  return 0;
}

int
upf_nwi_interface_add_del (
  upf_nwi_name_t name, upf_interface_type_t intf, u32 rx_ip4_table_id,
  u32 rx_ip6_table_id, u32 tx_ip4_table_id, u32 tx_ip6_table_id,
  upf_ipfix_policy_t ipfix_policy, ip_address_t *ipfix_collector_ip,
  u32 ipfix_report_interval, u32 observation_domain_id,
  u8 *observation_domain_name, u64 observation_point_id, u8 add)
{
  return (add) ?
           _upf_nwi_interface_create (
             name, intf, rx_ip4_table_id, rx_ip6_table_id, tx_ip4_table_id,
             tx_ip6_table_id, ipfix_policy, ipfix_collector_ip,
             ipfix_report_interval, observation_domain_id,
             observation_domain_name, observation_point_id) :
           _upf_nwi_interface_remove (name, intf);
}

upf_nwi_t *
upf_nwi_get_by_name (upf_nwi_name_t name)
{
  upf_main_t *um = &upf_main;
  uword *p;

  p = hash_get_mem (um->nwi_index_by_name, name);
  if (!p)
    return NULL;

  return pool_elt_at_index (um->nwis, p[0]);
}

u32
upf_interface_get_table_id (upf_interface_t *nwif, bool is_tx, bool is_ip4)
{
  fib_protocol_t fib_proto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  u32 fib_index = (is_tx ? nwif->tx_fib_index : nwif->rx_fib_index)[fib_proto];

  if (!is_valid_id (fib_index))
    return ~0;

  return fib_table_get_table_id (fib_index, fib_proto);
}

upf_interface_type_t
upf_interface_type_from_pfcp_source_interface_ie (
  pfcp_ie_source_interface_t ie)
{
  switch (ie)
    {
    default:
      return -1;
    case PFCP_SRC_INTF_ACCESS:
      return UPF_INTERFACE_TYPE_ACCESS;
    case PFCP_SRC_INTF_CORE:
      return UPF_INTERFACE_TYPE_CORE;
    case PFCP_SRC_INTF_SGI_LAN:
      return UPF_INTERFACE_TYPE_SGI_LAN;
    case PFCP_SRC_INTF_CP:
      return UPF_INTERFACE_TYPE_CP;
    }
}

upf_interface_type_t
upf_interface_type_from_pfcp_destination_interface_ie (
  pfcp_ie_destination_interface_t ie)
{
  switch (ie)
    {
    default:
      return -1;
    case PFCP_DST_INTF_ACCESS:
      return UPF_INTERFACE_TYPE_ACCESS;
    case PFCP_DST_INTF_CORE:
      return UPF_INTERFACE_TYPE_CORE;
    case PFCP_DST_INTF_SGI_LAN:
      return UPF_INTERFACE_TYPE_SGI_LAN;
    case PFCP_DST_INTF_CP:
      return UPF_INTERFACE_TYPE_CP;
    }
}

u8 *
format_upf_interface_type (u8 *s, va_list *args)
{
  upf_interface_type_t intf = va_arg (*args, int);

  switch (intf)
    {
    case UPF_INTERFACE_TYPE_ACCESS:
      return format (s, "access");
    case UPF_INTERFACE_TYPE_CORE:
      return format (s, "core");
    case UPF_INTERFACE_TYPE_SGI_LAN:
      return format (s, "sgi");
    case UPF_INTERFACE_TYPE_CP:
      return format (s, "cp");
    case UPF_INTERFACE_DEFAULT_TYPE:
      return format (s, "default");
    default:
      return format (s, "intf(%u)", intf);
    }
}

uword
unformat_upf_interface_type (unformat_input_t *input, va_list *args)
{
  upf_interface_type_t *result = va_arg (*args, upf_interface_type_t *);

  if (unformat (input, "access"))
    *result = UPF_INTERFACE_TYPE_ACCESS;
  else if (unformat (input, "core"))
    *result = UPF_INTERFACE_TYPE_CORE;
  else if (unformat (input, "sgi"))
    *result = UPF_INTERFACE_TYPE_SGI_LAN;
  else if (unformat (input, "cp"))
    *result = UPF_INTERFACE_TYPE_CP;
  else
    return 0;

  return 1;
}
