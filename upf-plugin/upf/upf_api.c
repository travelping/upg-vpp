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

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>
#include <upf/upf.api_enum.h>
#include <upf/upf.api_types.h>
#include <vnet/ip/ip6_hop_by_hop.h>

#include "upf/upf.h"
#include "upf/rules/upf_ipfilter.h"
#include "upf/pfcp/upf_pfcp_server.h"
#include "upf/integrations/upf_ipfix.h"
#include "upf/integrations/upf_ueip_export.h"
#include "upf/nat/nat.h"
#include "upf/adf/adf.h"
#include "upf/rules/upf_session_dpo.h"

#define REPLY_MSG_ID_BASE um->msg_id_base
#include <vlibapi/api_helper_macros.h>

#define UPF_DEBUG_ENABLE 0

static u8 *
vec_from_cstring (u8 *cstr, size_t maxsize)
{
  u8 *result = NULL;
  int len = clib_strnlen ((char *) cstr, maxsize);
  vec_validate (result, len - 1);
  memcpy (result, cstr, len);
  return result;
}

/* API message handler */
static void
vl_api_adf_create_application_t_handler (vl_api_adf_create_application_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_adf_create_application_reply_t *rmp;

  u8 *app_name = vec_from_cstring (mp->name, sizeof (mp->name));

  vnet_api_error_t rv = upf_adf_app_create (app_name);

  vec_free (app_name);

  REPLY_MACRO (VL_API_ADF_CREATE_APPLICATION_REPLY);
}

/* API message handler */
static void
vl_api_adf_delete_application_t_handler (vl_api_adf_delete_application_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_adf_delete_application_reply_t *rmp;

  u32 rv = -1; /* unimplemented */

  REPLY_MACRO (VL_API_ADF_DELETE_APPLICATION_REPLY);
}

/* API message handler */
static void
vl_api_adf_application_dump_t_handler (vl_api_adf_version_drop_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_registration_t *reg;
  vl_api_adf_application_details_t *rmp = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  upf_adf_app_t *app = NULL;
  pool_foreach (app, um->adf_main.apps)
    {
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id =
        htons (VL_API_ADF_APPLICATION_DETAILS + um->msg_id_base);
      rmp->context = mp->context;

      memcpy (rmp->name, app->name, vec_len (app->name));
      rmp->flags = 0;

      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

/* API message handler */
static void
vl_api_adf_create_version_t_handler (vl_api_adf_create_version_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_adf_create_version_reply_t *rmp;
  vnet_api_error_t rv;

  u8 *app_name = vec_from_cstring (mp->app_name, sizeof (mp->app_name));

  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);
  if (!app)
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  else
    rv = upf_adf_app_version_create (app, NULL);

  vec_free (app_name);

  REPLY_MACRO (VL_API_ADF_CREATE_VERSION_REPLY);
}

/* API message handler */
static void
vl_api_adf_add_ip_rule_t_handler (vl_api_adf_add_ip_rule_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_adf_add_ip_rule_reply_t *rmp;
  vnet_api_error_t rv;

  u8 *app_name = vec_from_cstring (mp->app_name, sizeof (mp->app_name));

  unformat_input_t in;
  unformat_init_string (&in, (char *) mp->rule,
                        clib_strnlen ((char *) mp->rule, sizeof (mp->rule)));

  ipfilter_rule_t rule;
  uword urv = unformat_user (&in, unformat_upf_ipfilter, &rule);
  unformat_free (&in);

  if (urv == 0)
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto end;
    }

  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);
  if (!app)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto end;
    }

  rv = upf_adf_app_rule_create_by_acl (app, &rule);

end:
  vec_free (app_name);

  REPLY_MACRO (VL_API_ADF_ADD_IP_RULE_REPLY);
}

/* API message handler */
static void
vl_api_adf_add_l7_rule_t_handler (vl_api_adf_add_l7_rule_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_adf_add_l7_rule_reply_t *rmp;

  u8 *v_regex = vec_from_cstring (mp->regex, sizeof (mp->regex));
  u8 *app_name = vec_from_cstring (mp->app_name, sizeof (mp->app_name));

  vnet_api_error_t rv;

  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);
  if (!app)
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  else
    rv = upf_adf_app_rule_create_by_regexp (app, v_regex);

  vec_free (app_name);
  vec_free (v_regex);

  REPLY_MACRO (VL_API_ADF_ADD_L7_RULE_REPLY);
}

/* API message handler */
static void
vl_api_adf_version_commit_t_handler (vl_api_adf_version_commit_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_adf_version_commit_reply_t *rmp;

  u8 *app_name = vec_from_cstring (mp->app_name, sizeof (mp->app_name));

  vnet_api_error_t rv;
  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);
  if (!app)
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  else
    rv = upf_adf_commit_version (app);

  vec_free (app_name);

  REPLY_MACRO (VL_API_ADF_VERSION_COMMIT_REPLY);
}

/* API message handler */
static void
vl_api_adf_version_drop_t_handler (vl_api_adf_version_drop_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_adf_version_drop_reply_t *rmp;

  u8 *app_name = vec_from_cstring (mp->app_name, sizeof (mp->app_name));

  vnet_api_error_t rv;
  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);
  if (!app)
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  else
    rv = upf_adf_drop_uncommited_version (app);

  REPLY_MACRO (VL_API_ADF_VERSION_DROP_REPLY);
}

/* API message handler */
static void
vl_api_adf_active_version_dump_t_handler (vl_api_adf_version_drop_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_registration_t *reg;
  vl_api_adf_active_version_details_t *rmp = NULL;
  vnet_api_error_t rv = 0;

  u8 *app_name = vec_from_cstring (mp->app_name, sizeof (mp->app_name));

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto end;
    }

  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);
  if (!app)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto end;
    }

  if (!is_valid_id (app->active_ver_idx))
    goto end;

  upf_adf_app_version_t *ver =
    pool_elt_at_index (um->adf_main.versions, app->active_ver_idx);

  if (!ver)
    {
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto end;
    }

  upf_adf_rule_t *rule = NULL;
  pool_foreach (rule, ver->rules)
    {
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id =
        htons (VL_API_ADF_ACTIVE_VERSION_DETAILS + um->msg_id_base);
      rmp->context = mp->context;

      if (rule->regex)
        {
          rmp->is_regex = 1;
          memcpy (rmp->rule, rule->regex, vec_len (rule->regex));
        }
      else
        {
          rmp->is_regex = 0;
          u8 *str = format (0, "%U", format_upf_ipfilter, &rule->acl_rule);
          memcpy (rmp->rule, str, vec_len (str));
          vec_free (str);
        }

      vl_api_send_msg (reg, (u8 *) rmp);
    }

end:
  if (rv != 0)
    clib_warning ("api adf_active_version_details error %U for app %v",
                  format_vnet_api_errno, rv, app_name);

  vec_free (app_name);
}

static void
vl_api_upf_pfcp_reencode_t_handler (vl_api_upf_pfcp_reencode_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_upf_pfcp_reencode_reply_t *rmp;
  pfcp_decoded_msg_t dmsg;
  pfcp_ie_offending_ie_t *err = 0;
  u8 *reply_data = 0;
  int rv = 0;
  int data_len = 0, packet_len = clib_net_to_host_u32 (mp->packet_len);

  if ((rv = pfcp_decode_msg (mp->packet, packet_len, &dmsg, &err)) != 0)
    {
      pfcp_ie_offending_ie_t *cur_err;
      vec_foreach (cur_err, err)
        {
          clib_warning ("offending IE: %d", *cur_err);
        }
      clib_warning ("pfcp_decode_msg failed, rv=%d", rv);
      vec_free (err);
      goto reply;
    }

  rv = pfcp_encode_msg (&dmsg, &reply_data);
  data_len = vec_len (reply_data);

reply:
  REPLY_MACRO3_ZERO (VL_API_UPF_PFCP_REENCODE_REPLY, data_len, {
    rmp->packet_len = clib_host_to_net_u32 (data_len);
    if (data_len)
      clib_memcpy (rmp->packet, reply_data, data_len);
  });

  pfcp_free_dmsg_contents (&dmsg);
  vec_free (reply_data);
}

static void
vl_api_upf_pfcp_format_t_handler (vl_api_upf_pfcp_reencode_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_upf_pfcp_format_reply_t *rmp;
  pfcp_decoded_msg_t dmsg;
  pfcp_ie_offending_ie_t *err = 0;
  u8 *s;
  /* pfcp_ie_offending_ie_t *err = NULL; */
  int rv = 0;
  int text_len = 0, packet_len = clib_net_to_host_u32 (mp->packet_len);

  if ((rv = pfcp_decode_msg (mp->packet, packet_len, &dmsg, &err)) != 0)
    {
      pfcp_ie_offending_ie_t *cur_err;
      vec_foreach (cur_err, err)
        {
          clib_warning ("offending IE: %d", *cur_err);
        }
      clib_warning ("pfcp_decode_msg failed, rv=%d", rv);
      vec_free (err);
      goto reply;
    }

  s = format (0, "%U\n", format_pfcp_dmsg, &dmsg);

  text_len = vec_len (s);

reply:
  REPLY_MACRO3_ZERO (VL_API_UPF_PFCP_FORMAT_REPLY, text_len, {
    rmp->text_len = clib_host_to_net_u32 (text_len);
    if (text_len)
      clib_memcpy (rmp->text, s, text_len);
  });

  if (s != 0)
    vec_free (s);
}

static void
send_upf_nat_pool_details (vl_api_registration_t *reg,
                           upf_nat_pool_t *nat_pool, u32 context)
{
  vl_api_upf_nat_pool_details_t *mp;
  upf_main_t *um = &upf_main;

  upf_interface_t *nwif =
    pool_elt_at_index (um->nwi_interfaces, nat_pool->nwif_id);
  upf_nwi_t *nwi = pool_elt_at_index (um->nwis, nwif->nwi_id);
  u32 nwi_name_len = vec_len (nwi->name);

  mp = vl_msg_api_alloc (sizeof (*mp) + nwi_name_len * sizeof (u8));
  clib_memset (mp, 0, sizeof (*mp) + nwi_name_len * sizeof (u8));

  memcpy (mp->nwi, nwi->name, nwi_name_len);
  mp->nwi_len = nwi_name_len;

  mp->_vl_msg_id = htons (VL_API_UPF_NAT_POOL_DETAILS + um->msg_id_base);
  mp->context = context;

  nwi_name_len = clib_min (sizeof (mp->name) - 1, vec_len (nat_pool->name));
  memcpy (mp->name, nat_pool->name, nwi_name_len);
  mp->name[nwi_name_len] = 0;

  u32 max_users = nat_pool->addr_count * nat_pool->blocks_per_addr;
  mp->max_users = htonl (max_users);

  mp->current_users = htonl (nat_pool->used_blocks);

  mp->block_size = htons (nat_pool->ports_per_block);

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void
vl_api_upf_nat_pool_dump_t_handler (vl_api_upf_nat_pool_dump_t *mp)
{
  upf_nat_main_t *unm = &upf_nat_main;
  vl_api_registration_t *reg;
  upf_nat_pool_t *np = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  pool_foreach (np, unm->nat_pools)
    {
      send_upf_nat_pool_details (reg, np, mp->context);
    }
}

/* API message handler */
static void
vl_api_upf_policy_add_del_t_handler (vl_api_upf_policy_add_del_t *mp)
{
  vl_api_upf_policy_add_del_reply_t *rmp = NULL;
  upf_main_t *um = &upf_main;
  int rv = 0;

  /* Make sure ID is null terminated */
  mp->identifier[sizeof (mp->identifier) - 1] = 0;

  u8 action = mp->action;
  u8 *policy_id = format (0, "%s", mp->identifier);
  u32 ip4_table_id = clib_net_to_host_u32 (mp->ip4_table_id);
  u32 ip6_table_id = clib_net_to_host_u32 (mp->ip6_table_id);

  clib_error_t *err = upf_forwarding_policy_add_del (policy_id, ip4_table_id,
                                                     ip6_table_id, action);
  if (err)
    {
      rv = err->code;
      clib_error_free (err);
    }

  vec_free (policy_id);

  REPLY_MACRO (VL_API_UPF_POLICY_ADD_DEL_REPLY);
}

static void
_send_upf_policy_details (vl_api_registration_t *reg,
                          upf_forwarding_policy_t *fp, u32 context)
{
  vl_api_upf_policy_details_t *mp;
  upf_main_t *um = &upf_main;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_UPF_POLICY_DETAILS + um->msg_id_base);
  mp->context = context;

  u32 len = clib_min (sizeof (mp->identifier) - 1, vec_len (fp->policy_id));
  memcpy (mp->identifier, fp->policy_id, len);
  mp->identifier[len] = 0;

  mp->ip4_table_id =
    clib_host_to_net_u32 (upf_forwarding_policy_get_table_id (fp, 1));
  mp->ip6_table_id =
    clib_host_to_net_u32 (upf_forwarding_policy_get_table_id (fp, 0));

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void
vl_api_upf_policy_dump_t_handler (vl_api_upf_policy_dump_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_registration_t *reg;
  upf_forwarding_policy_t *fp = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  pool_foreach (fp, um->forwarding_policies)
    {
      if (fp->is_removed)
        continue;

      _send_upf_policy_details (reg, fp, mp->context);
    }
}

/* API message handler */
static void
vl_api_upf_nwi_add_del_t_handler (vl_api_upf_nwi_add_del_t *mp)
{
  vl_api_upf_nwi_add_del_reply_t *rmp = NULL;
  upf_main_t *um = &upf_main;
  u8 *nwi_name = 0;
  u32 ip4_table_id, ip6_table_id, tx_ip4_table_id, tx_ip6_table_id;
  bool ok;
  u8 *ipfix_policy_name;
  upf_ipfix_policy_t ipfix_policy = UPF_IPFIX_POLICY_NONE;
  int rv = 0;
  ip_address_t ipfix_collector_ip;
  u32 ipfix_report_interval;
  u32 observation_domain_id;
  u8 *observation_domain_name = 0;
  u64 observation_point_id;

  if (mp->nwi_len == 0)
    {
      upf_debug ("NWI name not specified");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  vec_validate (nwi_name, mp->nwi_len - 1);
  memcpy (nwi_name, mp->nwi, mp->nwi_len);
  ip4_table_id = clib_net_to_host_u32 (mp->ip4_table_id);
  ip6_table_id = clib_net_to_host_u32 (mp->ip6_table_id);
  tx_ip4_table_id = clib_net_to_host_u32 (mp->tx_ip4_table_id);
  tx_ip6_table_id = clib_net_to_host_u32 (mp->tx_ip6_table_id);

  /*
   * If just one of the table IDs is present in a request, use it for
   * both IPv4 and IPv6. But at least one of the IDs must be specified
   */
  if (ip4_table_id == (u32) ~0)
    ip4_table_id = ip6_table_id;
  else if (ip6_table_id == (u32) ~0)
    ip6_table_id = ip4_table_id;
  if (ip4_table_id == (u32) ~0)
    {
      upf_debug ("At least one of ip[46]_table_id should be defined");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  if (!is_valid_id (tx_ip4_table_id))
    tx_ip4_table_id = ip4_table_id;
  if (!is_valid_id (tx_ip6_table_id))
    tx_ip6_table_id = ip6_table_id;

  if (mp->ipfix_policy[0])
    {
      mp->ipfix_policy[sizeof (mp->ipfix_policy) - 1] = 0;
      ipfix_policy_name = format (0, "%s", mp->ipfix_policy);
      ipfix_policy = upf_ipfix_lookup_policy (ipfix_policy_name, &ok);
      vec_free (ipfix_policy_name);
      if (!ok)
        {
          upf_debug ("Invalid IPFIX policy '%s'", mp->ipfix_policy);
          rv = VNET_API_ERROR_INVALID_VALUE;
          goto out;
        }
    }

  ip_address_decode (&mp->ipfix_collector_ip, &ipfix_collector_ip.ip);
  ipfix_collector_ip.version =
    ip46_address_is_ip4 (&ipfix_collector_ip.ip) ? AF_IP4 : AF_IP6;

  ipfix_report_interval = clib_net_to_host_u32 (mp->ipfix_report_interval);
  observation_domain_id = clib_net_to_host_u32 (mp->observation_domain_id);
  if (mp->observation_domain_name[0])
    {
      mp->observation_domain_name[sizeof (mp->observation_domain_name) - 1] =
        0;
      observation_domain_name = format (0, "%s", mp->observation_domain_name);
    }
  observation_point_id = clib_net_to_host_u64 (mp->observation_point_id);

  upf_interface_type_t intf =
    UPF_INTERFACE_DEFAULT_TYPE; // TODO: pass from API

  rv = upf_nwi_interface_add_del (
    nwi_name, intf, ip4_table_id, ip6_table_id, tx_ip4_table_id,
    tx_ip6_table_id, ipfix_policy, &ipfix_collector_ip, ipfix_report_interval,
    observation_domain_id, observation_domain_name, observation_point_id,
    mp->add);

out:
  vec_free (nwi_name);
  vec_free (observation_domain_name);
  REPLY_MACRO (VL_API_UPF_NWI_ADD_DEL_REPLY);
}

static void
_upf_send_nwi_interface_details (vl_api_registration_t *reg,
                                 upf_interface_t *nwif, u32 context)
{
  vl_api_upf_nwi_details_t *mp;
  upf_main_t *um = &upf_main;
  upf_nwi_t *nwi = pool_elt_at_index (um->nwis, nwif->nwi_id);

  u32 name_len = vec_len (nwi->name);

  mp = vl_msg_api_alloc (sizeof (*mp) + name_len * sizeof (u8));
  clib_memset (mp, 0, sizeof (*mp) + name_len * sizeof (u8));

  mp->_vl_msg_id = htons (VL_API_UPF_NWI_DETAILS + um->msg_id_base);
  mp->context = context;

  mp->ip4_table_id =
    clib_host_to_net_u32 (upf_interface_get_table_id (nwif, 0, 1));
  mp->ip6_table_id =
    clib_host_to_net_u32 (upf_interface_get_table_id (nwif, 0, 0));
  mp->tx_ip4_table_id =
    clib_host_to_net_u32 (upf_interface_get_table_id (nwif, 1, 1));
  mp->tx_ip6_table_id =
    clib_host_to_net_u32 (upf_interface_get_table_id (nwif, 1, 0));

  u8 *ipfix_policy =
    format (0, "%U", format_upf_ipfix_policy, nwif->ipfix.default_policy);
  u32 ipfix_policy_len =
    clib_min (sizeof (mp->ipfix_policy) - 1, vec_len (ipfix_policy));
  memcpy (mp->ipfix_policy, ipfix_policy, ipfix_policy_len);
  mp->ipfix_policy[ipfix_policy_len] = 0;

  mp->ipfix_report_interval =
    clib_host_to_net_u32 (nwif->ipfix.report_interval);
  mp->observation_domain_id =
    clib_host_to_net_u32 (nwif->ipfix.observation_domain_id);
  u32 observation_domain_name_len =
    clib_min (sizeof (mp->observation_domain_name) - 1,
              vec_len (nwif->ipfix.observation_domain_name));
  memcpy (mp->observation_domain_name, nwif->ipfix.observation_domain_name,
          observation_domain_name_len);
  mp->observation_domain_name[observation_domain_name_len] = 0;
  mp->observation_point_id =
    clib_host_to_net_u64 (nwif->ipfix.observation_point_id);

  memcpy (mp->nwi, nwi->name, name_len);
  mp->nwi_len = name_len;

  ip_address_encode (&ip_addr_46 (&nwif->ipfix.collector_ip), IP46_TYPE_ANY,
                     &mp->ipfix_collector_ip);

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void
vl_api_upf_nwi_dump_t_handler (vl_api_upf_nwi_dump_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  upf_interface_t *nwif = NULL;
  pool_foreach (nwif, um->nwi_interfaces)
    {
      _upf_send_nwi_interface_details (reg, nwif, mp->context);
    }
}

/* API message handler */
static void
vl_api_upf_pfcp_endpoint_add_del_t_handler (
  vl_api_upf_pfcp_endpoint_add_del_t *mp)
{
  vl_api_upf_pfcp_endpoint_add_del_reply_t *rmp = NULL;
  upf_main_t *um = &upf_main;
  u32 vrf;
  u32 fib_index = 0;
  u8 is_add;
  ip46_address_t ip_addr;
  int rv = 0;

  is_add = mp->is_add;
  vrf = clib_net_to_host_u32 (mp->table_id);

  ip_address_decode (&mp->ip, &ip_addr);
  if (ip46_address_is_zero (&ip_addr))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      upf_debug ("IP should be provided");
      goto out;
    }

  if (is_valid_id (vrf))
    {
      fib_index =
        fib_table_find (fib_ip_proto (!ip46_address_is_ip4 (&ip_addr)), vrf);
      if (!is_valid_id (fib_index))
        {
          rv = VNET_API_ERROR_NO_SUCH_TABLE;
          upf_debug ("nonexistent vrf %d", vrf);
          goto out;
        }
    }

  rv = upf_pfcp_endpoint_add_del (&ip_addr, fib_index, is_add);

out:

  REPLY_MACRO (VL_API_UPF_PFCP_ENDPOINT_ADD_DEL_REPLY);
}

static void
send_upf_pfcp_endpoint_details (vl_api_registration_t *reg,
                                upf_pfcp_endpoint_key_t *key, u32 context)
{
  vl_api_upf_pfcp_endpoint_details_t *mp;
  upf_main_t *um = &upf_main;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_UPF_PFCP_ENDPOINT_DETAILS + um->msg_id_base);
  mp->context = context;

  mp->table_id = htonl (fib_table_get_table_id (
    key->fib_index,
    ip46_address_is_ip4 (&key->addr) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6));

  ip_address_encode (&key->addr, IP46_TYPE_ANY, &mp->ip);

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void
vl_api_upf_pfcp_endpoint_dump_t_handler (vl_api_upf_pfcp_endpoint_dump_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_registration_t *reg;
  upf_pfcp_endpoint_key_t *key;
  uword *v;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  /* clang-format off */
  mhash_foreach(key, v, &um->pfcp_endpoint_index,
  ({
    send_upf_pfcp_endpoint_details (reg, key, mp->context);
  }));
  /* clang-format on */
}

/* API message handler */
static void
vl_api_upf_pfcp_server_set_t_handler (vl_api_upf_pfcp_server_set_t *mp)
{
  vl_api_upf_pfcp_server_set_reply_t *rmp = NULL;
  upf_main_t *um = &upf_main;
  u32 fifo_size = 0;
  u32 prealloc_fifos = 0;
  u64 segment_size = 0;
  int rv = 0;

  /* We get segment size in MB */
  segment_size = (u64) clib_net_to_host_u32 (mp->segment_size);
  if (segment_size >= 0x1000)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      upf_debug ("Segment size is too large");
      goto out;
    }
  segment_size <<= 20;

  /* We get fifo_size in KB */
  fifo_size = clib_net_to_host_u32 (mp->fifo_size);
  if (fifo_size >= 0x100000)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      upf_debug ("FIFO size is too large");
      goto out;
    }
  fifo_size <<= 10;
  prealloc_fifos = clib_net_to_host_u32 (mp->prealloc_fifos);

  rv = upf_pfcp_session_server_apply_config (segment_size, prealloc_fifos,
                                             fifo_size);

out:

  REPLY_MACRO (VL_API_UPF_PFCP_SERVER_SET_REPLY);
}

/* API message handler */
static void
vl_api_upf_pfcp_server_show_t_handler (vl_api_upf_pfcp_server_show_t *mp)
{
  vl_api_upf_pfcp_server_show_reply_t *rmp = NULL;
  upf_main_t *um = &upf_main;
  vl_api_registration_t *reg;
  u32 fifo_size = 0;
  u32 prealloc_fifos = 0;
  u64 segment_size = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id =
    htons (VL_API_UPF_PFCP_SERVER_SHOW_REPLY + um->msg_id_base);
  rmp->context = mp->context;

  upf_pfcp_session_server_get_config (&segment_size, &prealloc_fifos,
                                      &fifo_size);

  segment_size >>= 20;
  rmp->segment_size = htonl ((u32) segment_size);
  fifo_size >>= 10;
  rmp->fifo_size = htonl (fifo_size);
  rmp->prealloc_fifos = htonl (prealloc_fifos);

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* API message handler */
static void
vl_api_upf_pfcp_heartbeats_set_t_handler (vl_api_upf_pfcp_heartbeats_set_t *mp)
{
  vl_api_upf_pfcp_heartbeats_set_reply_t *rmp = NULL;
  upf_main_t *um = &upf_main;
  u32 timeout, retries;
  int rv = 0;

  retries = clib_net_to_host_u32 (mp->retries);
  timeout = clib_net_to_host_u32 (mp->timeout);

  rv = upf_pfcp_heartbeat_config (timeout, retries);

  REPLY_MACRO (VL_API_UPF_PFCP_HEARTBEATS_SET_REPLY);
}

/* API message handler */
static void
vl_api_upf_pfcp_heartbeats_get_t_handler (vl_api_upf_pfcp_heartbeats_get_t *mp)
{
  vl_api_upf_pfcp_heartbeats_get_reply_t *rmp = NULL;
  upf_main_t *um = &upf_main;
  pfcp_server_main_t *psm = &pfcp_server_main;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id =
    htons (VL_API_UPF_PFCP_HEARTBEATS_GET_REPLY + um->msg_id_base);
  rmp->context = mp->context;

  rmp->timeout = clib_host_to_net_u32 (psm->heartbeat_cfg.timeout);
  rmp->retries = clib_host_to_net_u32 (psm->heartbeat_cfg.retries);

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* API message handler */
static void
vl_api_upf_set_node_id_t_handler (vl_api_upf_set_node_id_t *mp)
{
  int rv = 0;
  upf_main_t *um = &upf_main;
  vl_api_upf_set_node_id_reply_t *rmp = NULL;

  pfcp_ie_node_id_t node_id = { 0 };
  node_id.type = mp->type;

  switch (mp->type)
    {
    case PFCP_NID_IPv4:
    case PFCP_NID_IPv6:
      ip_address_decode (&mp->ip, &node_id.ip);
      break;

    case PFCP_NID_FQDN:
      vec_validate (node_id.fqdn, mp->fqdn_len - 1);
      memcpy (node_id.fqdn, mp->fqdn, mp->fqdn_len);
      break;

    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
      break;
    }

  if (rv == 0)
    rv = upf_node_id_set (&node_id);

  free_pfcp_ie_node_id (&node_id);

  REPLY_MACRO (VL_API_UPF_SET_NODE_ID_REPLY);
}

/* API message handler */
static void
vl_api_upf_get_node_id_t_handler (vl_api_upf_get_node_id_t *mp)
{
  int rv = 0;
  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vl_api_upf_get_node_id_reply_t *rmp = NULL;
  upf_main_t *um = &upf_main;
  pfcp_ie_node_id_t *node = &um->node_id;

  switch (node->type)
    {
    case PFCP_NID_IPv4:
    case PFCP_NID_IPv6:
      {
        rmp = vl_msg_api_alloc (sizeof (*rmp));
        clib_memset (rmp, 0, sizeof (*rmp));

        ip_address_encode (&ip_addr_46 (node), IP46_TYPE_ANY, &rmp->ip);
        break;
      }
    case PFCP_NID_FQDN:
      {
        u8 len;
        len = vec_len (node->fqdn);

        rmp = vl_msg_api_alloc (sizeof (*rmp) + len * sizeof (u8));
        clib_memset (rmp, 0, sizeof (*rmp) + len * sizeof (u8));

        rmp->fqdn_len = len;
        memcpy (rmp->fqdn, node->fqdn, rmp->fqdn_len);
        break;
      }
    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
      break;
    }

  rmp->type = node->type;

  rmp->_vl_msg_id = htons (VL_API_UPF_GET_NODE_ID_REPLY + um->msg_id_base);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* API message handler */
static void
vl_api_upf_tdf_ul_enable_disable_t_handler (
  vl_api_upf_tdf_ul_enable_disable_t *mp)
{
  int rv = 0;
  upf_main_t *um = &upf_main;
  vl_api_upf_tdf_ul_enable_disable_reply_t *rmp = NULL;

  fib_protocol_t fproto = mp->is_ipv6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4;

  if (!mp->enable)
    rv = VNET_API_ERROR_UNIMPLEMENTED;

  if (rv == 0)
    upf_tdf_ul_enable_disable (fproto, mp->interface, mp->enable);

  REPLY_MACRO (VL_API_UPF_TDF_UL_ENABLE_DISABLE_REPLY);
}

static void
vl_api_upf_tdf_ul_table_t_handler (vl_api_upf_tdf_ul_table_t *mp)
{
  vl_api_registration_t *reg;
  u8 size, len = 0, out_index = 0;
  u32 ii;
  vl_api_upf_tdf_ul_table_reply_t *rmp = NULL;
  upf_main_t *um = &upf_main;
  fib_protocol_t fproto = mp->is_ipv6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach_index (ii, um->tdf_ul_table[fproto])
    {
      if (~0 != vec_elt (um->tdf_ul_table[fproto], ii))
        len++;
    }
  // convert number of mappings to number of elements in the vector
  len *= 2;

  size = sizeof (u32) * len;
  rmp = vl_msg_api_alloc (sizeof (*rmp) + size);
  clib_memset (rmp, 0, sizeof (*rmp) + size);
  rmp->mappings_len = len;

  vec_foreach_index (ii, um->tdf_ul_table[fproto])
    {
      if (~0 != vec_elt (um->tdf_ul_table[fproto], ii))
        {
          rmp->mappings[out_index++] =
            htonl (fib_table_get_table_id (ii, fproto));
          rmp->mappings[out_index++] = htonl (fib_table_get_table_id (
            vec_elt (um->tdf_ul_table[fproto], ii), fproto));
        }
    }

  rmp->_vl_msg_id = htons (VL_API_UPF_TDF_UL_TABLE_REPLY + um->msg_id_base);
  rmp->context = mp->context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* API message handler */
static void
vl_api_upf_tdf_ul_table_add_t_handler (vl_api_upf_tdf_ul_table_add_t *mp)
{
  int rv = 0;
  upf_main_t *um = &upf_main;
  vl_api_upf_tdf_ul_table_add_reply_t *rmp = NULL;

  fib_protocol_t fproto = mp->is_ipv6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4;

  rv = upf_tdf_ul_table_add_del (ntohl (mp->table_id), fproto,
                                 ntohl (mp->src_lookup_table_id), mp->is_add);

  REPLY_MACRO (VL_API_UPF_TDF_UL_TABLE_ADD_REPLY);
}

/* API message handler */
static void
vl_api_upf_ueip_pool_nwi_add_t_handler (vl_api_upf_ueip_pool_nwi_add_t *mp)
{
  int rv = 0;
  upf_main_t *um = &upf_main;
  vl_api_upf_ueip_pool_nwi_add_reply_t *rmp = NULL;

  u8 *nwi_name = mp->nwi_name;
  u8 *nwi_name_vec = 0;
  u8 *identity = mp->identity;
  u8 *identity_vec = 0;

  if (mp->identity_len > 64 || mp->nwi_name_len > 64)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }

  nwi_name_vec = vec_new (u8, mp->nwi_name_len);
  memcpy (nwi_name_vec, nwi_name, mp->nwi_name_len);

  identity_vec = vec_new (u8, mp->identity_len);
  memcpy (identity_vec, identity, mp->identity_len);

  rv = upf_ue_ip_pool_add_del (identity_vec, nwi_name_vec, mp->is_add);

  vec_free (identity_vec);
  vec_free (nwi_name_vec);

reply:
  REPLY_MACRO (VL_API_UPF_UEIP_POOL_NWI_ADD_REPLY);
}

/* API message handler */
static void
vl_api_upf_ueip_pool_dump_t_handler (vl_api_upf_ueip_pool_dump_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_registration_t *reg;
  vl_api_upf_ueip_pool_details_t *rmp = NULL;
  upf_ue_ip_pool_info_t *pool = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (pool, um->ueip_pools)
    {
      u8 nwi_name_len;
      u8 identity_len;

      nwi_name_len = vec_len (pool->nwi_name);
      ASSERT (nwi_name_len <= 64);
      identity_len = vec_len (pool->identity);
      ASSERT (identity_len <= 64);

      rmp = vl_msg_api_alloc (sizeof (*rmp) + nwi_name_len);
      clib_memset (rmp, 0, sizeof (*rmp) + nwi_name_len);
      rmp->_vl_msg_id = htons (VL_API_UPF_UEIP_POOL_DETAILS + um->msg_id_base);
      rmp->context = mp->context;

      rmp->nwi_name_len = nwi_name_len;
      memcpy (rmp->nwi_name, pool->nwi_name, nwi_name_len);
      memcpy (rmp->identity, pool->identity, identity_len);
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

/* API message handler */
static void
vl_api_upf_nat_pool_add_t_handler (vl_api_upf_nat_pool_add_t *mp)
{
  int rv = 0;
  upf_main_t *um = &upf_main;
  vl_api_upf_nat_pool_add_reply_t *rmp = NULL;

  u8 *name_vec = 0;
  u8 *nwi_vec = 0;
  ip4_address_t start, end;

  mp->min_port = ntohs (mp->min_port);
  mp->max_port = ntohs (mp->max_port);
  mp->block_size = ntohl (mp->block_size);

  if (mp->nwi_len > 64 || mp->name_len > 64)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }

  nwi_vec = vec_new (u8, mp->nwi_len);
  memcpy (nwi_vec, mp->nwi, mp->nwi_len);

  name_vec = vec_new (u8, mp->name_len);
  memcpy (name_vec, mp->name, mp->name_len);

  ip4_address_decode (mp->start, &start);
  ip4_address_decode (mp->end, &end);

  upf_interface_type_t intf =
    UPF_INTERFACE_DEFAULT_TYPE; // TODO: pass from API

  rv =
    upf_nat_pool_add_del (nwi_vec, intf, start, end, name_vec, mp->block_size,
                          mp->min_port, mp->max_port, mp->is_add);

  vec_free (nwi_vec);
  vec_free (name_vec);

reply:
  REPLY_MACRO (VL_API_UPF_NAT_POOL_ADD_REPLY);
}

/* API message handler */
static void
vl_api_upf_ueip_export_enable_t_handler (vl_api_upf_ueip_export_enable_t *mp)
{
  int rv = 0;
  upf_main_t *um = &upf_main;
  vl_api_upf_nat_pool_add_reply_t *rmp = NULL;

  u8 *if_name_vec = 0;
  u8 *ns_path_vec = 0;

  bool is_enable = mp->is_enable;
  u32 table_id = ntohl (mp->table_id);

  if (mp->if_name_len > 64)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }

  if_name_vec = vec_new (u8, mp->if_name_len);
  memcpy (if_name_vec, mp->if_name, mp->if_name_len);

  ns_path_vec = vec_new (u8, mp->ns_path_len);
  memcpy (ns_path_vec, mp->ns_path, mp->ns_path_len);

  rv = upf_ueip_export_enable_disable (is_enable, table_id, if_name_vec,
                                       ns_path_vec);

  vec_free (if_name_vec);
  vec_free (ns_path_vec);

reply:
  REPLY_MACRO (VL_API_UPF_UEIP_EXPORT_ENABLE_REPLY);
}

/* API message handler */
static void
vl_api_upf_show_ueip_export_t_handler (vl_api_upf_show_ueip_export_t *mp)
{
  vl_api_registration_t *reg;
  vl_api_upf_show_ueip_export_reply_t *rmp = NULL;
  u8 nslen, iflen;
  upf_main_t *um = &upf_main;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nslen = vec_len (um->ueip_export.host_ns_name);
  iflen = vec_len (um->ueip_export.host_if_name);

  rmp = vl_msg_api_alloc (sizeof (*rmp) + nslen);
  clib_memset (rmp, 0, sizeof (*rmp) + nslen);

  rmp->enabled = um->ueip_export.enabled;
  rmp->table_id = htonl (um->ueip_export.host_table_id);

  rmp->if_name_len = iflen;
  memcpy (rmp->if_name, um->ueip_export.host_if_name, rmp->if_name_len);

  rmp->ns_path_len = nslen;
  memcpy (rmp->ns_path, um->ueip_export.host_ns_name, rmp->ns_path_len);

  rmp->_vl_msg_id =
    htons (VL_API_UPF_SHOW_UEIP_EXPORT_REPLY + um->msg_id_base);
  rmp->context = mp->context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* API message handler */
static void
vl_api_upf_imsi_netcap_enable_disable_t_handler (
  vl_api_upf_imsi_netcap_enable_disable_t *mp)
{
  int rv = 0;
  upf_main_t *um = &upf_main;
  vl_api_upf_imsi_netcap_enable_disable_reply_t *rmp;
  clib_error_t *err = NULL;

  u8 *target_vec = 0;
  u8 *tag_vec = 0;

  if (mp->target_len > 64)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      upf_debug ("netcap target len invalid: %d", mp->target_len);
      goto reply;
    }

  if (mp->tag_len > 64)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      upf_debug ("netcap tag len invalid: %d", mp->tag_len);
      goto reply;
    }

  u16 packet_max_bytes = ntohs (mp->packet_max_bytes);
  if (packet_max_bytes == 0)
    packet_max_bytes = 9000;
  else if (packet_max_bytes < 32 || packet_max_bytes > 16000)
    {
      upf_debug ("invalid netcap packet max bytes: %d", packet_max_bytes);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }

  target_vec = vec_new (u8, mp->target_len);
  if (mp->target_len > 0 && target_vec == NULL)
    {
      rv = VNET_API_ERROR_INVALID_MEMORY_SIZE;
      goto cleanup;
    }
  clib_memcpy (target_vec, mp->target, mp->target_len);

  if (mp->tag_len > 0)
    {
      tag_vec = vec_new (u8, mp->tag_len);
      if (tag_vec == NULL)
        {
          rv = VNET_API_ERROR_INVALID_MEMORY_SIZE;
          goto cleanup;
        }
      clib_memcpy (tag_vec, mp->tag, mp->tag_len);
    }

  upf_imsi_t imsi;
  memcpy (imsi.tbcd, mp->imsi, sizeof (imsi.tbcd));
  STATIC_ASSERT (sizeof (imsi.tbcd) == sizeof (mp->imsi),
                 "imsi sizes don't match");

  err = upf_imsi_netcap_enable_disable (imsi, target_vec, tag_vec,
                                        packet_max_bytes, mp->is_enable);
  if (err != NULL)
    {
      rv = err->code;
    }

cleanup:
  vec_free (target_vec);
  vec_free (tag_vec);
  clib_error_free (err);

reply:
  REPLY_MACRO (VL_API_UPF_IMSI_NETCAP_ENABLE_DISABLE_REPLY);
}

static void
send_upf_netcap_imsi_details (vl_api_registration_t *reg, upf_imsi_t *imsi,
                              upf_imsi_capture_t *capture, u32 context)
{
  vl_api_netcap_imsi_details_t *mp = NULL;
  upf_main_t *um = &upf_main;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_NETCAP_IMSI_DETAILS + um->msg_id_base);
  mp->context = context;

  memcpy (mp->imsi, imsi->tbcd, sizeof (imsi->tbcd));
  u32 target_len = vec_len (capture->target);
  ASSERT (target_len <= 64);
  mp->target_len = (u8) target_len;
  memcpy (mp->target, capture->target, target_len);

  u32 tag_len = vec_len (capture->tag);
  ASSERT (tag_len <= 64);
  mp->tag_len = (u8) tag_len;
  memcpy (mp->tag, capture->tag, tag_len);

  mp->packet_max_bytes = htons (capture->packet_max_bytes);

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void
vl_api_netcap_imsi_dump_t_handler (vl_api_netcap_imsi_dump_t *mp)
{
  upf_main_t *um = &upf_main;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  upf_imsi_t *imsi;
  uword *v;

  mhash_foreach (
    imsi, v, &um->mhash_imsi_to_capture_list_id, ({
      upf_imsi_capture_list_id_t imsi_cap_list_id =
        *((upf_imsi_capture_list_id_t *) v);
      upf_imsi_capture_list_t *imsi_cap_list =
        pool_elt_at_index (um->netcap.capture_lists, imsi_cap_list_id);

      upf_llist_foreach (capture, um->netcap.captures, imsi_list_anchor,
                         imsi_cap_list)
        send_upf_netcap_imsi_details (reg, imsi, capture, mp->context);
    }));
}

#include <upf/upf.api.c>
static clib_error_t *
upf_api_hookup (vlib_main_t *vm)
{
  upf_main_t *um = &upf_main;

  um->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (upf_api_hookup);
