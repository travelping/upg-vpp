/*
 * upf.c - 3GPP TS 29.244 GTP-U UP plug-in for vpp
 *
 * Copyright (c) 2017 Travelping GmbH
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

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>

#include <upf/upf.h>
#include <upf/upf_app_db.h>
#include <upf/upf_pfcp_server.h>
#include <upf/upf_pfcp.h>

#include <vnet/format_fns.h>
#include <upf/upf.api_enum.h>
#include <upf/upf.api_types.h>
#include <vnet/fib/fib_api.h>
#include <vnet/fib/fib_path.h>
#include <vnet/ip/ip6_hop_by_hop.h>

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* API message handler */
static void
vl_api_upf_app_add_del_t_handler (vl_api_upf_app_add_del_t * mp)
{
  vl_api_upf_app_add_del_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;
  int rv = 0;
  u8 *name = format (0, "%s", mp->name);

  rv = upf_app_add_del (sm, name, (u32) (mp->flags), (int) (mp->is_add));

  vec_free (name);
  REPLY_MACRO (VL_API_UPF_APP_ADD_DEL_REPLY);
}

/* API message handler */
static void vl_api_upf_app_ip_rule_add_del_t_handler
  (vl_api_upf_app_ip_rule_add_del_t * mp)
{
  vl_api_upf_app_ip_rule_add_del_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;
  int rv = 0;
  u8 *app = format (0, "%s", mp->app);

  // TODO: parse & pass the ACL rule
  rv =
    upf_rule_add_del (sm, app, clib_net_to_host_u32 (mp->id),
		      (int) (mp->is_add), NULL, NULL);

  vec_free (app);
  REPLY_MACRO (VL_API_UPF_APP_IP_RULE_ADD_DEL_REPLY);
}

/* API message handler */
static void vl_api_upf_app_l7_rule_add_del_t_handler
  (vl_api_upf_app_l7_rule_add_del_t * mp)
{
  vl_api_upf_app_l7_rule_add_del_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;
  int rv = 0;
  u8 *app = format (0, "%s", mp->app), *regex = format (0, "%s", mp->regex);

  rv =
    upf_rule_add_del (sm, app, clib_net_to_host_u32 (mp->id),
		      (int) (mp->is_add), regex, NULL);

  vec_free (app);
  vec_free (regex);
  REPLY_MACRO (VL_API_UPF_APP_L7_RULE_ADD_DEL_REPLY);
}

/* API message handler */
static void vl_api_upf_app_flow_timeout_set_t_handler
  (vl_api_upf_app_flow_timeout_set_t * mp)
{
  int rv = 0;
  vl_api_upf_app_flow_timeout_set_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;

  //rv = upf_flow_timeout_update(mp->type, ntohs(mp->default_value));

  REPLY_MACRO (VL_API_UPF_APP_FLOW_TIMEOUT_SET_REPLY);
}

static void
send_upf_applications_details (vl_api_registration_t * reg,
			       u8 * app_name, u32 flags, u32 context)
{
  vl_api_upf_applications_details_t *mp;
  upf_main_t *sm = &upf_main;
  u32 name_len;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_UPF_APPLICATIONS_DETAILS + sm->msg_id_base);
  mp->context = context;

  name_len = clib_min (vec_len (app_name) + 1, ARRAY_LEN (mp->name));
  memcpy (mp->name, app_name, name_len - 1);
  ASSERT (0 == mp->name[name_len - 1]);
  mp->flags = htonl (flags);

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void vl_api_upf_applications_dump_t_handler
  (vl_api_upf_applications_dump_t * mp)
{
  upf_main_t *sm = &upf_main;
  vl_api_registration_t *reg;
  upf_adf_app_t *app = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  pool_foreach (app, sm->upf_apps)
  {
    send_upf_applications_details (reg, app->name, app->flags, mp->context);
  }
}

static void
send_upf_application_l7_rule_details (vl_api_registration_t * reg,
				      u32 id, u8 * regex, u32 context)
{
  vl_api_upf_application_l7_rule_details_t *mp;
  upf_main_t *sm = &upf_main;
  u32 regex_len;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_UPF_APPLICATION_L7_RULE_DETAILS
			  + sm->msg_id_base);
  mp->context = context;

  mp->id = htonl (id);
  regex_len = clib_min (vec_len (regex) + 1, ARRAY_LEN (mp->regex));
  memcpy (mp->regex, regex, regex_len - 1);
  ASSERT (0 == mp->regex[regex_len - 1]);

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void vl_api_upf_application_l7_rule_dump_t_handler
  (vl_api_upf_application_l7_rule_dump_t * mp)
{
  upf_main_t *sm = &upf_main;
  vl_api_registration_t *reg;
  upf_adf_app_t *app = NULL;
  upf_adr_t *rule = NULL;
  u8 *app_name = format (0, "%s", mp->app);
  uword *p = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  p = hash_get_mem (sm->upf_app_by_name, app_name);
  if (!p)
    return;

  app = pool_elt_at_index (sm->upf_apps, p[0]);

  pool_foreach (rule, app->rules)
  {
    send_upf_application_l7_rule_details (reg, rule->id, rule->regex,
					  mp->context);
  }

  vec_free (app_name);
}

/* API message handler */
static void
vl_api_upf_update_app_t_handler (vl_api_upf_update_app_t * mp)
{
  vl_api_upf_update_app_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;
  int rv = 0;
  u8 *app_name = format (0, "%s", mp->app);
  u32 rule_count = clib_net_to_host_u32 (mp->l7_rule_count);
  u8 *rule_ptr = (u8 *) & mp->l7_rules[0];
  u32 *ids = vec_new (u32, rule_count);
  u32 *regex_lengths = vec_new (u32, rule_count);
  u8 **regexes = vec_new (u8 *, rule_count);

  for (u32 n = 0; n < rule_count; n++)
    {
      vl_api_upf_l7_rule_t *rule = (vl_api_upf_l7_rule_t *) rule_ptr;
      u32 regex_length = clib_net_to_host_u32 (rule->regex_length);
      ids[n] = clib_net_to_host_u32 (rule->id);
      regex_lengths[n] = regex_length;
      regexes[n] = rule->regex;
      // the regex field in vl_api_upf_l7_rule_t is defined as 'u8 regex[0]'
      rule_ptr += sizeof (vl_api_upf_l7_rule_t) + regex_length;
    }

  rv = upf_update_app (sm, app_name, rule_count, ids, regex_lengths, regexes);

  vec_free (ids);
  vec_free (regex_lengths);
  vec_free (regexes);

  REPLY_MACRO (VL_API_UPF_UPDATE_APP_REPLY);
}

static void
vl_api_upf_pfcp_reencode_t_handler (vl_api_upf_pfcp_reencode_t * mp)
{
  upf_main_t *sm = &upf_main;
  vl_api_upf_pfcp_reencode_reply_t *rmp;
  pfcp_decoded_msg_t dmsg;
  pfcp_offending_ie_t *err = 0;
  u8 *reply_data = 0;
  int rv = 0;
  int data_len = 0, packet_len = clib_net_to_host_u32 (mp->packet_len);

  if ((rv = pfcp_decode_msg (mp->packet, packet_len, &dmsg, &err)) != 0)
    {
      pfcp_offending_ie_t *cur_err;
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
  /* *INDENT-OFF* */
  REPLY_MACRO3_ZERO (VL_API_UPF_PFCP_REENCODE_REPLY, data_len,
  {
    rmp->packet_len = clib_host_to_net_u32 (data_len);
    if (data_len)
      clib_memcpy (rmp->packet, reply_data, data_len);
  });
  /* *INDENT-ON* */

  pfcp_free_dmsg_contents (&dmsg);
  vec_free (reply_data);
}

static void
vl_api_upf_pfcp_format_t_handler (vl_api_upf_pfcp_reencode_t * mp)
{
  upf_main_t *sm = &upf_main;
  vl_api_upf_pfcp_format_reply_t *rmp;
  pfcp_decoded_msg_t dmsg;
  pfcp_offending_ie_t *err = 0;
  u8 *s;
  /* pfcp_offending_ie_t *err = NULL; */
  int rv = 0;
  int text_len = 0, packet_len = clib_net_to_host_u32 (mp->packet_len);

  if ((rv = pfcp_decode_msg (mp->packet, packet_len, &dmsg, &err)) != 0)
    {
      pfcp_offending_ie_t *cur_err;
      vec_foreach (cur_err, err)
      {
	clib_warning ("offending IE: %d", *cur_err);
      }
      clib_warning ("pfcp_decode_msg failed, rv=%d", rv);
      vec_free (err);
      goto reply;
    }

  s = format (0, "%U\n", format_dmsg, &dmsg);

  text_len = vec_len (s);

reply:
  /* *INDENT-OFF* */
  REPLY_MACRO3_ZERO (VL_API_UPF_PFCP_FORMAT_REPLY, text_len,
  {
    rmp->text_len = clib_host_to_net_u32 (text_len);
    if (text_len)
      clib_memcpy (rmp->text, s, text_len);
  });
  /* *INDENT-ON* */

  if (s != 0)
    vec_free (s);
}

static void
send_upf_nat_pool_details (vl_api_registration_t * reg,
			   upf_nat_pool_t * np, u32 context)
{
  vl_api_upf_nat_pool_details_t *mp;
  upf_main_t *sm = &upf_main;
  upf_nat_addr_t *ap;
  u8 *nwi_name = 0;
  u32 len;
  u32 max_users = 0;
  u32 current_users = 0;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_UPF_NAT_POOL_DETAILS + sm->msg_id_base);
  mp->context = context;

  len = clib_min (sizeof (mp->name) - 1, vec_len (np->name));
  memcpy (mp->name, np->name, len);
  mp->name[len] = 0;

  nwi_name = format (nwi_name, "%U", format_dns_labels, np->network_instance);
  len = clib_min (sizeof (mp->nwi) - 1, vec_len (nwi_name));
  memcpy (mp->nwi, nwi_name, len);
  mp->nwi[len] = 0;
  vec_free (nwi_name);

  max_users = vec_len (np->addresses) * np->max_blocks_per_addr;
  mp->max_users = htonl (max_users);

  vec_foreach (ap, np->addresses) current_users += ap->used_blocks;

  mp->current_users = htonl (current_users);

  mp->block_size = htons (np->port_block_size);

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void vl_api_upf_nat_pool_dump_t_handler
  (vl_api_upf_nat_pool_dump_t * mp)
{
  upf_main_t *sm = &upf_main;
  vl_api_registration_t *reg;
  upf_nat_pool_t *np = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  pool_foreach (np, sm->nat_pools)
  {
    send_upf_nat_pool_details (reg, np, mp->context);
  }
}

/* API message handler */
static void
vl_api_upf_policy_add_del_t_handler (vl_api_upf_policy_add_del_t * mp)
{
  vl_api_upf_policy_add_del_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;
  fib_route_path_t *rpaths = NULL, *rpath;
  vl_api_fib_path_t *apath;
  u8 *policy_id = 0;
  u8 action = mp->action;
  int ii = 0;
  int rv = 0;

  /* Make sure ID is null terminated */
  mp->identifier[sizeof (mp->identifier) - 1] = 0;

  policy_id = format (0, "%s", mp->identifier);

  if (0 != mp->n_paths)
    vec_validate (rpaths, mp->n_paths - 1);

  for (ii = 0; ii < mp->n_paths; ii++)
    {
      apath = &mp->paths[ii];
      rpath = &rpaths[ii];

      rv = fib_api_path_decode (apath, rpath);

      if (0 != rv)
	goto out;
    }

  rv = vnet_upf_policy_fn (rpaths, policy_id, action);

out:

  vec_free (rpaths);
  vec_free (policy_id);

  REPLY_MACRO (VL_API_UPF_POLICY_ADD_DEL_REPLY);
}

static void
send_upf_policy_details (vl_api_registration_t * reg,
			 upf_forwarding_policy_t * fp, u32 context)
{
  vl_api_upf_policy_details_t *mp;
  upf_main_t *sm = &upf_main;
  fib_route_path_t *rpath;
  vl_api_fib_path_t *ap;
  u32 path_count;
  u32 len;

  path_count = vec_len (fp->rpaths);
  mp = vl_msg_api_alloc (sizeof (*mp) + path_count * sizeof (*ap));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_UPF_POLICY_DETAILS + sm->msg_id_base);
  mp->context = context;

  len = clib_min (sizeof (mp->identifier) - 1, vec_len (fp->policy_id));
  memcpy (mp->identifier, fp->policy_id, len);
  mp->identifier[len] = 0;

  mp->n_paths = path_count;

  ap = mp->paths;
  vec_foreach (rpath, fp->rpaths)
  {
    fib_api_path_encode (rpath, ap);
    ap++;
  }

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void
vl_api_upf_policy_dump_t_handler (vl_api_upf_policy_dump_t * mp)
{
  upf_main_t *sm = &upf_main;
  vl_api_registration_t *reg;
  upf_forwarding_policy_t *fp = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  pool_foreach (fp, sm->upf_forwarding_policies)
  {
    send_upf_policy_details (reg, fp, mp->context);
  }
}

/* API message handler */
static void
vl_api_upf_nwi_add_del_t_handler (vl_api_upf_nwi_add_del_t * mp)
{
  vl_api_upf_nwi_add_del_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;
  u8 *name = 0;
  u8 *nwi_name = 0;
  u32 ip4_table_id = 0;
  u32 ip6_table_id = 0;
  int rv = 0;

  /* Make sure name is null terminated */
  mp->name[sizeof (mp->name) - 1] = 0;
  name = format (0, "%s", mp->name);
  nwi_name = upf_name_to_labels (name);
  vec_free (name);
  ip4_table_id = clib_net_to_host_u32 (mp->ip4_table_id);
  ip6_table_id = clib_net_to_host_u32 (mp->ip6_table_id);
  if (!ip4_table_id && !ip6_table_id)
    {
      clib_warning ("At least one of ip[46]_table_id should be defined");
      rv = 1;
      goto out;
    }

  /* if only one of table IDs given in a request, assign both IDs to it */
  if ((ip4_table_id == 0) || (ip6_table_id == 0))
    ip4_table_id = ip6_table_id = clib_max (ip4_table_id, ip6_table_id);

  rv = vnet_upf_nwi_add_del (nwi_name, ip4_table_id, ip6_table_id, mp->add);

out:
  vec_free (nwi_name);
  REPLY_MACRO (VL_API_UPF_NWI_ADD_DEL_REPLY);
}

static void
send_upf_nwi_details (vl_api_registration_t * reg,
		      upf_nwi_t * nwi, u32 context)
{
  vl_api_upf_nwi_details_t *mp;
  upf_main_t *sm = &upf_main;
  u8 *nwi_name = 0;
  u8 len;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_UPF_NWI_DETAILS + sm->msg_id_base);
  mp->context = context;

  nwi_name = format (nwi_name, "%U", format_dns_labels, nwi->name);
  len = clib_min (sizeof (mp->name) - 1, vec_len (nwi_name));
  memcpy (mp->name, nwi_name, len);
  mp->name[len] = 0;
  vec_free (nwi_name);

  mp->ip4_fib_table = htonl (nwi->fib_index[FIB_PROTOCOL_IP4]);
  mp->ip6_fib_table = htonl (nwi->fib_index[FIB_PROTOCOL_IP6]);

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void
vl_api_upf_nwi_dump_t_handler (vl_api_upf_nwi_dump_t * mp)
{
  upf_main_t *sm = &upf_main;
  vl_api_registration_t *reg;
  upf_nwi_t *nwi = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  pool_foreach (nwi, sm->nwis)
  {
    send_upf_nwi_details (reg, nwi, mp->context);
  }
}

/* API message handler */
static void
vl_api_upf_pfcp_endpoint_add_del_t_handler (vl_api_upf_pfcp_endpoint_add_del_t
					    * mp)
{
  vl_api_upf_pfcp_endpoint_add_del_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;
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
      rv = 1;
      clib_warning ("IP should be provided");
      goto out;
    }

  if (vrf != ~0)
    {
      fib_index =
	fib_table_find (fib_ip_proto (!ip46_address_is_ip4 (&ip_addr)), vrf);
      if (fib_index == ~0)
	{
	  rv = 1;
	  clib_warning ("nonexistent vrf %d", vrf);
	  goto out;
	}
    }

  rv = vnet_upf_pfcp_endpoint_add_del (&ip_addr, fib_index, is_add);

out:

  REPLY_MACRO (VL_API_UPF_PFCP_ENDPOINT_ADD_DEL_REPLY);
}

static void
send_upf_pfcp_endpoint_details (vl_api_registration_t * reg,
				ip46_address_fib_t * key, u32 context)
{
  vl_api_upf_pfcp_endpoint_details_t *mp;
  upf_main_t *sm = &upf_main;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_UPF_PFCP_ENDPOINT_DETAILS + sm->msg_id_base);
  mp->context = context;

  mp->fib_table = htonl (key->fib_index);
  ip_address_encode (&key->addr, IP46_TYPE_ANY, &mp->ip);

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void
vl_api_upf_pfcp_endpoint_dump_t_handler (vl_api_upf_pfcp_endpoint_dump_t * mp)
{
  upf_main_t *sm = &upf_main;
  vl_api_registration_t *reg;
  ip46_address_fib_t *key;
  uword *v;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }
  /* *INDENT-OFF* */
  mhash_foreach(key, v, &sm->pfcp_endpoint_index,
  ({
    send_upf_pfcp_endpoint_details (reg, key, mp->context);
  }));
  /* *INDENT-ON* */
}

#include <upf/upf.api.c>

static clib_error_t *
upf_api_hookup (vlib_main_t * vm)
{
  upf_main_t *gtm = &upf_main;

  gtm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (upf_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
