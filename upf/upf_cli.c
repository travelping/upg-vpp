/*
 * upf_cli.c - 3GPP TS 29.244 GTP-U UP plug-in for vpp
 *
 * Copyright (c) 2017-2019 Travelping GmbH
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

#include <math.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_hop_by_hop.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/pfcp.h>
#include <upf/upf_pfcp_server.h>
#include <upf/upf_proxy.h>
#include <upf/upf_ipfix.h>

/* Action function shared between message handler and debug CLI */
#include <upf/flowtable.h>
#include <upf/upf_app_db.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_walk.h>

#define DEFAULT_MAX_SHOW_UPF_SESSIONS 100
#define HARD_MAX_SHOW_UPF_SESSIONS    10000

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)                          \
  do { } while (0)
#endif

static clib_error_t *
upf_pfcp_endpoint_ip_add_del_command_fn (vlib_main_t * vm,
					 unformat_input_t * main_input,
					 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u32 fib_index = 0;
  ip46_address_t ip;
  u8 addr_set = 0;
  u32 vrf = ~0;
  u8 add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else
	if (unformat
	    (line_input, "%U", unformat_ip46_address, &ip, IP46_TYPE_ANY))
	addr_set = 1;
      else if (unformat (line_input, "vrf %u", &vrf))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (!addr_set)
    {
      error = clib_error_return (0, "endpoint IP be specified");
      goto done;
    }

  if (vrf != ~0)
    {
      fib_index =
	fib_table_find (fib_ip_proto (!ip46_address_is_ip4 (&ip)), vrf);
      if (fib_index == ~0)
	{
	  error = clib_error_return (0, "nonexistent vrf %d", vrf);
	  goto done;
	}
    }

  rv = vnet_upf_pfcp_endpoint_add_del (&ip, fib_index, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance does not exist...");
      break;

    default:
      error = clib_error_return (0, "vnet_upf_pfcp_endpoint_add_del %d", rv);
      break;
    }

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_pfcp_endpoint_ip_add_del_command, static) =
{
  .path = "upf pfcp endpoint ip",
  .short_help =
  "upf pfcp endpoint ip <address> [vrf <table-id>] [del]",
  .function = upf_pfcp_endpoint_ip_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_pfcp_show_endpoint_command_fn (vlib_main_t * vm,
				   unformat_input_t * main_input,
				   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *gtm = &upf_main;
  clib_error_t *error = NULL;
  ip46_address_fib_t *key;
  uword *v;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  error = unformat_parse_error (line_input);
	  unformat_free (line_input);
	  goto done;
	}

      unformat_free (line_input);
    }

  vlib_cli_output (vm, "Endpoints: %d\n",
		   mhash_elts (&gtm->pfcp_endpoint_index));

  /* *INDENT-OFF* */
  mhash_foreach(key, v, &gtm->pfcp_endpoint_index,
  ({
    vlib_cli_output (vm, "  %U: %u\n", format_pfcp_endpoint_key, key, *v);
  }));
  /* *INDENT-ON* */

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_pfcp_show_endpoint_command, static) =
{
  .path = "show upf pfcp endpoint",
  .short_help =
  "show upf pfcp endpoint",
  .function = upf_pfcp_show_endpoint_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_pfcp_policer_set_fn (vlib_main_t * vm,
			 unformat_input_t * main_input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  qos_pol_cfg_params_st *cfg = &pfcp_rate_cfg_main;
  u32 cir_pps;
  u32 cb_ms;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "cir-pps %u", &cir_pps))
	cfg->rb.pps.cir_pps = cir_pps;
      else if (unformat (line_input, "cb-ms %u", &cb_ms))
	cfg->rb.pps.cb_ms = cb_ms;
      else
	{
	  error = unformat_parse_error (line_input);
	  return error;
	}
    }

  upf_pfcp_policers_recalculate (cfg);

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_pfcp_policer_set, static) =
{
  .path = "upf pfcp policer set",
  .short_help =
  "upf pfcp policer set cir-pps <packet-per-second> cb-ms <burst-ms>",
  .function = upf_pfcp_policer_set_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_ueip_pool_add_del_command_fn (vlib_main_t * vm,
				  unformat_input_t * main_input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = 0;
  u8 *nwi_s = 0;
  u8 *nwi_name;
  int rv = 0;
  int is_add = 1;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "id %_%v%_", &name))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "nwi %_%v%_", &nwi_s))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  nwi_name = upf_name_to_labels (nwi_s);
  vec_free (nwi_s);

  rv = vnet_upf_ue_ip_pool_add_del (name, nwi_name, is_add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "UE IP pool already exists");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "UE IP pool does not exist...");
      break;

    default:
      error = clib_error_return (0, "vnet_upf_ue_ip_pool_add_del %d", rv);
      break;
    }

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_ueip_pool_add_del_command, static) =
{
  .path = "upf ueip pool",
  .short_help =
  "upf ueip pool nwi <nwi-name> id <identity> [del]",
  .function = upf_ueip_pool_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_nat_pool_add_del_command_fn (vlib_main_t * vm,
				 unformat_input_t * main_input,
				 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = 0;
  u8 *nwi_name;
  u8 *nwi_s = 0;
  ip4_address_t start, end;
  u32 min_port = UPF_NAT_MIN_PORT;
  u32 max_port = UPF_NAT_MAX_PORT;
  u32 port_block_size;
  u8 is_add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U - %U",
		    unformat_ip4_address, &start, unformat_ip4_address, &end))
	;
      else if (unformat (line_input, "block_size %u", &port_block_size))
	;
      else if (unformat (line_input, "min_port %u", &min_port))
	;
      else if (unformat (line_input, "max_port %u", &max_port))
	;
      else if (unformat (line_input, "nwi %_%v%_", &nwi_s))
	;
      else if (unformat (line_input, "name %_%v%_", &name))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  /*
   * Extra port range check here because port values are parsed into
   * u32 instead of u16
   */
  if (min_port < UPF_NAT_MIN_PORT ||
      max_port > UPF_NAT_MAX_PORT || min_port > max_port)
    error = clib_error_return (0, "Invalid port range");
  else
    {
      nwi_name = upf_name_to_labels (nwi_s);

      rv =
	vnet_upf_nat_pool_add_del (nwi_name, start, end, name,
				   port_block_size, min_port, max_port,
				   is_add);

      if (rv)
	error = clib_error_return (0, "Unable to create NAT Pool");
    }

  vec_free (nwi_s);

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_nat_pool_add_del_command, static) =
{
  .path = "upf nat pool",
  .short_help =
  "upf nat pool nwi <nwi-name> start <ip4-addr> end <ip4-addr> min_port <min-port> max_port <max-port> block_size <port-block-size> name <name> [del]",
  .function = upf_nat_pool_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_nwi_add_del_command_fn (vlib_main_t * vm,
			    unformat_input_t * main_input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = NULL;
  u8 *s;
  u32 table_id = 0;
  upf_ipfix_policy_t ipfix_policy = UPF_IPFIX_POLICY_NONE;
  u8 add = 1;
  int rv;
  ip_address_t ipfix_collector_ip = ip_address_initializer;
  u32 ipfix_report_interval = 0;
  u32 observation_domain_id = 1;
  u8 *observation_domain_name = 0;
  u64 observation_point_id = 1;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "name %_%v%_", &s))
	{
	  name = upf_name_to_labels (s);
	  vec_free (s);
	}
      else if (unformat (line_input, "table %u", &table_id))
	;
      else if (unformat (line_input, "vrf %u", &table_id))
	;
      else if (unformat (line_input, "ipfix-policy %U",
			 unformat_ipfix_policy, &ipfix_policy))
	;
      else if (unformat (line_input, "ipfix-collector-ip %U",
			 unformat_ip_address, &ipfix_collector_ip))
	;
      else if (unformat (line_input, "ipfix-report-interval %u",
			 &ipfix_report_interval))
	;
      else
	if (unformat
	    (line_input, "observation-domain-id %u", &observation_domain_id))
	;
      else
	if (unformat
	    (line_input, "observation-domain-name %_%v%_",
	     &observation_domain_name))
	;
      else
	if (unformat
	    (line_input, "observation-point-id %lu", &observation_point_id))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (!name)
    {
      error = clib_error_return (0, "name or label must be specified!");
      goto done;
    }

  if (~0 == fib_table_find (FIB_PROTOCOL_IP4, table_id))
    clib_warning ("table %d not (yet) defined for IPv4", table_id);
  if (~0 == fib_table_find (FIB_PROTOCOL_IP6, table_id))
    clib_warning ("table %d not (yet) defined for IPv6", table_id);

  rv = vnet_upf_nwi_add_del (name, table_id, table_id, ipfix_policy,
			     &ipfix_collector_ip,
			     ipfix_report_interval,
			     observation_domain_id,
			     observation_domain_name,
			     observation_point_id, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "network instance already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance does not exist...");
      break;

    default:
      error = clib_error_return (0, "vnet_upf_nwi_add_del returned %d", rv);
      break;
    }

done:
  vec_free (name);
  vec_free (observation_domain_name);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_nwi_add_del_command, static) =
{
  .path = "upf nwi",
  .short_help =
  "upf nwi name <name> [table <table-id>] [vrf <vrf-id>] "
  "[ipfix-policy <name>] "
  "[ipfix-collector-ip <ip>] "
  "[ipfix-report-interval <secs>] "
  "[observation-domain-id <id>] "
  "[observation-domain-name <name>] "
  "[observation-point-id <id>] "
  "[del]",
  .function = upf_nwi_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_nwi_command_fn (vlib_main_t * vm,
			 unformat_input_t * main_input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *gtm = &upf_main;
  clib_error_t *error = NULL;
  upf_nwi_t *nwi;
  u8 *name = NULL;
  u8 *s;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "name %_%v%_", &s))
	    {
	      name = upf_name_to_labels (s);
	      vec_free (s);
	    }
	  else
	    {
	      error = unformat_parse_error (line_input);
	      unformat_free (line_input);
	      goto done;
	    }
	}

      unformat_free (line_input);
    }

  pool_foreach (nwi, gtm->nwis)
  {
    ip4_fib_t *fib4;
    ip6_fib_t *fib6;
    if (name && !vec_is_equal (name, nwi->name))
      continue;

    fib4 = ip4_fib_get (nwi->fib_index[FIB_PROTOCOL_IP4]);
    fib6 = ip6_fib_get (nwi->fib_index[FIB_PROTOCOL_IP6]);

    vlib_cli_output (vm,
		     "%U, ip4-table-id %u, ip6-table-id %u, ipfix-policy %U, ipfix-collector-ip %U\n",
		     format_dns_labels, nwi->name,
		     fib4->hash.table_id,
		     fib6->table_id,
		     format_upf_ipfix_policy, nwi->ipfix_policy,
		     format_ip_address, &nwi->ipfix_collector_ip);
  }

done:
  vec_free (name);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_nwi_command, static) =
{
  .path = "show upf nwi",
  .short_help =
  "show upf nwi",
  .function = upf_show_nwi_command_fn,
};
/* *INDENT-ON* */

#if 0
static void
vtep_ip4_ref (ip4_address_t * ip, u8 ref)
{
  uword *vtep = hash_get (upf_main.vtep4, ip->as_u32);
  if (ref)
    {
      if (vtep)
	++(*vtep);
      else
	hash_set (upf_main.vtep4, ip->as_u32, 1);
    }
  else
    {
      if (!vtep)
	return;

      if (--(*vtep) == 0)
	hash_unset (upf_main.vtep4, ip->as_u32);
    }
}

static void
vtep_ip6_ref (ip6_address_t * ip, u8 ref)
{
  uword *vtep = hash_get_mem (upf_main.vtep6, ip);
  if (ref)
    {
      if (vtep)
	++(*vtep);
      else
	hash_set_mem_alloc (&upf_main.vtep6, ip, 1);
    }
  else
    {
      if (!vtep)
	return;

      if (--(*vtep) == 0)
	hash_unset_mem_free (&upf_main.vtep6, ip);
    }
}

static void
vtep_if_address_add_del (u32 sw_if_index, u8 add)
{
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;
  ip4_address_t *ip4;
  ip6_address_t *ip6;

  /* *INDENT-OFF* */
  foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* unnumbered */ ,
  ({
    ip4 = ip_interface_address_get_address (lm4, ia);
    vtep_ip4_ref(ip4, add);
  }));
  foreach_ip_interface_address (lm6, ia, sw_if_index, 1 /* unnumbered */ ,
  ({
    ip6 = ip_interface_address_get_address (lm6, ia);
    vtep_ip6_ref(ip6, add);
  }));
  /* *INDENT-ON* */
}
#endif

static clib_error_t *
upf_tdf_ul_table_add_del_command_fn (vlib_main_t * vm,
				     unformat_input_t * main_input,
				     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  fib_protocol_t fproto = FIB_PROTOCOL_IP4;
  u32 table_id = ~0;
  u32 vrf = 0;
  u8 add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "vrf %u", &vrf))
	;
      else if (unformat (line_input, "ip4"))
	fproto = FIB_PROTOCOL_IP4;
      else if (unformat (line_input, "ip6"))
	fproto = FIB_PROTOCOL_IP6;
      else if (unformat (line_input, "table-id %u", &table_id))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (table_id == ~0)
    return clib_error_return (0, "table-id must be specified");

  rv = vnet_upf_tdf_ul_table_add_del (vrf, fproto, table_id, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_FIB:
      error = clib_error_return (0, "TDF UL lookup table already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "In VRF instance does not exist...");
      break;

    default:
      error = clib_error_return (0, "vvnet_upf_tdf_ul_table_add_del %d", rv);
      break;
    }

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_tdf_ul_table_add_del_command, static) =
{
  .path = "upf tdf ul table",
  .short_help =
  "upf tdf ul table vrf <table-id> [ip4|ip6] table-id <src-lookup-table-id> [del]",
  .function = upf_tdf_ul_table_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_tdf_ul_table_show_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  upf_main_t *gtm = &upf_main;
  fib_protocol_t fproto;
  u32 ii;

  vlib_cli_output (vm, "UPF TDF UpLink VRF to fib-index mappings:");
  FOR_EACH_FIB_IP_PROTOCOL (fproto)
  {
    vlib_cli_output (vm, " %U", format_fib_protocol, fproto);
    vec_foreach_index (ii, gtm->tdf_ul_table[fproto])
    {
      if (~0 != vec_elt (gtm->tdf_ul_table[fproto], ii))
	{
	  u32 vrf_table_id = fib_table_get_table_id (ii, fproto);
	  u32 fib_table_id =
	    fib_table_get_table_id (vec_elt (gtm->tdf_ul_table[fproto], ii),
				    fproto);

	  vlib_cli_output (vm, "  %u -> %u", vrf_table_id, fib_table_id);
	}
    }
  }
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_tdf_ul_table_show_command, static) = {
  .path = "show upf tdf ul tables",
  .short_help = "Show UPF TDF UpLink tables",
  .function = upf_tdf_ul_table_show_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_tdf_ul_enable_command_fn (vlib_main_t * vm,
			      unformat_input_t * main_input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_protocol_t fproto = FIB_PROTOCOL_IP4;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 enable = 1;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (line_input, "enable"))
	enable = 1;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else if (unformat (line_input, "ip4"))
	fproto = FIB_PROTOCOL_IP4;
      else if (unformat (line_input, "ip6"))
	fproto = FIB_PROTOCOL_IP6;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");

  vnet_upf_tdf_ul_enable_disable (fproto, sw_if_index, enable);

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_tdf_ul_enable_command, static) = {
    .path = "upf tdf ul enable",
    .short_help = "UPF TDF UpLink [enable|disable] [ip4|ip6] <interface>",
    .function = upf_tdf_ul_enable_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_spec_release_command_fn (vlib_main_t * vm,
			     unformat_input_t * main_input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *gtm = &upf_main;
  u32 spec_version = 0;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "release %u", &spec_version))
	break;
      else
	return 0;
    }

  gtm->pfcp_spec_version = spec_version;
  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_spec_release_command, static) = {
    .path = "upf specification",
    .short_help = "upf specification release [MAJOR.MINOR.PATCH]",
    .function = upf_spec_release_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_spec_release_command_fn (vlib_main_t * vm,
				  unformat_input_t * main_input,
				  vlib_cli_command_t * cmd)
{
  upf_main_t *gtm = &upf_main;
  vlib_cli_output (vm, "PFCP version: %u", gtm->pfcp_spec_version);
  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_spec_release_command, static) =
{
  .path = "show upf specification release",
  .short_help =
  "show upf specification release",
  .function = upf_show_spec_release_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_node_id_command_fn (vlib_main_t * vm,
			unformat_input_t * main_input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *fqdn = 0;
  pfcp_node_id_t node_id = {.type = (u8) ~ 0 };

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "fqdn %_%v%_", &fqdn))
	{
	  node_id.type = NID_FQDN;
	  node_id.fqdn = upf_name_to_labels (fqdn);
	  vec_free (fqdn);
	}
      else if (unformat (line_input, "ip4 %U",
			 unformat_ip46_address, &node_id.ip, IP46_TYPE_ANY))
	{
	  node_id.type = NID_IPv4;
	}
      else if (unformat (line_input, "ip6 %U",
			 unformat_ip46_address, &node_id.ip, IP46_TYPE_ANY))
	{
	  node_id.type = NID_IPv6;
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  return error;
	}
    }

  if ((u8) ~ 0 == node_id.type)
    return clib_error_return (0, "A valid node id must be specified");

  vnet_upf_node_id_set (&node_id);

  return NULL;

}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_node_id_command, static) = {
    .path = "upf node-id",
    .short_help = "upf node-id ( fqdn <fqdn> | ip4 <ip4-addr> | ip6 <ip6-addr> )",
    .function = upf_node_id_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_node_id_command_fn (vlib_main_t * vm,
			     unformat_input_t * main_input,
			     vlib_cli_command_t * cmd)
{
  upf_main_t *gtm = &upf_main;
  u8 *type = 0;
  vec_reset_length (type);
  vlib_cli_output (vm, "Node ID: %U", format_node_id, &gtm->node_id);
  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_node_id_command, static) =
{
  .path = "show upf node-id",
  .short_help =
  "show upf node-id",
  .function = upf_show_node_id_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_gtpu_endpoint_add_del_command_fn (vlib_main_t * vm,
				      unformat_input_t * main_input,
				      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 teid = 0, mask = 0, teidri = 0;
  clib_error_t *error = NULL;
  ip6_address_t ip6 = ip6_address_initializer;
  ip4_address_t ip4 = ip4_address_initializer;
  u8 ip_set = 0;
  u8 *name = NULL;
  u8 intf = INTF_INVALID;
  u8 add = 1;
  int rv;
  u8 *s;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "ip %U", unformat_ip4_address, &ip4))
	ip_set |= 1;
      else if (unformat (line_input, "ip6 %U", unformat_ip6_address, &ip6))
	ip_set |= 2;
      else if (unformat (line_input, "nwi %_%v%_", &s))
	{
	  name = upf_name_to_labels (s);
	  vec_free (s);
	}
      else if (unformat (line_input, "intf access"))
	intf = SRC_INTF_ACCESS;
      else if (unformat (line_input, "intf core"))
	intf = SRC_INTF_CORE;
      else if (unformat (line_input, "intf sgi"))
	/*
	 * WTF: the specification does permit that,
	 *      but what does that mean in terms
	 *      of the UPIP IE?
	 */
	intf = SRC_INTF_SGI_LAN;
      else if (unformat (line_input, "intf cp"))
	intf = SRC_INTF_CP;
      else if (unformat (line_input, "teid %u/%u", &teid, &teidri))
	{
	  if (teidri > 7)
	    {
	      error =
		clib_error_return (0,
				   "TEID Range Indication to large (%d > 7)",
				   teidri);
	      goto done;
	    }
	  mask = 0xfe000000 << (7 - teidri);
	}
      else if (unformat (line_input, "teid 0x%x/%u", &teid, &teidri))
	{
	  if (teidri > 7)
	    {
	      error =
		clib_error_return (0,
				   "TEID Range Indication to large (%d > 7)",
				   teidri);
	      goto done;
	    }
	  mask = 0xfe000000 << (7 - teidri);
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (!ip_set)
    {
      error = clib_error_return (0, "ip or ip6 need to be set");
      goto done;
    }

  rv = vnet_upf_upip_add_del (&ip4, &ip6, name, intf, teid, mask, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error =
	clib_error_return (0, "network instance or entry does not exist...");
      break;

    default:
      error = clib_error_return
	(0, "vnet_upf_nwi_set_intf_role returned %d", rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_gtpu_endpoint_command, static) =
{
  .path = "upf gtpu endpoint",
  .short_help =
  "upf gtpu endpoint [ip <v4 address>] [ip6 <v6 address>] [nwi <name>]"
  " [src access | core | sgi | cp] [teid <teid>/<mask>] [del]",
  .function = upf_gtpu_endpoint_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_gtpu_endpoint_command_fn (vlib_main_t * vm,
				   unformat_input_t * main_input,
				   vlib_cli_command_t * cmd)
{
  upf_main_t *gtm = &upf_main;
  clib_error_t *error = NULL;
  upf_upip_res_t *res;

  /* TBD....
     if (unformat_user (main_input, unformat_line_input, line_input))
     {
     while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
     {
     if (unformat (line_input, "name %_%v%_", &s))
     {
     name = upf_name_to_labels (s);
     vec_free (s);
     }
     else
     {
     error = unformat_parse_error (line_input);
     unformat_free (line_input);
     goto done;
     }
     }

     unformat_free (line_input);
     }
   */

  pool_foreach (res, gtm->upip_res)
  {
    vlib_cli_output (vm, "[%d]: %U", res - gtm->upip_res,
		     format_gtpu_endpoint, res);
  }

  //done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_gtpu_endpoint_command, static) =
{
  .path = "show upf gtpu endpoint",
  .short_help =
  "show upf gtpu endpoint",
  .function = upf_show_gtpu_endpoint_command_fn,
};
/* *INDENT-ON* */

typedef struct
{
  vlib_main_t *vm;
  u64 seid;
  bool filtered;
  u32 limit;
} flows_out_arg_t;

static int
upf_flows_out_cb (clib_bihash_kv_48_8_t * kvp, void *arg)
{
  flowtable_main_t *fm = &flowtable_main;
  flows_out_arg_t *arg_value = (flows_out_arg_t *) arg;
  flow_key_t *key = (flow_key_t *) & kvp->key;
  flow_entry_t *flow;

  flow = pool_elt_at_index (fm->flows, kvp->value);
  if (!arg_value->filtered || arg_value->seid == key->seid)
    vlib_cli_output (arg_value->vm, "%U", format_flow, flow);

  return arg_value->limit != ~0 && !--arg_value->limit ?
    BIHASH_WALK_STOP : BIHASH_WALK_CONTINUE;
}

static clib_error_t *
upf_show_session_command_fn (vlib_main_t * vm,
			     unformat_input_t * main_input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *gtm = &upf_main;
  clib_error_t *error = NULL;
  u64 cp_seid, up_seid;
  ip46_address_t cp_ip;
  u8 has_cp_f_seid = 0, has_up_seid = 0;
  upf_session_t *sess = NULL;
  int debug = 0;
  u32 limit = DEFAULT_MAX_SHOW_UPF_SESSIONS;
  u8 has_flows = 0;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "cp %U seid 0x%llx",
			unformat_ip46_address, &cp_ip, IP46_TYPE_ANY,
			&cp_seid))
	    has_cp_f_seid = 1;
	  else if (unformat (line_input, "cp %U seid %llu",
			     unformat_ip46_address, &cp_ip, IP46_TYPE_ANY,
			     &cp_seid))
	    has_cp_f_seid = 1;
	  else if (unformat (line_input, "up seid 0x%llx", &up_seid))
	    has_up_seid = 1;
	  else if (unformat (line_input, "up seid %lu", &up_seid))
	    has_up_seid = 1;
	  else if (unformat (line_input, "debug"))
	    debug = 1;
	  else if (unformat (line_input, "flows"))
	    has_flows = 1;
	  else if (unformat (line_input, "limit %u", &limit))
	    ;
	  else
	    {
	      error = unformat_parse_error (line_input);
	      unformat_free (line_input);
	      goto done;
	    }
	}

      unformat_free (line_input);
    }

  if (limit > HARD_MAX_SHOW_UPF_SESSIONS)
    limit = HARD_MAX_SHOW_UPF_SESSIONS;

  if (has_flows && !has_up_seid)
    {
      error =
	clib_error_return (0, "must specify UP F-SEID to show session flows");
      goto done;
    }

  if (has_flows)
    {
      u32 cpu_index;
      flowtable_main_t *fm = &flowtable_main;
      vlib_thread_main_t *tm = vlib_get_thread_main ();
      flows_out_arg_t arg = {
	.vm = vm,
	.seid = up_seid,
	.filtered = true,
	.limit = limit
      };

      if (!(sess = pfcp_lookup (up_seid)))
	{
	  error = clib_error_return (0, "Sessions 0x%lx not found", up_seid);
	  goto done;
	}

      for (cpu_index = 0; cpu_index < tm->n_vlib_mains; cpu_index++)
	{
	  flowtable_main_per_cpu_t *fmt = &fm->per_cpu[cpu_index];
	  clib_bihash_foreach_key_value_pair_48_8
	    (&fmt->flows_ht, upf_flows_out_cb, &arg);
	}

      goto done;
    }

  if (has_cp_f_seid)
    {
      error = clib_error_return (0, "CP F-SEID is not supported, yet");
      goto done;
    }

  if (has_up_seid && !has_flows)
    {
      if (!(sess = pfcp_lookup (up_seid)))
	{
	  error = clib_error_return (0, "Sessions %d not found", up_seid);
	  goto done;
	}

      vlib_cli_output (vm, "%U", format_pfcp_session, sess, PFCP_ACTIVE,
		       debug);
    }
  else
    {
      pool_foreach (sess, gtm->sessions)
      {
	if (limit != 0 && sess - gtm->sessions >= limit)
	  {
	    vlib_cli_output (vm, "Max number of sessions displayed: %u",
			     limit);
	    break;
	  }
	vlib_cli_output (vm, "%U", format_pfcp_session, sess, PFCP_ACTIVE,
			 debug);
      }
    }

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_session_command, static) =
{
  .path = "show upf session",
  .short_help =
  "show upf session [up seid 0x... [flows]] [limit N]",
  .function = upf_show_session_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_assoc_command_fn (vlib_main_t * vm,
			   unformat_input_t * main_input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *gtm = &upf_main;
  clib_error_t *error = NULL;
  u8 has_ip = 0, has_fqdn = 0;
  ip46_address_t node_ip;
  upf_node_assoc_t *node;
  u8 verbose = 0;
  u8 *fqdn = 0;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "ip %U",
			unformat_ip46_address, &node_ip, IP46_TYPE_ANY))
	    has_ip = 1;
	  else if (unformat (line_input, "fqdn %_%v%_", &fqdn))
	    has_fqdn = 1;
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else
	    {
	      error = unformat_parse_error (line_input);
	      unformat_free (line_input);
	      goto done;
	    }
	}

      unformat_free (line_input);
    }

  if (has_ip && has_fqdn)
    {
      error =
	clib_error_return (0,
			   "Only one selector is allowed, eith ip or fqdn");
      goto done;
    }

  if (has_ip && has_fqdn)
    {
      pfcp_node_id_t node_id;

      if (has_ip)
	{
	  node_id.type = ip46_address_is_ip4 (&node_ip) ? NID_IPv4 : NID_IPv6;
	  node_id.ip = node_ip;
	}
      if (has_fqdn)
	{
	  node_id.type = NID_FQDN;
	  node_id.fqdn = upf_name_to_labels (fqdn);
	}

      node = pfcp_get_association (&node_id);

      if (node_id.type == NID_FQDN)
	vec_free (node_id.fqdn);

      if (!node)
	{
	  error = clib_error_return (0, "Association not found");
	  goto done;
	}

      vlib_cli_output (vm, "%U", format_pfcp_node_association, node, verbose);
    }
  else
    {
      pool_foreach (node, gtm->nodes)
      {
	vlib_cli_output (vm, "%U", format_pfcp_node_association, node,
			 verbose);
      }
    }

done:
  if (fqdn)
    vec_free (fqdn);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_assoc_command, static) =
{
  .path = "show upf association",
  .short_help =
  "show upf association",
  .function = upf_show_assoc_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_flows_command_fn (vlib_main_t * vm,
			   unformat_input_t * main_input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u32 cpu_index;
  flowtable_main_t *fm = &flowtable_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  flows_out_arg_t arg = {
    .vm = vm,
    .filtered = false,
    .limit = ~0
  };

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "limit %u", &arg.limit))
	    ;
	  else
	    {
	      error = unformat_parse_error (line_input);
	      unformat_free (line_input);
	      goto done;
	    }
	}

      unformat_free (line_input);
    }

  for (cpu_index = 0; cpu_index < tm->n_vlib_mains; cpu_index++)
    {
      flowtable_main_per_cpu_t *fmt = &fm->per_cpu[cpu_index];
      clib_bihash_foreach_key_value_pair_48_8
	(&fmt->flows_ht, upf_flows_out_cb, &arg);
    }

done:
  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_flows_command, static) =
{
  .path = "show upf flows",
  .short_help = "show upf flows [limit N]",
  .function = upf_show_flows_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_bihash_command_fn (vlib_main_t * vm,
			    unformat_input_t * main_input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  upf_main_t *sm = &upf_main;
  int verbose = 0;
  int hash = 0;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "detail"))
	verbose = 1;
      else if (unformat (line_input, "verbose"))
	verbose = 2;
      else if (unformat (line_input, "v4-tunnel-by-key"))
	hash = 1;
      else if (unformat (line_input, "v6-tunnel-by-key"))
	hash = 2;
      else if (unformat (line_input, "qer-by-id"))
	hash = 3;
      else if (unformat (line_input, "peer-index-by-ip"))
	hash = 4;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  switch (hash)
    {
    case 1:
      vlib_cli_output (vm, "%U", format_bihash_8_8, &sm->v4_tunnel_by_key,
		       verbose);
      break;
    case 2:
      vlib_cli_output (vm, "%U", format_bihash_24_8, &sm->v6_tunnel_by_key,
		       verbose);
      break;
    case 3:
      vlib_cli_output (vm, "%U", format_bihash_8_8, &sm->qer_by_id, verbose);
      break;
    case 4:
      vlib_cli_output (vm, "%U", format_bihash_24_8, &sm->peer_index_by_ip,
		       verbose);
      break;
    default:
      error = clib_error_return (0, "Please specify an hash...");
      break;
    }

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_bihash_command, static) =
{
  .path = "show upf bihash",
  .short_help =
  "show upf bihash <v4-tunnel-by-key | v6-tunnel-by-key | qer-by-id | peer-index-by-ip> [detail|verbose]",
  .function = upf_show_bihash_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_proxy_set_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  upf_proxy_main_t *pm = &upf_proxy_main;
#define _(type, name) type name;
  foreach_upf_proxy_config_fields
#undef _
    u32 tmp32;

#define _(type, name) name = pm->name;
  foreach_upf_proxy_config_fields
#undef _
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "mss %d", &tmp32))
	mss = (u16) tmp32;
      else if (unformat (input, "fifo-size %U",
			 unformat_memory_size, &fifo_size))
	;
      else if (unformat (input, "max-fifo-size %U",
			 unformat_memory_size, &max_fifo_size))
	;
      else if (unformat (input, "high-watermark %d", &tmp32))
	high_watermark = (u8) tmp32;
      else if (unformat (input, "low-watermark %d", &tmp32))
	low_watermark = (u8) tmp32;
      else if (unformat (input, "prealloc-fifos %d", &prealloc_fifos))
	;
      else if (unformat (input, "private-segment-count %d",
			 &private_segment_count))
	;
      else if (unformat (input, "private-segment-size %U",
			 unformat_memory_size, &private_segment_size))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

#define _(type, name) pm->name = name;
  foreach_upf_proxy_config_fields
#undef _
    return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_proxy_set_command, static) =
{
  .path = "set upf proxy",
  .short_help = "set upf proxy [mss <nn>] [fifo-size <nn>[k|m]]"
      "[max-fifo-size <nn>[k|m]][high-watermark <nn>]"
      "[low-watermark <nn>][prealloc-fifos <nn>]"
      "[private-segment-size <mem>][private-segment-count <nn>]",
  .function = upf_proxy_set_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_proxy_command_fn (vlib_main_t * vm,
			   unformat_input_t * main_input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_proxy_main_t *pm = &upf_proxy_main;
  clib_error_t *error = NULL;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  error = unformat_parse_error (line_input);
	  unformat_free (line_input);
	  goto done;
	}

      unformat_free (line_input);
    }

  vlib_cli_output (vm, "MSS: %u\n"
		   "FIFO Size: %U\n"
		   "Max FIFO Size: %U\n"
		   "Hi/Lo Watermark: %u %% / %u %%\n"
		   "Prealloc FIFOs: %u\n"
		   "Private Segment Count: %u\n"
		   "Private Segment Size: %U\n",
		   pm->mss,
		   format_memory_size, pm->fifo_size,
		   format_memory_size, pm->max_fifo_size,
		   pm->high_watermark, pm->low_watermark,
		   pm->prealloc_fifos,
		   pm->private_segment_count,
		   format_memory_size, pm->private_segment_size);

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_proxy_command, static) =
{
  .path = "show upf proxy",
  .short_help = "show upf proxy",
  .function = upf_show_proxy_command_fn,
};

/* *INDENT-ON* */

static clib_error_t *
upf_show_proxy_session_command_fn (vlib_main_t * vm,
				   unformat_input_t * main_input,
				   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_proxy_main_t *pm = &upf_proxy_main;
  clib_error_t *error = NULL;
  upf_proxy_session_t *ps;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  error = unformat_parse_error (line_input);
	  unformat_free (line_input);
	  goto done;
	}

      unformat_free (line_input);
    }

  pool_foreach (ps, pm->sessions)
  {
    vlib_cli_output (vm, "%U\n", format_upf_proxy_session, ps);
  }

done:
  return error;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_proxy_session_command, static) =
{
  .path = "show upf proxy sessions",
  .short_help = "show upf proxy sessions",
  .function = upf_show_proxy_session_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_policy_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  upf_main_t *gtm = &upf_main;
  upf_forwarding_policy_t *fp_entry;
  uword *hash_ptr;
  u8 *policy_id = NULL;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%_%v%_", &policy_id))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }
  if (NULL == policy_id)
    {
      pool_foreach (fp_entry, gtm->upf_forwarding_policies)
      {
	vlib_cli_output (vm, "%U", format_upf_policy, fp_entry);
      }
    }
  else
    {
      hash_ptr = hash_get_mem (gtm->forwarding_policy_by_id, policy_id);
      if (hash_ptr)
	{
	  fp_entry =
	    pool_elt_at_index (gtm->upf_forwarding_policies, hash_ptr[0]);
	  vlib_cli_output (vm, "%U", format_upf_policy, fp_entry);
	}
      else
	upf_debug ("###### Policy with id %v does not exist ######",
		   policy_id);
    }
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_policy_command, static) =
{
  .path = "show upf policy",
  .short_help = "show upf policy",
  .function = upf_show_policy_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_policy_command_fn (vlib_main_t * vm,
		       unformat_input_t * main_input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_route_path_t *rpaths = NULL, rpath;
  dpo_proto_t payload_proto;

  u8 *policy_id;
  u8 action = 0;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "id %_%v%_", &policy_id))
	;
      else if (unformat (line_input, "del"))
	action = 0;
      else if (unformat (line_input, "add"))
	action = 1;
      else if (unformat (line_input, "update"))
	action = 2;
      else if (unformat (line_input, "via %U",
			 unformat_fib_route_path, &rpath, &payload_proto))
	vec_add1 (rpaths, rpath);
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input));
    }

  vnet_upf_policy_fn (rpaths, policy_id, action);
  vec_free (policy_id);
  unformat_free (line_input);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_add_policy_command, static) =
{
  .path = "upf policy",
  .short_help = "upf policy [add|del] id <policy_id> via <next_hop> <interface>",
  .function = upf_policy_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_pfcp_heartbeat_config_command_fn (vlib_main_t * vm,
				      unformat_input_t * main_input,
				      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *gtm = &upf_main;
  clib_error_t *error = NULL;
  u32 timeout = ~0;
  u32 retries = ~0;
  int rv = 0;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "timeout %u", &timeout))
	;
      else if (unformat (line_input, "retries %u", &retries));
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input));
    }

  rv = vnet_upf_pfcp_heartbeat_config (timeout, retries);
  if (rv)
    error = clib_return_error ("Invalid parameters");
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_pfcp_heartbeat_config_command, static) = {
    .path = "upf pfcp heartbeat-config",
    .short_help = "upf pfcp heartbeat-config timeout <sec> retries <count>",
    .function = upf_pfcp_heartbeat_config_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
upf_show_pfcp_heartbeat_config_command_fn (vlib_main_t * vm,
					   unformat_input_t * main_input,
					   vlib_cli_command_t * cmd)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  vlib_cli_output (vm, "Timeout: %u Retries: %u", psm->hb_cfg.timeout,
		   psm->hb_cfg.retries);
  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_show_pfcp_heartbeat_config_command, static) =
{
  .path = "show upf heartbeat-config",
  .short_help =
  "show upf heartbeat-config",
  .function = upf_show_pfcp_heartbeat_config_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
