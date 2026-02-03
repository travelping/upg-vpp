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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_walk.h>

#include "upf/upf.h"
#include "upf/nat/nat.h"
#include "upf/pfcp/pfcp_proto.h"
#include "upf/pfcp/upf_pfcp_assoc.h"
#include "upf/pfcp/upf_pfcp_server.h"
#include "upf/proxy/upf_proxy.h"
#include "upf/integrations/upf_ipfix.h"
#include "upf/rules/upf_gtpu.h"
#include "upf/rules/upf_session_dpo.h"
#include "upf/rules/upf_forwarding_policy.h"
#include "upf/integrations/upf_ipfix.h"

#define DEFAULT_MAX_SHOW_UPF_SESSIONS 100
#define HARD_MAX_SHOW_UPF_SESSIONS    10000

#define UPF_DEBUG_ENABLE 0

static clib_error_t *
upf_pfcp_endpoint_ip_add_del_command_fn (vlib_main_t *vm,
                                         unformat_input_t *main_input,
                                         vlib_cli_command_t *cmd)
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
      else if (unformat (line_input, "%U", unformat_ip46_address, &ip,
                         IP46_TYPE_ANY))
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

  if (is_valid_id (vrf))
    {
      fib_index =
        fib_table_find (fib_ip_proto (!ip46_address_is_ip4 (&ip)), vrf);
      if (!is_valid_id (fib_index))
        {
          error = clib_error_return (0, "nonexistent vrf %d", vrf);
          goto done;
        }
    }

  rv = upf_pfcp_endpoint_add_del (&ip, fib_index, add);

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

VLIB_CLI_COMMAND (upf_pfcp_endpoint_ip_add_del_command, static) = {
  .path = "upf pfcp endpoint ip",
  .short_help = "upf pfcp endpoint ip <address> [vrf <table-id>] [del]",
  .function = upf_pfcp_endpoint_ip_add_del_command_fn,
};

static clib_error_t *
upf_pfcp_show_endpoint_command_fn (vlib_main_t *vm,
                                   unformat_input_t *main_input,
                                   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *um = &upf_main;
  clib_error_t *error = NULL;
  upf_pfcp_endpoint_key_t *key;
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
                   mhash_elts (&um->pfcp_endpoint_index));

  /* clang-format off */
  mhash_foreach(key, v, &um->pfcp_endpoint_index,
  ({
    vlib_cli_output (vm, "  %U: %u\n", format_pfcp_endpoint_key, key, *v);
  }));
  /* clang-format on */

done:
  return error;
}

VLIB_CLI_COMMAND (upf_pfcp_show_endpoint_command, static) = {
  .path = "show upf pfcp endpoint",
  .short_help = "show upf pfcp endpoint",
  .function = upf_pfcp_show_endpoint_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_ueip_pool_add_del_command_fn (vlib_main_t *vm,
                                  unformat_input_t *main_input,
                                  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *identity = 0;
  u8 *nwi_s = 0;
  u8 *nwi_name = 0;
  int rv = 0;
  int is_add = 1;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "id %_%v%_", &identity))
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

  if (vec_len (nwi_name) > 64)
    {
      error =
        clib_error_return (0, "NWI name(encoded) has to fit in 64 bytes");
      goto done;
    }
  if (vec_len (identity) > 64)
    {
      error = clib_error_return (0, "UE IP pool name has to fit in 64 bytes");
      goto done;
    }

  rv = upf_ue_ip_pool_add_del (identity, nwi_name, is_add);

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
      error = clib_error_return (0, "upf_ue_ip_pool_add_del %d", rv);
      break;
    }

done:
  vec_free (identity);
  vec_free (nwi_name);
  vec_free (nwi_s);
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (upf_ueip_pool_add_del_command, static) = {
  .path = "upf ueip pool",
  .short_help = "upf ueip pool nwi <nwi-name> id <identity> [del]",
  .function = upf_ueip_pool_add_del_command_fn,
};

static clib_error_t *
upf_show_ueip_pool_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                               vlib_cli_command_t *cmd)
{
  upf_main_t *um = &upf_main;
  upf_ue_ip_pool_info_t *pool;

  pool_foreach (pool, um->ueip_pools)
    {
      vlib_cli_output (vm, "id: %v nwi: %U", pool->identity,
                       format_upf_nwi_name, pool->nwi_name);
    }

  return NULL;
}

VLIB_CLI_COMMAND (upf_show_ueip_pool_command, static) = {
  .path = "show upf ueip pool",
  .short_help = "show upf ueip pool",
  .function = upf_show_ueip_pool_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_nwi_add_del_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                            vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = NULL;
  u8 *s;
  u32 rx_table_id = ~0;
  u32 tx_table_id = ~0;
  upf_ipfix_policy_t ipfix_policy = UPF_IPFIX_POLICY_NONE;
  u8 add = 1;
  upf_interface_type_t intf = UPF_INTERFACE_DEFAULT_TYPE;
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
      else if (unformat (line_input, "table %u", &rx_table_id))
        ;
      else if (unformat (line_input, "vrf %u", &rx_table_id))
        ;
      else if (unformat (line_input, "tx-table %u", &tx_table_id))
        ;
      else if (unformat (line_input, "tx-vrf %u", &tx_table_id))
        ;
      else if (unformat (line_input, "intf %U", unformat_upf_interface_type,
                         &intf))
        ;
      else if (unformat (line_input, "ipfix-policy %U", unformat_ipfix_policy,
                         &ipfix_policy))
        ;
      else if (unformat (line_input, "ipfix-collector-ip %U",
                         unformat_ip_address, &ipfix_collector_ip))
        ;
      else if (unformat (line_input, "ipfix-report-interval %u",
                         &ipfix_report_interval))
        ;
      else if (unformat (line_input, "observation-domain-id %u",
                         &observation_domain_id))
        ;
      else if (unformat (line_input, "observation-domain-name %_%v%_",
                         &observation_domain_name))
        ;
      else if (unformat (line_input, "observation-point-id %lu",
                         &observation_point_id))
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

  if (!is_valid_id (tx_table_id))
    tx_table_id = rx_table_id;

  if (~0 == fib_table_find (FIB_PROTOCOL_IP4, rx_table_id))
    clib_warning ("rx table %d not (yet) defined for IPv4", rx_table_id);
  if (~0 == fib_table_find (FIB_PROTOCOL_IP6, rx_table_id))
    clib_warning ("rx table %d not (yet) defined for IPv6", rx_table_id);
  if (~0 == fib_table_find (FIB_PROTOCOL_IP4, tx_table_id))
    clib_warning ("tx table %d not (yet) defined for IPv4", tx_table_id);
  if (~0 == fib_table_find (FIB_PROTOCOL_IP6, tx_table_id))
    clib_warning ("tx table %d not (yet) defined for IPv6", tx_table_id);

  rv = upf_nwi_interface_add_del (
    name, intf, rx_table_id, rx_table_id, tx_table_id, tx_table_id,
    ipfix_policy, &ipfix_collector_ip, ipfix_report_interval,
    observation_domain_id, observation_domain_name, observation_point_id, add);

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

VLIB_CLI_COMMAND (upf_nwi_add_del_command, static) = {
  .path = "upf nwi",
  .short_help = "upf nwi name <name> "
                "[intf (access|core|sgi|cp)] "
                "[table <table-id>] [tx-table <table-id>] "
                "[vrf <vrf-id>] [tx-vrf <vrf-id>] "
                "[ipfix-policy <name>] "
                "[ipfix-collector-ip <ip>] "
                "[ipfix-report-interval <secs>] "
                "[observation-domain-id <id>] "
                "[observation-domain-name <name>] "
                "[observation-point-id <id>] "
                "[del]",
  .function = upf_nwi_add_del_command_fn,
};

static clib_error_t *
upf_show_nwi_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                         vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *um = &upf_main;
  clib_error_t *error = NULL;
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

  upf_interface_t *nwif;
  pool_foreach (nwif, um->nwi_interfaces)
    {
      upf_nwi_t *nwi = pool_elt_at_index (um->nwis, nwif->nwi_id);
      if (name && !vec_is_equal (name, nwi->name))
        continue;

      i32 table_rx4 = upf_interface_get_table_id (nwif, 0, 1);
      i32 table_rx6 = upf_interface_get_table_id (nwif, 0, 0);
      i32 table_tx4 = upf_interface_get_table_id (nwif, 1, 1);
      i32 table_tx6 = upf_interface_get_table_id (nwif, 1, 0);

      vlib_cli_output (
        vm,
        "%U %U: ip4-table-id %d, ip6-table-id %d, tx-ip4-table-id %d, "
        "tx-ip6-table-id %d, ipfix-policy %U, ipfix-collector-ip %U\n",
        format_upf_nwi_name, nwi->name, format_upf_interface_type, nwif->intf,
        table_rx4, table_rx6, table_tx4, table_tx6, format_upf_ipfix_policy,
        nwif->ipfix.default_policy, format_ip_address,
        &nwif->ipfix.collector_ip);
    }

done:
  vec_free (name);
  return error;
}

VLIB_CLI_COMMAND (upf_show_nwi_command, static) = {
  .path = "show upf nwi",
  .short_help = "show upf nwi [name <name>]",
  .function = upf_show_nwi_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_tdf_ul_table_add_del_command_fn (vlib_main_t *vm,
                                     unformat_input_t *main_input,
                                     vlib_cli_command_t *cmd)
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

  if (!is_valid_id (table_id))
    {
      error = clib_error_return (0, "table-id must be specified");
      goto done;
    }

  rv = upf_tdf_ul_table_add_del (vrf, fproto, table_id, add);

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
      error = clib_error_return (0, "upf_tdf_ul_table_add_del %d", rv);
      break;
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (upf_tdf_ul_table_add_del_command, static) = {
  .path = "upf tdf ul table",
  .short_help = "upf tdf ul table "
                "vrf <table-id> [ip4|ip6] "
                "table-id <src-lookup-table-id> "
                "[del]",
  .function = upf_tdf_ul_table_add_del_command_fn,
};

static clib_error_t *
upf_tdf_ul_table_show_fn (vlib_main_t *vm, unformat_input_t *input,
                          vlib_cli_command_t *cmd)
{
  upf_main_t *um = &upf_main;
  fib_protocol_t fproto;
  u32 ii;

  vlib_cli_output (vm, "UPF TDF UpLink VRF to fib-index mappings:");
  FOR_EACH_FIB_IP_PROTOCOL (fproto)
  {
    vlib_cli_output (vm, " %U", format_fib_protocol, fproto);
    vec_foreach_index (ii, um->tdf_ul_table[fproto])
      {
        if (~0 != vec_elt (um->tdf_ul_table[fproto], ii))
          {
            u32 vrf_table_id = fib_table_get_table_id (ii, fproto);
            u32 fib_table_id = fib_table_get_table_id (
              vec_elt (um->tdf_ul_table[fproto], ii), fproto);

            vlib_cli_output (vm, "  %u -> %u", vrf_table_id, fib_table_id);
          }
      }
  }
  return (NULL);
}

VLIB_CLI_COMMAND (upf_tdf_ul_table_show_command, static) = {
  .path = "show upf tdf ul tables",
  .short_help = "show upf tdf ul tables",
  .function = upf_tdf_ul_table_show_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_tdf_ul_enable_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                              vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  fib_protocol_t fproto = FIB_PROTOCOL_IP4;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 enable = 1;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
                    &sw_if_index))
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
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  if (!enable)
    {
      error = clib_error_return (0, "not implemented");
      goto done;
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "interface must be specified");
      goto done;
    }

  upf_tdf_ul_enable_disable (fproto, sw_if_index, enable);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (upf_tdf_ul_enable_command, static) = {
  .path = "upf tdf ul enable",
  .short_help = "upf tdf ul enable [ip4|ip6] <interface>",
  .function = upf_tdf_ul_enable_command_fn,
};

static clib_error_t *
upf_spec_release_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                             vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  upf_main_t *um = &upf_main;
  u32 spec_version = 0;
  bool has_release = false;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "release %u", &spec_version))
        has_release = true;
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  if (!has_release)
    {
      error = clib_error_return (0, "release version must be specified");
      goto done;
    }

  um->pfcp_spec_version = spec_version;

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (upf_spec_release_command, static) = {
  .path = "upf specification",
  .short_help = "upf specification release <version>",
  .function = upf_spec_release_command_fn,
};

static clib_error_t *
upf_show_spec_release_command_fn (vlib_main_t *vm,
                                  unformat_input_t *main_input,
                                  vlib_cli_command_t *cmd)
{
  upf_main_t *um = &upf_main;
  vlib_cli_output (vm, "PFCP version: %u", um->pfcp_spec_version);
  return NULL;
}

VLIB_CLI_COMMAND (upf_show_spec_release_command, static) = {
  .path = "show upf specification release",
  .short_help = "show upf specification release",
  .function = upf_show_spec_release_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_node_id_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                        vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *fqdn = 0;
  pfcp_ie_node_id_t node_id = { .type = (u8) ~0 };

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "fqdn %_%v%_", &fqdn))
        {
          node_id.type = PFCP_NID_FQDN;
          node_id.fqdn = upf_name_to_labels (fqdn);
          vec_free (fqdn);
        }
      else if (unformat (line_input, "ip4 %U", unformat_ip46_address,
                         &node_id.ip, IP46_TYPE_ANY))
        {
          node_id.type = PFCP_NID_IPv4;
        }
      else if (unformat (line_input, "ip6 %U", unformat_ip46_address,
                         &node_id.ip, IP46_TYPE_ANY))
        {
          node_id.type = PFCP_NID_IPv6;
        }
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  if ((u8) ~0 == node_id.type)
    {
      error = clib_error_return (0, "A valid node id must be specified");
      goto done;
    }

  vnet_api_error_t rv = upf_node_id_set (&node_id);
  if (rv)
    error = clib_error_return (0, "%U", format_vnet_api_errno, rv);

done:
  free_pfcp_ie_node_id (&node_id);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (upf_node_id_command, static) = {
  .path = "upf node-id",
  .short_help = "upf node-id (fqdn <fqdn> | ip4 <ip4-addr> | ip6 <ip6-addr>)",
  .function = upf_node_id_command_fn,
};

static clib_error_t *
upf_show_node_id_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                             vlib_cli_command_t *cmd)
{
  upf_main_t *um = &upf_main;
  vlib_cli_output (vm, "Node ID: %U", format_pfcp_ie_node_id, &um->node_id);
  return NULL;
}

VLIB_CLI_COMMAND (upf_show_node_id_command, static) = {
  .path = "show upf node-id",
  .short_help = "show upf node-id",
  .function = upf_show_node_id_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_gtpu_endpoint_add_del_command_fn (vlib_main_t *vm,
                                      unformat_input_t *main_input,
                                      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 teid = 0, mask = 0, teidri = 0;
  clib_error_t *error = NULL;
  ip6_address_t ip6 = { 0 };
  ip4_address_t ip4 = { 0 };
  u8 ip_set = 0;
  u8 *name = NULL;
  upf_interface_type_t intf = UPF_INTERFACE_DEFAULT_TYPE;
  u8 add = 1;
  int rv;
  u8 *s;
  u32 min_port = 32768, max_port = 32768 + 1024;

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
      else if (unformat (line_input, "intf %U", unformat_upf_interface_type,
                         &intf))
        ;
      else if (unformat (line_input, "teid %u/%u", &teid, &teidri))
        {
          if (teidri > 7)
            {
              error = clib_error_return (
                0, "TEID Range Indication to large (%d > 7)", teidri);
              goto done;
            }
          mask = 0xfe000000 << (7 - teidri);
        }
      else if (unformat (line_input, "teid 0x%x/%u", &teid, &teidri))
        {
          if (teidri > 7)
            {
              error = clib_error_return (
                0, "TEID Range Indication to large (%d > 7)", teidri);
              goto done;
            }
          mask = 0xfe000000 << (7 - teidri);
        }
      else if (unformat (line_input, "sport %u-%u", &min_port, &max_port))
        ;
      else if (unformat (line_input, "sport %u", &min_port))
        max_port = min_port;
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

  if (min_port > max_port || min_port > 65535 || max_port > 65535)
    {
      error = clib_error_return (0, "Invalid port range");
      goto done;
    }

  // TODO: introduce later with breaking API change
  // if (intf < 0 || intf >= UPF_INTERFACE_N_TYPE)
  //   {
  //     error = clib_error_return (0, "interface type is required");
  //     goto done;
  //   }

  rv = upf_gtpu_endpoint_add_del (&ip4, &ip6, name, intf, teid, mask, add,
                                  min_port, max_port);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error =
        clib_error_return (0, "network instance or entry does not exist...");
      break;

    default:
      error = clib_error_return (0, "upf_gtpu_endpoint_add_del returned %U",
                                 format_vnet_api_errno, rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (upf_gtpu_endpoint_command, static) = {
  .path = "upf gtpu endpoint",
  .short_help = "upf gtpu endpoint "
                "[ip <v4 address>] [ip6 <v6 address>] [nwi <name>] "
                "[intf (access | core | sgi | cp)] "
                "[teid <teid>/<mask>] "
                "[sport <port> | sport <min>-<max>] "
                "[del]",
  .function = upf_gtpu_endpoint_add_del_command_fn,
};

static clib_error_t *
upf_show_gtpu_endpoint_command_fn (vlib_main_t *vm,
                                   unformat_input_t *main_input,
                                   vlib_cli_command_t *cmd)
{
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  clib_error_t *error = NULL;
  upf_gtpu_endpoint_t *res;

  pool_foreach (res, ugm->endpoints)
    {
      vlib_cli_output (vm, "[%d]: %U", res - ugm->endpoints,
                       format_gtpu_endpoint, res);
    }

  // done:
  return error;
}

VLIB_CLI_COMMAND (upf_show_gtpu_endpoint_command, static) = {
  .path = "show upf gtpu endpoint",
  .short_help = "show upf gtpu endpoint",
  .function = upf_show_gtpu_endpoint_command_fn,
  .is_mp_safe = 1,
};

typedef struct
{
  vlib_main_t *vm;
  flowtable_wk_t *fwk;
  u32 limit;
  u32 thread_id;
  u32 filter_session_id;
  bool has_session_filter;
} flows_out_arg_t;

static int
_upf_flows_bihash4_out_cb (clib_bihash_kv_16_8_t *kvp, void *arg)
{
  flows_out_arg_t *arg_value = (flows_out_arg_t *) arg;

  flow_entry_t *flow = pool_elt_at_index (arg_value->fwk->flows, kvp->value);

  if (arg_value->has_session_filter &&
      flow->session_id != arg_value->filter_session_id)
    return BIHASH_WALK_CONTINUE;

  vlib_cli_output (arg_value->vm, "[%u] %U", kvp->value, format_flow_entry,
                   flow, arg_value->thread_id);

  if (is_valid_id (arg_value->limit))
    if (--arg_value->limit == 0)
      return BIHASH_WALK_STOP;

  return BIHASH_WALK_CONTINUE;
}

static int
_upf_flows_bihash6_out_cb (clib_bihash_kv_40_8_t *kvp, void *arg)
{
  flows_out_arg_t *arg_value = (flows_out_arg_t *) arg;

  flow_entry_t *flow = pool_elt_at_index (arg_value->fwk->flows, kvp->value);

  if (arg_value->has_session_filter &&
      flow->session_id != arg_value->filter_session_id)
    return BIHASH_WALK_CONTINUE;

  vlib_cli_output (arg_value->vm, "[%u] %U", kvp->value, format_flow_entry,
                   flow, arg_value->thread_id);

  if (is_valid_id (arg_value->limit))
    if (--arg_value->limit == 0)
      return BIHASH_WALK_STOP;

  return BIHASH_WALK_CONTINUE;
}

static clib_error_t *
upf_show_session_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                             vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *um = &upf_main;
  clib_error_t *error = NULL;
  u64 up_seid;
  u32 session_id;
  upf_imsi_t imsi_key;
  u8 has_up_seid = 0, has_imsi = 0, has_session_id = 0;
  upf_session_t *sx = NULL;
  u32 limit = DEFAULT_MAX_SHOW_UPF_SESSIONS;
  u8 has_flows = 0;

  bool locked = false;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "up seid 0x%llx", &up_seid))
            has_up_seid = 1;
          else if (unformat (line_input, "up seid %lu", &up_seid))
            has_up_seid = 1;
          else if (unformat (line_input, "id %u", &session_id))
            has_session_id = 1;
          else if (unformat (line_input, "imsi %U", unformat_upf_imsi_key,
                             &imsi_key))
            has_imsi = 1;
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

  if (has_flows && !has_up_seid && !has_session_id)
    {
      error = clib_error_return (
        0, "must specify UP F-SEID or session id to show session flows");
      goto done;
    }

  vlib_worker_thread_barrier_sync (vm);
  locked = true;

  if (has_flows)
    {
      if (has_session_id)
        {
          if (pool_is_free_index (um->sessions, session_id))
            {
              error =
                clib_error_return (0, "Session id %u not found", session_id);
              goto done;
            }
          sx = pool_elt_at_index (um->sessions, session_id);
        }
      else
        {
          if (!(sx = upf_session_get_by_up_seid (up_seid)))
            {
              error =
                clib_error_return (0, "Session 0x%lx not found", up_seid);
              goto done;
            }
        }

      if (sx->c_state != UPF_SESSION_STATE_CREATED)
        {
          // during creation list is empty, no problem
          // during removal can be removed anytime
          error = clib_error_return (
            0, "can't proceed while session in process of removal");
          goto done;
        }

      upf_dp_session_t *dsx =
        pool_elt_at_index (um->dp_sessions, sx - um->sessions);

      flowtable_main_t *fm = &flowtable_main;
      flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, sx->thread_index);

      uword limit_left = limit;
      upf_llist_foreach (flow, fwk->flows, session_anchor, &dsx->flows)
        {
          if (!limit_left)
            {
              vlib_cli_output (vm, "Max number of flows displayed: %u", limit);
              goto done;
            }

          limit_left -= 1;
          vlib_cli_output (vm, "[%u] %U", flow - fwk->flows, format_flow_entry,
                           flow, sx->thread_index);
        }

      goto done;
    }

  if (has_session_id)
    {
      if (pool_is_free_index (um->sessions, session_id))
        {
          error = clib_error_return (0, "Session id %u not found", session_id);
          goto done;
        }
      sx = pool_elt_at_index (um->sessions, session_id);
      vlib_cli_output (vm, "%U", format_upf_session, sx);
    }
  else if (has_up_seid)
    {
      if (!(sx = upf_session_get_by_up_seid (up_seid)))
        {
          error = clib_error_return (0, "Session 0x%lx not found", up_seid);
          goto done;
        }

      vlib_cli_output (vm, "%U", format_upf_session, sx);
    }
  else if (has_imsi)
    {
      upf_imsi_sessions_list_t *list = (upf_imsi_sessions_list_t *) mhash_get (
        &um->mhash_imsi_to_session_list, &imsi_key);

      if (!list)
        {
          error = clib_error_return (0, "Sessions for imsi %U not found",
                                     format_pfcp_tbcd, &imsi_key.tbcd,
                                     sizeof (imsi_key.tbcd));
          goto done;
        }

      uword limit_left = limit;
      upf_llist_foreach (sx, um->sessions, imsi_list_anchor, list)
        {
          if (!limit_left)
            {
              vlib_cli_output (vm, "Max number of sessions displayed: %u",
                               limit);
              goto done;
            }

          limit_left -= 1;
          vlib_cli_output (vm, "%U", format_upf_session, sx);
        };
    }
  else
    {
      u32 i = 0;
      pool_foreach (sx, um->sessions)
        {
          if (limit != 0 && i >= limit)
            {
              vlib_cli_output (vm, "Max number of sessions displayed: %u",
                               limit);
              break;
            }
          vlib_cli_output (vm, "%U", format_upf_session, sx);
          i += 1;
        }
    }

done:
  if (locked)
    vlib_worker_thread_barrier_release (vm);

  return error;
}

VLIB_CLI_COMMAND (upf_show_session_command, static) = {
  .path = "show upf session",
  .short_help = "show upf session "
                "[[id N] [up seid 0x...] [imsi <IMSI>] [flows]] [limit N]",
  .function = upf_show_session_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_show_assoc_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                           vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *um = &upf_main;
  clib_error_t *error = NULL;
  u8 has_ip = 0, has_fqdn = 0;
  ip46_address_t node_ip;
  upf_assoc_t *assoc;
  u8 verbose = 0;
  u8 *fqdn = 0;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "ip %U", unformat_ip46_address, &node_ip,
                        IP46_TYPE_ANY))
            has_ip = 1;
          else if (unformat (line_input, "fqdn %_%v%_", &fqdn))
            has_fqdn = 1;
          else if (unformat (line_input, "verbose"))
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
      error = clib_error_return (
        0, "Only one selector is allowed, either ip or fqdn");
      goto done;
    }

  if (has_ip || has_fqdn)
    {
      pfcp_ie_node_id_t node_id = {};

      if (has_ip)
        {
          node_id.type =
            ip46_address_is_ip4 (&node_ip) ? PFCP_NID_IPv4 : PFCP_NID_IPv6;
          node_id.ip = node_ip;
        }
      if (has_fqdn)
        {
          node_id.type = PFCP_NID_FQDN;
          node_id.fqdn = upf_name_to_labels (fqdn);
        }

      assoc = upf_assoc_get_by_nodeid (&node_id);

      free_pfcp_ie_node_id (&node_id);

      if (!assoc)
        {
          error = clib_error_return (0, "Association not found");
          goto done;
        }

      vlib_cli_output (vm, "%U", format_upf_assoc, assoc, verbose);
    }
  else
    {
      pool_foreach (assoc, um->assocs)
        {
          vlib_cli_output (vm, "%U", format_upf_assoc, assoc, verbose);
        }
    }

done:
  if (fqdn)
    vec_free (fqdn);

  return error;
}

VLIB_CLI_COMMAND (upf_show_assoc_command, static) = {
  .path = "show upf association",
  .short_help = "show upf association [ip <ip> | fqdn <fqdn>] [verbose]",
  .function = upf_show_assoc_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_delete_assoc_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                             vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *um = &upf_main;
  clib_error_t *error = NULL;
  u8 has_ip = 0, has_fqdn = 0;
  ip46_address_t node_ip;
  upf_assoc_t *assoc;
  u8 verbose = 0;
  u8 *fqdn = 0;
  bool all = false;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "ip %U", unformat_ip46_address, &node_ip,
                        IP46_TYPE_ANY))
            has_ip = 1;
          else if (unformat (line_input, "fqdn %_%v%_", &fqdn))
            has_fqdn = 1;
          else if (unformat (line_input, "all"))
            {
              all = true;
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

  if (has_ip && has_fqdn)
    {
      error = clib_error_return (
        0, "Only one selector is allowed, either ip or fqdn");
      goto done;
    }

  if (has_ip || has_fqdn)
    {
      pfcp_ie_node_id_t node_id = {};

      if (has_ip)
        {
          node_id.type =
            ip46_address_is_ip4 (&node_ip) ? PFCP_NID_IPv4 : PFCP_NID_IPv6;
          node_id.ip = node_ip;
        }
      if (has_fqdn)
        {
          node_id.type = PFCP_NID_FQDN;
          node_id.fqdn = upf_name_to_labels (fqdn);
        }

      assoc = upf_assoc_get_by_nodeid (&node_id);

      free_pfcp_ie_node_id (&node_id);

      if (!assoc)
        {
          error = clib_error_return (0, "Association not found");
          goto done;
        }

      vlib_cli_output (vm, "%U", format_upf_assoc, assoc, verbose);
      if (!assoc->is_released)
        upf_assoc_delete (assoc, "user request");
    }
  else if (all)
    {
      pool_foreach (assoc, um->assocs)
        {
          if (!assoc->is_released)
            upf_assoc_delete (assoc, "user request");
        }
    }
  else
    {
      error = clib_error_return (0, "Provide specific association or all");
      goto done;
    }

done:
  if (fqdn)
    vec_free (fqdn);

  return error;
}

VLIB_CLI_COMMAND (upf_delete_assoc_command, static) = {
  .path = "delete upf association",
  .short_help = "delete upf association [(ip X | fqdn Y) | all]",
  .function = upf_delete_assoc_command_fn,
};

static clib_error_t *
upf_show_flows_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                           vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  flowtable_main_t *fm = &flowtable_main;
  clib_error_t *error = NULL;
  u32 limit = 2000;
  u32 filter_session_id = ~0;
  bool has_session_filter = false;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "limit %u", &limit))
            ;
          else if (unformat (line_input, "session_id %u", &filter_session_id))
            has_session_filter = true;
          else
            {
              error = unformat_parse_error (line_input);
              unformat_free (line_input);
              goto done;
            }
        }
      unformat_free (line_input);
    }

  vlib_worker_thread_barrier_sync (vm);

  flowtable_wk_t *fwk;
  vec_foreach (fwk, fm->workers)
    {
      u32 thread_id = fwk - fm->workers;
      flows_out_arg_t arg = {
        .vm = vm,
        .limit = limit,
        .fwk = fwk,
        .thread_id = thread_id,
        .filter_session_id = filter_session_id,
        .has_session_filter = has_session_filter,
      };

      vlib_cli_output (vm, "flows for worker %u:\n", thread_id);

      clib_bihash_foreach_key_value_pair_16_8 (
        &fwk->flows_ht4, _upf_flows_bihash4_out_cb, &arg);

      clib_bihash_foreach_key_value_pair_40_8 (
        &fwk->flows_ht6, _upf_flows_bihash6_out_cb, &arg);
    }

  vlib_worker_thread_barrier_release (vm);

done:
  return error;
}

VLIB_CLI_COMMAND (upf_show_flows_command, static) = {
  .path = "show upf flows",
  .short_help = "show upf flows [session_id <id>] [limit <n>]",
  .function = upf_show_flows_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_show_config_fn (vlib_main_t *vm, unformat_input_t *main_input,
                    vlib_cli_command_t *cmd)
{
  upf_main_t *um = &upf_main;
  flowtable_main_t *fm = &flowtable_main;

  vlib_cli_output (vm, "pfcp.specification-version: %u\n",
                   um->pfcp_spec_version);
  vlib_cli_output (vm, "pfcp.node-id: %U\n", format_pfcp_ie_node_id,
                   &um->node_id);
  vlib_cli_output (vm, "flow.max-flows-per-worker: %u\n",
                   fm->max_flows_per_worker);

  return 0;
}

VLIB_CLI_COMMAND (upf_show_config, static) = {
  .path = "show upf config",
  .short_help = "show upf config",
  .function = upf_show_config_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_show_bihash_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                            vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
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
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  switch (hash)
    {
    case 1:
      vlib_cli_output (vm, "%U", format_bihash_8_8, &ugm->tunnel_by_fteid4,
                       verbose);
      break;
    case 2:
      vlib_cli_output (vm, "%U", format_bihash_24_8, &ugm->tunnel_by_fteid6,
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

VLIB_CLI_COMMAND (upf_show_bihash_command, static) = {
  .path = "show upf bihash",
  .short_help =
    "show upf bihash <v4-tunnel-by-key | v6-tunnel-by-key> [detail|verbose]",
  .function = upf_show_bihash_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_show_pools_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                           vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  bool with_threads = false;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "with-threads"))
            with_threads = true;
          else
            {
              error = unformat_parse_error (line_input);
              unformat_free (line_input);
              goto done;
            }
        }
      unformat_free (line_input);
    }

#define print_pool(name, var)                                                 \
  vlib_cli_output (vm, name ": used: %d total: %d", pool_elts (var),          \
                   vec_len (var));

#define print_heap(name, var)                                                 \
  if (var)                                                                    \
    vlib_cli_output (vm, name ": handles: %d total: %d", heap_elts (var),     \
                     vec_len (var));                                          \
  else                                                                        \
    vlib_cli_output (vm, name ": empty");

  upf_main_t *um = &upf_main;
  pfcp_server_main_t *psm = &pfcp_server_main;
  flowtable_main_t *fm = &flowtable_main;
  upf_nat_main_t *unm = &upf_nat_main;
  upf_dpo_main_t *udm = &upf_dpo_main;
  upf_gtpu_main_t *ugm = &upf_gtpu_main;
  upf_ipfix_main_t *uim = &upf_ipfix_main;
  upf_acl_main_t *uam = &upf_acl_main;

  print_pool ("sessions", um->sessions);
  print_pool ("rules", um->rules);
  print_pool ("nwis", um->nwis);
  print_pool ("nwi_interfaces", um->nwi_interfaces);
  print_pool ("forwarding_policies", um->forwarding_policies);
  print_pool ("ueip_pools", um->ueip_pools);
  print_pool ("session_procedures", um->session_procedures);
  print_pool ("cached_fseid", um->cached_fseid_pool);
  print_pool ("associations", um->assocs);
  print_pool ("smf_sets", um->smf_sets);
  print_pool ("pfcp.requests", psm->requests);
  print_pool ("pfcp.responses", psm->responses);
  print_pool ("gtpu.endpoints", ugm->endpoints);
  print_pool ("dpo.dpos_result", udm->cp_dpos_results);
  print_pool ("acl.cache_entries", uam->cache_entries);
  print_heap ("heap.pdrs", um->heaps.pdrs);
  print_heap ("heap.fars", um->heaps.fars);
  print_heap ("heap.urrs", um->heaps.urrs);
  print_heap ("heap.traffic_endpoints", um->heaps.teps);
  print_heap ("heap.ep_ips4", um->heaps.ep_ips4);
  print_heap ("heap.ep_ips6", um->heaps.ep_ips6);
  print_heap ("heap.f_teids", um->heaps.f_teids);
  print_heap ("heap.ep_gtpus", um->heaps.ep_gtpus);
  print_heap ("heap.acls4", um->heaps.acls4);
  print_heap ("heap.acls6", um->heaps.acls6);
  print_pool ("netcap.captures", um->netcap.captures);
  print_pool ("netcap.capture_lists", um->netcap.capture_lists);
  print_pool ("nat.pools", unm->nat_pools);
  print_pool ("nat.bindings", unm->bindings);
  print_pool ("ipfix.contexts", uim->contexts);

  if (!with_threads)
    return NULL;

  upf_timer_main_t *utm = &upf_timer_main;

  vlib_worker_thread_barrier_sync (vm);
  u32 thread_id;
  vec_foreach_index (thread_id, um->workers)
    {
      vlib_cli_output (vm, "- thread %d:", thread_id);
      upf_main_wk_t *uwk = vec_elt_at_index (um->workers, thread_id);
      flowtable_wk_t *fwk = vec_elt_at_index (fm->workers, thread_id);
      upf_nat_wk_t *nnk = vec_elt_at_index (unm->workers, thread_id);
      upf_timer_wk_t *utw = vec_elt_at_index (utm->workers, thread_id);

      print_pool ("  split_measurements", uwk->split_measurements);
      print_pool ("  flows", fwk->flows);
      print_pool ("  nat.flows", nnk->flows);
      print_pool ("  nat.icmp_flows", nnk->icmp_flows);
      print_pool ("  timers", utw->timers);
    }
  vlib_worker_thread_barrier_release (vm);

#undef print_pool
#undef print_heap

done:
  return error;
}

VLIB_CLI_COMMAND (upf_show_pools_command, static) = {
  .path = "show upf pools",
  .short_help = "show upf pools [with-threads]",
  .function = upf_show_pools_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_proxy_set_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                          vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_proxy_main_t *upm = &upf_proxy_main;
  clib_error_t *error = NULL;

  u32 tmp32;

#define _(type, name) type name = upm->config.name;
  foreach_upf_proxy_config_fields
#undef _

    if (unformat_user (main_input, unformat_line_input, line_input))
  {
    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
      {
        if (unformat (line_input, "mss %d", &tmp32))
          mss = (u16) tmp32;
        else if (unformat (line_input, "fifo-size %U", unformat_memory_size,
                           &fifo_size))
          ;
        else if (unformat (line_input, "max-fifo-size %U",
                           unformat_memory_size, &max_fifo_size))
          ;
        else if (unformat (line_input, "high-watermark %d", &tmp32))
          high_watermark = (u8) tmp32;
        else if (unformat (line_input, "low-watermark %d", &tmp32))
          low_watermark = (u8) tmp32;
        else if (unformat (line_input, "prealloc-fifos %d", &prealloc_fifos))
          ;
        else if (unformat (line_input, "private-segment-count %d",
                           &private_segment_count))
          ;
        else if (unformat (line_input, "private-segment-size %U",
                           unformat_memory_size, &private_segment_size))
          ;
        else
          {
            error = clib_error_return (0, "unknown input `%U'",
                                       format_unformat_error, line_input);
            unformat_free (line_input);
            return error;
          }
      }
    unformat_free (line_input);
  }

#define _(type, name) upm->config.name = name;
  foreach_upf_proxy_config_fields
#undef _
    return 0;
}

VLIB_CLI_COMMAND (upf_proxy_set_command, static) = {
  .path = "set upf proxy",
  .short_help = "set upf proxy "
                "[mss <nn>] "
                "[fifo-size <nn>[k|m]] "
                "[max-fifo-size <nn>[k|m]] "
                "[high-watermark <nn>] "
                "[low-watermark <nn>] "
                "[prealloc-fifos <nn>] "
                "[private-segment-size <mem>] "
                "[private-segment-count <nn>]",
  .function = upf_proxy_set_command_fn,
};

static clib_error_t *
upf_show_proxy_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                           vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_proxy_main_t *upm = &upf_proxy_main;
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

  vlib_cli_output (vm,
                   "MSS: %u\n"
                   "FIFO Size: %U\n"
                   "Max FIFO Size: %U\n"
                   "Hi/Lo Watermark: %u %% / %u %%\n"
                   "Prealloc FIFOs: %u\n"
                   "Private Segment Count: %u\n"
                   "Private Segment Size: %U\n",
                   upm->config.mss, format_memory_size, upm->config.fifo_size,
                   format_memory_size, upm->config.max_fifo_size,
                   upm->config.high_watermark, upm->config.low_watermark,
                   upm->config.prealloc_fifos,
                   upm->config.private_segment_count, format_memory_size,
                   upm->config.private_segment_size);

done:
  return error;
}

VLIB_CLI_COMMAND (upf_show_proxy_command, static) = {
  .path = "show upf proxy",
  .short_help = "show upf proxy",
  .function = upf_show_proxy_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_show_proxy_session_command_fn (vlib_main_t *vm,
                                   unformat_input_t *main_input,
                                   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_proxy_main_t *upm = &upf_proxy_main;
  clib_error_t *error = NULL;
  u32 limit_per_wk = 2000;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "limit %u", &limit_per_wk))
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

  vlib_worker_thread_barrier_sync (vm);

  upf_proxy_worker_t *pwk;
  vec_foreach (pwk, upm->workers)
    {
      int i = 0;
      u32 thread_id = pwk - upm->workers;

      upf_proxy_session_t *ps;
      pool_foreach (ps, pwk->sessions)
        {
          if (i >= limit_per_wk)
            {
              vlib_cli_output (
                vm, " --- truncated %d/%d more sessions on worker %d\n",
                pool_elts (pwk->sessions) - limit_per_wk,
                pool_elts (pwk->sessions), pwk - upm->workers);
              break;
            }

          vlib_cli_output (vm, "%U\n", format_upf_proxy_session, thread_id,
                           ps);
          i += 1;
        }
    }

  vlib_worker_thread_barrier_release (vm);

done:
  return error;
}

VLIB_CLI_COMMAND (upf_show_proxy_session_command, static) = {
  .path = "show upf proxy sessions",
  .short_help = "show upf proxy sessions [limit <N>]",
  .function = upf_show_proxy_session_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_show_policy_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                            vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_main_t *um = &upf_main;
  clib_error_t *error = NULL;
  u8 *policy_id = NULL;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "%_%v%_", &policy_id))
            ;
          else
            {
              error = clib_error_return (0, "unknown input '%U'",
                                         format_unformat_error, line_input);
              unformat_free (line_input);
              goto done;
            }
        }
      unformat_free (line_input);
    }

  if (policy_id == NULL)
    {
      upf_forwarding_policy_t *fp;
      pool_foreach (fp, um->forwarding_policies)
        vlib_cli_output (vm, "%U\n", format_upf_forwarding_policy, fp);
    }
  else
    {
      upf_forwarding_policy_t *fp =
        upf_forwarding_policy_get_by_name (policy_id);
      if (fp)
        vlib_cli_output (vm, "%U\n", format_upf_forwarding_policy, fp);
      else
        error =
          clib_error_return (0, "unknown forwarding policy %v", policy_id);
    }

done:
  vec_free (policy_id);
  return error;
}

VLIB_CLI_COMMAND (upf_show_policy_command, static) = {
  .path = "show upf policy",
  .short_help = "show upf policy [<policy_id>]",
  .function = upf_show_policy_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_policy_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;

  u8 *policy_id = NULL;
  u8 action = ~0;
  u32 ip4_table_id = ~0, ip6_table_id = ~0;

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
      else if (unformat (line_input, "via ip4-lookup-in-table %d",
                         &ip4_table_id))
        ;
      else if (unformat (line_input, "via ip6-lookup-in-table %d",
                         &ip6_table_id))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  if (!is_valid_id (action))
    {
      error = clib_error_return (0, "provide action: add, del or update");
      goto done;
    }

  error = upf_forwarding_policy_add_del (policy_id, ip4_table_id, ip6_table_id,
                                         action);

done:
  vec_free (policy_id);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (upf_add_policy_command, static) = {
  .path = "upf policy",
  .short_help = "upf policy (add|del|update) id <policy_id> "
                "[via ip4-lookup-in-table <X>] [via ip6-lookup-in-table <Y>]",
  .function = upf_policy_command_fn,
};

static clib_error_t *
upf_pfcp_heartbeat_config_command_fn (vlib_main_t *vm,
                                      unformat_input_t *main_input,
                                      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
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
      else if (unformat (line_input, "retries %u", &retries))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  rv = upf_pfcp_heartbeat_config (timeout, retries);
  if (rv)
    error = clib_error_return (0, "invalid parameters");

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (upf_pfcp_heartbeat_config_command, static) = {
  .path = "upf pfcp heartbeat-config",
  .short_help = "upf pfcp heartbeat-config timeout <sec> retries <count>",
  .function = upf_pfcp_heartbeat_config_command_fn,
};

static clib_error_t *
upf_show_pfcp_heartbeat_config_command_fn (vlib_main_t *vm,
                                           unformat_input_t *main_input,
                                           vlib_cli_command_t *cmd)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  vlib_cli_output (vm, "Timeout: %u Retries: %u", psm->heartbeat_cfg.timeout,
                   psm->heartbeat_cfg.retries);
  return NULL;
}

VLIB_CLI_COMMAND (upf_show_pfcp_heartbeat_config_command, static) = {
  .path = "show upf heartbeat-config",
  .short_help = "show upf heartbeat-config",
  .function = upf_show_pfcp_heartbeat_config_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_netcap_session_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                               vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  bool enable = true;
  bool has_imsi = false;
  upf_imsi_t key;
  u8 *target = NULL;
  u8 *tag = NULL;
  u32 packet_max_bytes = 9000;
  clib_error_t *err = NULL;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "disable"))
        enable = false;
      else if (unformat (line_input, "imsi %U", unformat_upf_imsi_key, &key))
        has_imsi = true;
      else if (unformat (line_input, "packet_max_bytes %u", &packet_max_bytes))
        ;
      else if (unformat (line_input, "target %v", &target))
        ;
      else if (unformat (line_input, "tag %v", &tag))
        ;
      else
        {
          err = clib_error_return (0, "invalid input: %U",
                                   format_unformat_input, line_input);
          unformat_free (line_input);
          goto cleanup;
        }
    }
  unformat_free (line_input);

  if (!has_imsi)
    {
      err = clib_error_return (0, "imsi is not provided or invalid");
      goto cleanup;
    }

  if (enable && vec_len (target) == 0)
    {
      err = clib_error_return (0, "invalid target");
      goto cleanup;
    }

  if (packet_max_bytes < 32 || packet_max_bytes > 16000)
    {
      err = clib_error_return (
        0, "packet max bytes should be in [32,16000] range");
      goto cleanup;
    }

  err = upf_imsi_netcap_enable_disable (key, target, tag, packet_max_bytes,
                                        enable);

cleanup:
  if (target)
    vec_free (target);
  if (tag)
    vec_free (tag);
  return err;
}

VLIB_CLI_COMMAND (upf_netcap_session_command, static) = {
  .path = "upf netcap session",
  .short_help = "upf netcap session imsi <IMSI> target <name> [tag <tag>] "
                "[packet_max_bytes 9000] [disable]",
  .function = upf_netcap_session_command_fn,
};

static clib_error_t *
upf_netcap_show_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                            vlib_cli_command_t *cmd)
{
  upf_main_t *um = &upf_main;
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

        vlib_cli_output (vm, "  %U: %v%s%v, max_bytes: %u\n", format_pfcp_tbcd,
                         &imsi->tbcd, sizeof (imsi->tbcd), capture->target,
                         vec_len (capture->tag) ? ", tag: " : "", capture->tag,
                         capture->packet_max_bytes);
    }));

  return NULL;
}

VLIB_CLI_COMMAND (upf_netcap_show_command, static) = {
  .path = "show upf netcap",
  .short_help = "show upf netcap",
  .function = upf_netcap_show_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_post_mortem_dump_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                                 vlib_cli_command_t *cmd)
{
  upf_main_t *um = &upf_main;

  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  int enable = ~0;

  u32 limit = ~0;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
        enable = 1;
      else if (unformat (line_input, "disable"))
        enable = 0;
      else if (unformat (line_input, "elog_limit %u", &limit))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  if (!is_valid_id (enable))
    {
      error = clib_error_return (0, "provide enable or disable");
      goto done;
    }

  if (is_valid_id (limit) && (limit >= 100000))
    {
      error = clib_error_return (0, "limit must be less than 100000");
      goto done;
    }

  vlib_add_del_post_mortem_callback (upf_post_mortem_dump, enable);
  if (limit != ~0)
    um->post_mortem_events_show_limit = limit;

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (upf_post_mortem_dump_command, static) = {
  .path = "upf post-mortem",
  .short_help = "upf post-mortem (enable|disable) [elog_limit X]",
  .function = upf_post_mortem_dump_command_fn,
};

static clib_error_t *
upf_pfcp_ratelimit_set_command_fn (vlib_main_t *vm,
                                   unformat_input_t *main_input,
                                   vlib_cli_command_t *cmd)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u32 request_rate_limit = ~0;
  u32 request_rate_burst = ~0;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "request-rate-limit %u", &request_rate_limit))
        ;
      else if (unformat (line_input, "request-rate-burst %u",
                         &request_rate_burst))
        ;
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  if (request_rate_limit == 0)
    {
      error = clib_error_return (0, "rate should not be zero");
      goto done;
    }
  else if (request_rate_burst == ~0)
    request_rate_burst =
      request_rate_limit; // by default provide same burst as rate
  else if (request_rate_burst == 0)
    request_rate_burst = 1;

  if (request_rate_limit != ~0)
    tokenbucket_init (&psm->pfcp_request_drop_ratelimit, upf_time_now_main (),
                      request_rate_limit, request_rate_burst);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (upf_pfcp_ratelimit_set_command, static) = {
  .path = "upf pfcp set",
  .short_help = "upf pfcp set request-rate-limit <packet-per-second> "
                "[request-rate-burst <burst-capacity>]",
  .function = upf_pfcp_ratelimit_set_command_fn,
};

static clib_error_t *
upf_urr_set_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                        vlib_cli_command_t *cmd)
{
  upf_main_t *um = &upf_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u32 start_event_ratelimit = ~0;
  u32 start_event_timeout = ~0;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "start-event-ratelimit %u",
                    &start_event_ratelimit))
        ;
      else if (unformat (line_input, "start-event-timeout %u",
                         &start_event_timeout))
        ;
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  // validate
  if (start_event_ratelimit != ~0)
    if (start_event_ratelimit == 0 || start_event_ratelimit > 10000)
      {
        error = clib_error_return (
          0, "start event rate limit should be between [1, 10000]");
        goto done;
      }

  if (start_event_timeout != ~0)
    if (start_event_timeout == 0 || start_event_timeout > 3600)
      {
        error = clib_error_return (
          0, "start event timeout should be in range [1, 3600]");
        goto done;
      }

  // apply
  if (start_event_ratelimit != ~0)
    ratelimit_atomic_init (&um->start_of_traffic_rate_limit,
                           upf_time_now_main (), start_event_ratelimit);

  if (start_event_timeout != ~0)
    um->start_of_traffic_event_timeout_s = start_event_timeout;

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (upf_urr_set_command, static) = {
  .path = "upf urr set",
  .short_help = "upf urr set [start-event-ratelimit <reports-per-second>] "
                "[start-event-timeout <per-ip-timeout-seconds>]",
  .function = upf_urr_set_command_fn,
};
