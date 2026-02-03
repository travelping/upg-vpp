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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>

#include "upf/upf.h"
#include "upf/nat/nat.h"
#include "upf/utils/worker_pool.h"

static clib_error_t *
upf_nat_pool_add_del_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                                 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = 0;
  u8 *nwi_name = 0;
  ip4_address_t start = {}, end = {};
  u32 min_port = UPF_NAT_MIN_PORT;
  u32 max_port = 0xffff;
  u32 port_block_size = 0;
  upf_interface_type_t intf = UPF_INTERFACE_DEFAULT_TYPE;
  bool is_add = true;

  bool has_ip_range = false;
  bool has_block_size = false;
  bool has_nwi = false;
  bool has_name = false;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U - %U", unformat_ip4_address, &start,
                    unformat_ip4_address, &end))
        has_ip_range = true;
      else if (unformat (line_input, "block_size %u", &port_block_size))
        has_block_size = true;
      else if (unformat (line_input, "min_port %u", &min_port))
        ;
      else if (unformat (line_input, "max_port %u", &max_port))
        ;
      else if (unformat (line_input, "nwi %_%v%_", &nwi_name))
        has_nwi = true;
      else if (unformat (line_input, "name %_%v%_", &name))
        has_name = true;
      else if (unformat (line_input, "intf %U", unformat_upf_interface_type,
                         &intf))
        ;
      else if (unformat (line_input, "del"))
        is_add = false;
      else
        {
          error = unformat_parse_error (line_input);
          unformat_free (line_input);
          goto done;
        }
    }
  unformat_free (line_input);

  if (is_add && !has_ip_range)
    {
      error = clib_error_return (0, "IP range not provided");
      goto done;
    }
  else if (is_add && !has_block_size)
    {
      error = clib_error_return (0, "Block size not provided");
      goto done;
    }
  else if (is_add && !has_nwi)
    {
      error = clib_error_return (0, "NWI name not provided");
      goto done;
    }
  else if (!has_name)
    {
      error = clib_error_return (0, "Pool name not provided");
      goto done;
    }

  /*
   * Extra port range check here because port values are parsed into
   * u32 instead of u16
   */
  if (min_port < UPF_NAT_MIN_PORT || max_port > 0xffff || min_port > max_port)
    error = clib_error_return (0, "Invalid port range");
  else
    {
      u8 *nwi_fqdn = upf_name_to_labels (nwi_name);

      vnet_api_error_t rv =
        upf_nat_pool_add_del (nwi_fqdn, intf, start, end, name,
                              port_block_size, min_port, max_port, is_add);

      vec_free (nwi_fqdn);

      if (rv)
        error = clib_error_return (0, "Pool operation error: %U",
                                   format_vnet_api_errno, rv);
    }

done:
  vec_free (nwi_name);
  vec_free (name);

  return error;
}

VLIB_CLI_COMMAND (upf_nat_pool_add_del_command, static) = {
  .path = "upf nat pool",
  .short_help = "upf nat pool name <name> nwi <nwi-name> "
                "<ip4-addr-start> - <ip4-addr-end> "
                "block_size <port-block-size> "
                "[min_port <port>] [max_port <port>] "
                "[intf (access|core|sgi|cp)] [del]",
  .function = upf_nat_pool_add_del_command_fn,
};

static clib_error_t *
upf_nat_show_icmp_flows_command_fn (vlib_main_t *vm,
                                    unformat_input_t *main_input,
                                    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_nat_main_t *unm = &upf_nat_main;
  clib_error_t *error = NULL;
  u32 limit = 1000;

  if (!unm->initialized)
    return NULL;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "limit %u", &limit))
            ;
          else
            {
              error = unformat_parse_error (line_input);
              unformat_free (line_input);
              return error;
            }
        }
      unformat_free (line_input);
    }

  vlib_worker_thread_barrier_sync (vm);
  {
    upf_nat_wk_t *unw;
    vec_foreach (unw, unm->workers)
      {
        u32 limit_left = limit;
        u32 worker_id = unw - unm->workers;
        upf_nat_icmp_flow_t *nif;
        pool_foreach (nif, unw->icmp_flows)
          {
            if (limit_left-- == 0)
              {
                vlib_cli_output (vm, ".. output entries limit..\n");
                break;
              }

            vlib_cli_output (vm, "[w %u] id %u %U\n", worker_id,
                             nif - unw->icmp_flows, format_upf_nat_icmp_flow,
                             nif);
          }
      }
  }
  vlib_worker_thread_barrier_release (vm);

  return NULL;
}

VLIB_CLI_COMMAND (upf_nat_show_icmp_flows, static) = {
  .path = "show upf nat icmp flows",
  .short_help = "show upf nat icmp flows [limit <N>]",
  .function = upf_nat_show_icmp_flows_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_nat_show_tcpudp_flows_command_fn (vlib_main_t *vm,
                                      unformat_input_t *main_input,
                                      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_nat_main_t *unm = &upf_nat_main;
  clib_error_t *error = NULL;
  u32 limit = 1000;

  if (!unm->initialized)
    return NULL;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "limit %u", &limit))
            ;
          else
            {
              error = unformat_parse_error (line_input);
              unformat_free (line_input);
              return error;
            }
        }
      unformat_free (line_input);
    }

  vlib_worker_thread_barrier_sync (vm);
  {
    upf_nat_wk_t *unw;
    vec_foreach (unw, unm->workers)
      {
        u32 limit_left = limit;
        u32 worker_id = unw - unm->workers;
        upf_nat_flow_t *nif;
        pool_foreach (nif, unw->flows)
          {
            if (limit_left-- == 0)
              {
                vlib_cli_output (vm, ".. output entries limit..\n");
                break;
              }
            vlib_cli_output (vm, "[w %u][id %u] %U\n", worker_id,
                             nif - unw->flows, format_upf_nat_flow, nif);
          }
      }
  }
  vlib_worker_thread_barrier_release (vm);

  return NULL;
}

VLIB_CLI_COMMAND (upf_nat_show_tcpudp_flows, static) = {
  .path = "show upf nat tcpudp flows",
  .short_help = "show upf nat tcpudp flows [limit <N>]",
  .function = upf_nat_show_tcpudp_flows_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_nat_show_pool_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                              vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_nat_main_t *unm = &upf_nat_main;
  clib_error_t *error = NULL;
  bool has_name = false;
  bool verbose = false;
  u8 *name = NULL;

  if (!unm->initialized)
    return NULL;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "name %v", &name))
            has_name = true;
          else if (unformat (line_input, "verbose"))
            verbose = true;
          else
            {
              error = unformat_parse_error (line_input);
              unformat_free (line_input);
              goto done;
            }
        }
      unformat_free (line_input);
    }

  if (has_name)
    {
      upf_nat_pool_t *pool = upf_nat_pool_get_by_name (name);
      if (!pool)
        {
          error = clib_error_return (0, "pool name '%v' not found", name);
          goto done;
        }

      vlib_cli_output (vm, "%U\n", format_upf_nat_pool, pool);
      if (verbose)
        {
          vlib_cli_output (vm, "List of bindings:\n");

          upf_nat_block_t *block;
          vec_foreach (block, pool->vec_blocks)
            {
              if (upf_nat_block_free_list_el_is_part_of_list (block))
                continue;

              if (is_valid_id (block->binding_id))
                {
                  upf_nat_binding_t *b = upf_worker_pool_elt_at_index (
                    unm->bindings, block->binding_id);
                  vlib_cli_output (vm, "id %u binding {%U}\n",
                                   block - pool->vec_blocks,
                                   format_upf_nat_binding, b);
                }
              else
                {
                  vlib_cli_output (vm, "id %u safety timeout\n",
                                   block - pool->vec_blocks);
                }
            };
        }
      goto done;
    }

  if (verbose)
    {
      error = clib_error_return (0, "verbose requires pool name");
      goto done;
    }

  upf_nat_pool_t *pool;
  pool_foreach (pool, unm->nat_pools)
    {
      vlib_cli_output (vm, "%U\n", format_upf_nat_pool, pool);
    }

done:
  vec_free (name);
  return error;
}

VLIB_CLI_COMMAND (upf_nat_show_pool, static) = {
  .path = "show upf nat pool",
  .short_help = "show upf nat pool [name <NAME>] [verbose]",
  .function = upf_nat_show_pool_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
upf_nat_config_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                           vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  upf_nat_main_t *unm = &upf_nat_main;
  clib_error_t *error = NULL;
  uword icmp_flow_timeout = 0;
  uword icmp_max_flows_per_binding = 0;
  uword binding_block_timeout = 0;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (line_input, "icmp-flow-timeout %u",
                        &icmp_flow_timeout))
            {
              if (icmp_flow_timeout < 2 || icmp_flow_timeout > 60)
                {
                  error = clib_error_return (
                    0, "icmp flow timeout should be between 2 and 60");
                  unformat_free (line_input);
                  return error;
                }
            }
          else if (unformat (line_input, "icmp-max-flows-per-binding %u",
                             &icmp_max_flows_per_binding))
            {
              if (icmp_max_flows_per_binding < 1 ||
                  icmp_max_flows_per_binding > 65536)
                {
                  error =
                    clib_error_return (0, "icmp max flows per binding should "
                                          "be between 1 and 65536");
                  unformat_free (line_input);
                  return error;
                }
            }
          else if (unformat (line_input, "binding-block-timeout %u",
                             &binding_block_timeout))
            {
              if (binding_block_timeout < 1 || binding_block_timeout > 7200)
                {
                  error = clib_error_return (
                    0, "binding block timeout should be between 1 and 7200");
                  unformat_free (line_input);
                  return error;
                }
            }
          else
            {
              error = unformat_parse_error (line_input);
              unformat_free (line_input);
              return error;
            }
        }
      unformat_free (line_input);
    }

  if (icmp_flow_timeout)
    unm->icmp_flow_timeout = icmp_flow_timeout;

  if (icmp_max_flows_per_binding)
    unm->icmp_max_flows_per_binding = icmp_max_flows_per_binding;

  if (binding_block_timeout)
    unm->binding_block_timeout = binding_block_timeout;

  return NULL;
}

VLIB_CLI_COMMAND (upf_nat_config, static) = {
  .path = "upf nat config",
  .short_help = "upf nat config "
                "[icmp-flow-timeout <SECONDS>] "
                "[icmp-max-flows-per-binding <COUNT>] "
                "[binding-block-timeout <SECONDS>]",
  .function = upf_nat_config_command_fn,
};

static clib_error_t *
upf_nat_show_config_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                vlib_cli_command_t *cmd)
{
  upf_nat_main_t *unm = &upf_nat_main;

  vlib_cli_output (vm, "initialized: %s\n",
                   unm->initialized ? "true" : "false");
  vlib_cli_output (vm, "icmp-flow-timeout: %u\n", unm->icmp_flow_timeout);
  vlib_cli_output (vm, "icmp-max-flows-per-binding: %u\n",
                   unm->icmp_max_flows_per_binding);
  vlib_cli_output (vm, "binding-block-timeout: %u\n",
                   unm->binding_block_timeout);

  return NULL;
}

VLIB_CLI_COMMAND (upf_nat_show_config, static) = {
  .path = "show upf nat config",
  .short_help = "show upf nat config",
  .function = upf_nat_show_config_command_fn,
  .is_mp_safe = 1,
};
