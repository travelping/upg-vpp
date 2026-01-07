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

#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>

#include <vnet/api_errno.h>
#include <vppinfra/clib_error.h>

#include "upf/upf.h"
#include "upf/integrations/upf_ueip_export.h"

/* There is an issue with missed vppinfra/linux/netns.h file from distribution,
 * we copy declarations here */
int clib_netns_open (u8 *netns);
int clib_setns (int nfd);

#define UPF_DEBUG_ENABLE 0

vnet_api_error_t
upf_ueip_export_enable_disable (bool enable, u32 host_table_id,
                                u8 *host_if_name, u8 *host_ns_name)
{
  upf_main_t *um = &upf_main;
  vnet_api_error_t rv = 0;

  if (enable)
    {
      int dest_ns_fd = -1, vpp_ns_fd = -1;
      if (um->ueip_export.enabled)
        return VNET_API_ERROR_VALUE_EXIST;

      if (!is_valid_id (host_table_id) || !vec_len (host_if_name) ||
          !vec_len (host_ns_name))
        return VNET_API_ERROR_INVALID_VALUE;

      if (vec_len (host_if_name) > 64)
        return VNET_API_ERROR_INVALID_VALUE;

      u8 *host_ns_name_zt = vec_dup (host_ns_name);
      vec_terminate_c_string (host_ns_name_zt);
      dest_ns_fd = clib_netns_open (host_ns_name_zt);
      vec_free (host_ns_name_zt);
      if (dest_ns_fd == -1)
        return VNET_API_ERROR_SYSCALL_ERROR_1;

      vpp_ns_fd = clib_netns_open (NULL);
      if (vpp_ns_fd == -1)
        {
          close (dest_ns_fd);
          return VNET_API_ERROR_SYSCALL_ERROR_2;
        }

      if (clib_setns (dest_ns_fd) == -1)
        {
          close (dest_ns_fd);
          close (vpp_ns_fd);
          return VNET_API_ERROR_SYSCALL_ERROR_3;
        }

      u8 *host_if_name_zt =
        vec_dup (host_if_name); // mitigate possible reallocation
      vec_terminate_c_string (host_if_name_zt);
      um->ueip_export.host_if_index =
        if_nametoindex ((char *) host_if_name_zt);
      vec_free (host_if_name_zt);
      if (um->ueip_export.host_if_index == 0)
        {
          rv = VNET_API_ERROR_INVALID_INTERFACE;
          goto out;
        }

      um->ueip_export.nl_sock = nl_socket_alloc ();
      if (um->ueip_export.nl_sock == NULL)
        {
          rv = VNET_API_ERROR_NETLINK_ERROR;
          goto out;
        }

      if (nl_connect (um->ueip_export.nl_sock, NETLINK_ROUTE) != 0)
        {
          rv = VNET_API_ERROR_NETLINK_ERROR;
          goto out;
        }

      um->ueip_export.enabled = true;

      um->ueip_export.host_table_id = host_table_id;
      um->ueip_export.host_if_name = vec_dup (host_if_name);
      um->ueip_export.host_ns_name = vec_dup (host_ns_name);
      mhash_init (&um->ueip_export.added_ips, sizeof (u32),
                  sizeof (ip46_address_t));

    out:
      clib_setns (vpp_ns_fd);
      close (dest_ns_fd);
      close (vpp_ns_fd);
    }
  else
    {
      um->ueip_export.enabled = false;

      vec_free (um->ueip_export.host_if_name);
      vec_free (um->ueip_export.host_ns_name);

      if (um->ueip_export.nl_sock != NULL)
        nl_socket_free (um->ueip_export.nl_sock);

      mhash_free (&um->ueip_export.added_ips);
    }

  return rv;
}

static void
upf_ueip_export_add_del_ueip_hook (const ip46_address_t *ip, bool is_add)
{
  upf_main_t *um = &upf_main;

  struct rtnl_route *route = NULL;
  struct nl_addr *dst = NULL;
  struct rtnl_nexthop *nh = NULL;
  int err;

  if (!um->ueip_export.enabled)
    return;

  if (ip46_address_is_ip4 (ip))
    dst = nl_addr_build (AF_INET, ip->ip4.as_u8, 4);
  else
    dst = nl_addr_build (AF_INET6, ip->ip6.as_u8, 8); // ip/64 prefix

  u32 *refcnt = (u32 *) mhash_get (&um->ueip_export.added_ips, ip);
  if (is_add)
    {
      if (refcnt)
        {
          // refcount if already added
          ASSERT (*refcnt);
          *refcnt += 1;
          goto out;
        }
      mhash_set (&um->ueip_export.added_ips, (void *) ip, 1, NULL);
    }
  else
    {
      if (!refcnt)
        {
          // shouldn't happen, already removed
          ASSERT (0 && "Export address already removed");
          vlib_log_err (um->log_class, "export address %U already removed",
                        format_ip46_address, ip, IP46_TYPE_ANY);
          goto out;
        }

      ASSERT (*refcnt);
      if ((*refcnt = *refcnt - 1))
        goto out;

      mhash_unset (&um->ueip_export.added_ips, (void *) ip, NULL);
    }

  // Allocate memory for the route
  route = rtnl_route_alloc ();
  if (!route)
    {
      upf_debug ("Failed to allocate route structure.");
      goto out;
    }

  // Set the destination address on the route
  rtnl_route_set_dst (route, dst);

  // Create a nexthop
  nh = rtnl_route_nh_alloc ();
  if (!nh)
    {
      upf_debug ("Failed to allocate nexthop.");
      goto out;
    }

  rtnl_route_nh_set_ifindex (nh, um->ueip_export.host_if_index);
  rtnl_route_add_nexthop (route, nh); // transfer nh ownership
  rtnl_route_set_table (route, um->ueip_export.host_table_id);

  // Add the route
  if (is_add)
    err = rtnl_route_add (um->ueip_export.nl_sock, route, NLM_F_CREATE);
  else
    err = rtnl_route_delete (um->ueip_export.nl_sock, route, NLM_F_CREATE);

  if (err < 0)
    upf_debug ("Failed to %s route ip: %U err: %s", is_add ? "add" : "del",
               format_ip46_address, ip, IP46_TYPE_ANY, nl_geterror (err));
  else
    upf_debug ("%s route ip: %U", is_add ? "add" : "del", format_ip46_address,
               ip, IP46_TYPE_ANY);

out:
  if (route)
    rtnl_route_put (route);
  if (dst)
    nl_addr_put (dst);
}

void
upf_ueip_export_add_ueip_hook (const ip46_address_t *ip)
{
  upf_ueip_export_add_del_ueip_hook (ip, true);
}

void
upf_ueip_export_del_ueip_hook (const ip46_address_t *ip)
{
  upf_ueip_export_add_del_ueip_hook (ip, false);
}

static clib_error_t *
upf_ueip_export_enable_disable_command_fn (vlib_main_t *vm,
                                           unformat_input_t *main_input,
                                           vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *ns_path = 0;
  u8 *if_name = 0;
  u32 table_id = 0;
  int is_enable = 1;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
        is_enable = 1;
      else if (unformat (line_input, "disable"))
        is_enable = 0;
      else if (unformat (line_input, "ns-path %_%v%_", &ns_path))
        ;
      else if (unformat (line_input, "table %u", &table_id))
        ;
      else if (unformat (line_input, "if-name %_%v%_", &if_name))
        ;
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }

  vnet_api_error_t rv =
    upf_ueip_export_enable_disable (is_enable, table_id, if_name, ns_path);

  if (rv)
    switch (rv)
      {
      case VNET_API_ERROR_VALUE_EXIST:
        error = clib_error_return (0, "UEIP Export already enabled...");
        break;
      case VNET_API_ERROR_INVALID_VALUE:
        error = clib_error_return (0, "Argument error...");
        break;
      case VNET_API_ERROR_SYSCALL_ERROR_1:
        error = clib_error_return (0, "Failed to open target ns...");
        break;
      case VNET_API_ERROR_SYSCALL_ERROR_2:
        error = clib_error_return (0, "Failed to open vpp ns...");
        break;
      case VNET_API_ERROR_SYSCALL_ERROR_3:
        error = clib_error_return (0, "Failed to change ns...");
        break;
      case VNET_API_ERROR_INVALID_INTERFACE:
        error = clib_error_return (0, "Failed to get interface index...");
        break;
      case VNET_API_ERROR_NETLINK_ERROR:
        error = clib_error_return (0, "Failed to connect to netlink...");
        break;
      default:
        error = clib_error_return (0, "upf_ueip_export_enable_disable %U",
                                   format_vnet_api_errno, rv);
        break;
      }

done:
  vec_free (ns_path);
  vec_free (if_name);
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (upf_ueip_export_enable_disable_command, static) = {
  .path = "upf ueip export as-ns-route",
  .short_help = "upf ueip export as-ns-route "
                "[enable|disable] ns-path <path> "
                "table <table> if-name <name>",
  .function = upf_ueip_export_enable_disable_command_fn,
};

static clib_error_t *
show_upf_ueip_export_command_fn (vlib_main_t *vm, unformat_input_t *main_input,
                                 vlib_cli_command_t *cmd)
{
  upf_main_t *um = &upf_main;

  vlib_cli_output (vm, "UEIP export as-ns-route status: %s\n",
                   um->ueip_export.enabled ? "enabled" : "disabled");

  if (!um->ueip_export.enabled)
    return 0;

  vlib_cli_output (vm, "  Network namespace: %v\n",
                   um->ueip_export.host_ns_name);
  vlib_cli_output (vm, "  Interface: %v (id %d)\n",
                   um->ueip_export.host_if_name,
                   um->ueip_export.host_if_index);
  vlib_cli_output (vm, "  Table: %d\n", um->ueip_export.host_table_id);
  vlib_cli_output (vm, "  Routes added: %d\n",
                   mhash_elts (&um->ueip_export.added_ips));

  return 0;
}

VLIB_CLI_COMMAND (show_upf_ueip_export_command, static) = {
  .path = "show upf ueip export as-ns-route",
  .short_help = "show upf ueip export as-ns-route",
  .function = show_upf_ueip_export_command_fn,
  .is_mp_safe = 1,
};
