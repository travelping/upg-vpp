/*
 * Copyright (c) 2018-2025 Travelping GmbH
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

#include <vppinfra/types.h>
#include <vppinfra/format.h>
#include <vppinfra/crc32.h>

#include "upf/rules/upf_ipfilter.h"

static uword
_unformat_ipfilter_address_port (unformat_input_t *i, ipfilter_rule_t *acl,
                                 upf_el_t field)
{
  ip46_address_t *ip = &acl->addresses[field];
  ipfilter_port_t *port = &acl->ports[field];

  port->min = 0;
  port->max = ~0;

  if (unformat_is_eof (i))
    return 0;

  if (unformat (i, "any"))
    {
      if (field == UPF_EL_UE)
        acl->is_ue_any = 1;
      else
        acl->is_rmt_any = 1;

      acl->addresses[field] = (ip46_address_t) ip46_address_initializer;
      acl->masks[field] = 0;
    }
  else if (unformat (i, "assigned"))
    {
      if (field == UPF_EL_UE)
        acl->is_ue_assigned = 1;
      else
        // Do not allow remote assigned field
        // Require assigned to be source only
        return 0;
    }
  else if (unformat (i, "%U", unformat_ip46_address, ip, IP46_TYPE_ANY))
    {
      bool is_ip4 = ip46_address_is_ip4 (ip);

      // do not allow to mix ip versions
      if ((acl->is_ip6 && is_ip4) || (acl->is_ip4 && !is_ip4))
        return 0;

      if (is_ip4)
        acl->is_ip4 = 1;
      else
        acl->is_ip6 = 1;

      acl->masks[field] = is_ip4 ? 32 : 128;
      u32 _mask = 0;

      if (unformat_is_eof (i))
        return 1;

      if (unformat (i, "/%u", &_mask))
        acl->masks[field] = (u8) _mask;
    }
  else
    return 0;

  if (unformat_is_eof (i))
    return 1;

  u32 _port_min, _port_max;
  if (unformat (i, "%u-%u", &_port_min, &_port_max))
    {
      port->min = (u16) _port_min;
      port->max = (u16) _port_max;
    }
  else if (unformat (i, "%u", &_port_min))
    {
      port->min = (u16) _port_min;
      port->max = (u16) _port_min;
    }

  return 1;
}

uword
unformat_upf_ipfilter (unformat_input_t *i, va_list *args)
{
  ipfilter_rule_t *acl = va_arg (*args, ipfilter_rule_t *);

  // Examples:
  // permit out ip from any to assigned
  // permit out 6 from 192.168.0.0/16 80 to assigned

  // zero memory, since it is used as hashmap key
  memset (acl, 0, sizeof (*acl));
  // explicitly set defaults
  acl->is_ip4 = 0;
  acl->is_ip6 = 0;
  acl->is_ue_any = 0;
  acl->is_rmt_any = 0;
  acl->is_ue_assigned = 0;
  acl->action_deny = 0;
  acl->direction_in = 0;

  acl->proto = ~0;

  // parse action
  if (unformat (i, "permit"))
    ;
  else if (unformat (i, "deny"))
    // not allowed by 29.212 cause 5.4.2, but here we are more flexible
    acl->action_deny = 1;
  else
    return 0;

  // From TS 29.214 cause 5.3.8:
  // > Direction (in or out). The direction "in" refers to uplink IP flows, and
  // > the direction "out" refers to downlink IP flows.
  // So string fields should map like:
  // | direction | source     | destination |
  // | out       | remote     | local (UE)  |
  // | in        | local (UE) | remote      |

  // parse direction
  if (unformat_is_eof (i))
    return 0;
  else if (unformat (i, "out"))
    ;
  else if (unformat (i, "in"))
    // not allowed by 29.212 cause 5.4.2, but here we are more flexible
    acl->direction_in = 1;
  else
    return 0;

  u32 proto;
  // parse proto
  if (unformat_is_eof (i))
    return 0;
  else if (unformat (i, "ip"))
    ;
  else if (unformat (i, "%u", &proto))
    {
      if (proto >= 255)
        return 0;

      acl->proto = proto;
    }
  else
    return 0;

  // parse addresses and ports
  if (unformat_is_eof (i))
    return 0;
  else if (unformat (i, "from"))
    ;
  else
    return 0;

  if (!_unformat_ipfilter_address_port (
        i, acl, acl->direction_in ? UPF_EL_UE : UPF_EL_RMT))
    return 0;

  if (unformat_is_eof (i))
    return 0;
  else if (unformat (i, "to"))
    ;
  else
    return 0;

  if (!_unformat_ipfilter_address_port (
        i, acl, acl->direction_in ? UPF_EL_RMT : UPF_EL_UE))
    return 0;

  return 1;
}

static u8 *
_format_ipfilter_address_port (u8 *s, ipfilter_rule_t *acl, int field)
{
  ip46_address_t *ip = &acl->addresses[field];
  ipfilter_port_t *port = &acl->ports[field];
  u8 mask = acl->masks[field];

  bool is_any = (field == UPF_EL_UE) ? acl->is_ue_any : acl->is_rmt_any;
  bool is_assigned = (field == UPF_EL_UE) ? acl->is_ue_assigned : false;

  if (is_any)
    s = format (s, "any");
  else if (is_assigned)
    s = format (s, "assigned");
  else
    {
      s = format (s, "%U", format_ip46_address, ip, IP46_TYPE_ANY);

      if (mask != (acl->is_ip4 ? 32 : 128))
        s = format (s, "/%u", mask);
    }

  if (port->min != 0 || port->max != (u16) ~0)
    {
      s = format (s, " %d", port->min);
      if (port->min != port->max)
        s = format (s, "-%d", port->max);
    }

  return s;
}

u8 *
format_upf_ipfilter (u8 *s, va_list *args)
{
  ipfilter_rule_t *acl = va_arg (*args, ipfilter_rule_t *);

  s = format (s, acl->action_deny ? "deny " : "permit ");
  s = format (s, acl->direction_in ? "in " : "out ");

  if (acl->proto == (u8) ~0)
    s = format (s, "ip");
  else
    s = format (s, "%d", acl->proto);

  s = format (s, " from ");
  s = _format_ipfilter_address_port (
    s, acl, acl->direction_in ? UPF_EL_UE : UPF_EL_RMT);

  s = format (s, " to ");
  s = _format_ipfilter_address_port (
    s, acl, acl->direction_in ? UPF_EL_RMT : UPF_EL_UE);

  return s;
}

static int
_upf_ipfilter_rule_vec_cmp (void *a1, void *a2)
{
  ipfilter_rule_t *r1 = a1, *r2 = a2;
  return memcmp (r1, r2, sizeof (ipfilter_rule_t));
}

void
upf_ipfilter_vec_sort (ipfilter_rule_t *rules)
{
  vec_sort_with_function (rules, _upf_ipfilter_rule_vec_cmp);
}
