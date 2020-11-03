/*
 * Copyright(c) 2018 Travelping GmbH.
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

#include <vppinfra/types.h>
#include <vppinfra/format.h>

#include "upf_ipfilter.h"

static uword
unformat_ipfilter_address_port (unformat_input_t * i, va_list * args)
{
  acl_rule_t *acl = va_arg (*args, acl_rule_t *);
  int field = va_arg (*args, int);
  ipfilter_address_t *ip = &acl->address[field];
  ipfilter_port_t *port = &acl->port[field];
  int is_ip4;

  ip->mask = ~0;
  port->min = 0;
  port->max = ~0;

  if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
    return 0;

  if (unformat (i, "any"))
    {
      *ip = ACL_ADDR_ANY;
    }
  else if (unformat (i, "assigned"))
    {
      *ip = ACL_ADDR_ASSIGNED;
    }
  else if (unformat (i, "%U", unformat_ip46_address, &ip->address, IP46_TYPE_ANY))
    {
      is_ip4 = ip46_address_is_ip4 (&ip->address);
      acl->type = is_ip4 ? IPFILTER_IPV4 : IPFILTER_IPV6;
      ip->mask = is_ip4 ? 32 : 128;

      if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
	return 1;
      if (unformat (i, "/%d", &ip->mask))
	;
    }
  else
    return 0;

  if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
    return 1;
  if (unformat (i, "%d-%d", &port->min, &port->max))
    ;
  else if (unformat (i, "%d", &port->min))
    port->max = port->min;

  return 1;
}

uword
unformat_ipfilter (unformat_input_t * i, va_list * args)
{
  acl_rule_t * acl = va_arg (*args, acl_rule_t *);
  int step = 0;

  acl->type = IPFILTER_WILDCARD;

  /* action dir proto from src to dst [options] */
  while (step < 5 && unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      switch (step)
	{
	case 0:		/* action */
	  if (unformat (i, "permit"))
	    {
	      acl->action = ACL_PERMIT;
	    }
	  else if (unformat (i, "deny"))
	    {
	      acl->action = ACL_DENY;
	    }
	  else
	    return 0;

	  break;

	case 1:		/* dir */
	  if (unformat (i, "in"))
	    {
	      acl->direction = ACL_IN;
	    }
	  else if (unformat (i, "out"))
	    {
	      acl->direction = ACL_OUT;
	    }
	  else
	    return 0;

	  break;

	case 2:		/* proto */
	  if (unformat (i, "ip"))
	    {
	      acl->proto = ~0;
	    }
	  else if (unformat (i, "%u", &acl->proto))
	    ;
	  else
	    return 0;

	  break;

	case 3:		/* from src */
	  if (unformat (i, "from %U", unformat_ipfilter_address_port,
			acl, UPF_ACL_FIELD_SRC))
	    ;
	  else
	    return 0;

	  break;

	case 4:
	  if (unformat (i, "to %U", unformat_ipfilter_address_port,
			acl, UPF_ACL_FIELD_DST))
	    ;
	  else
	    return 0;

	  break;

	default:
	  return 0;
	}

      step++;
    }

  return 1;
}

static u8 *
format_ipfilter_address_port (u8 * s, va_list * args)
{
  acl_rule_t *acl = va_arg (*args, acl_rule_t *);
  int field = va_arg (*args, int);
  ipfilter_address_t *ip = &acl->address[field];
  ipfilter_port_t *port = &acl->port[field];

  if (acl_addr_is_any (ip))
    {
      s = format (s, "any");
    }
  else if (acl_addr_is_assigned (ip))
    {
      s = format (s, "assigned");
    }
  else
    {
      s = format (s, "%U", format_ip46_address, &ip->address, IP46_TYPE_ANY);
      if (ip->mask != (ip46_address_is_ip4 (&ip->address) ? 32 : 128))
	s = format (s, "/%u", ip->mask);
    }

  if (port->min != 0 || port->max != (u16) ~ 0)
    {
      s = format (s, " %d", port->min);
      if (port->min != port->max)
	s = format (s, "-%d", port->max);
    }

  return s;
}

u8 *
format_ipfilter (u8 * s, va_list * args)
{
  acl_rule_t *acl = va_arg (*args, acl_rule_t *);

  switch (acl->action)
    {
    case ACL_PERMIT:
      s = format (s, "permit ");
      break;

    case ACL_DENY:
      s = format (s, "deny ");
      break;

    default:
      s = format (s, "action_%d ", acl->action);
      break;
    }

  switch (acl->direction)
    {
    case ACL_IN:
      s = format (s, "in ");
      break;

    case ACL_OUT:
      s = format (s, "out ");
      break;

    default:
      s = format (s, "direction_%d ", acl->direction);
      break;
    }

  if (acl->proto == (u8) ~ 0)
    s = format (s, "ip ");
  else
    s = format (s, "%d ", acl->proto);

  s = format (s, "from %U ", format_ipfilter_address_port,
	      acl, UPF_ACL_FIELD_SRC);
  s =
    format (s, "to %U ", format_ipfilter_address_port,
	    acl, UPF_ACL_FIELD_DST);

  return s;
}
