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

#include "upf/nat/nat.h"
#include "upf/nat/nat_dpo.h"

dpo_type_t upf_nat_dpo_type;

void
upf_nat_dpo_create (u32 pool_index, dpo_id_t *dpo)
{
  dpo_set (dpo, upf_nat_dpo_type, DPO_PROTO_IP4, pool_index);
}

u8 *
format_upf_nat_dpo (u8 *s, va_list *args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  upf_nat_main_t *unm = &upf_nat_main;
  upf_nat_pool_t *pool = pool_elt_at_index (unm->nat_pools, index);
  return (format (s, "UPF NAT pool: %v", pool->name));
}

static void
upf_nat_dpo_lock (dpo_id_t *dpo)
{
}

static void
upf_nat_dpo_unlock (dpo_id_t *dpo)
{
}

const static dpo_vft_t upf_nat_dpo_vft = {
  .dv_lock = upf_nat_dpo_lock,
  .dv_unlock = upf_nat_dpo_unlock,
  .dv_format = format_upf_nat_dpo,
};

const static char *const upf_nat_ip4_nodes[] = {
  "upf-ip4-nat-dpo",
  NULL,
};

const static char *const upf_nat_ip6_nodes[] = {
  NULL,
};

const static char *const *const upf_nat_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = upf_nat_ip4_nodes,
  [DPO_PROTO_IP6] = upf_nat_ip6_nodes,
  [DPO_PROTO_MPLS] = NULL,
};

static clib_error_t *
upf_nat_dpo_module_init (vlib_main_t *vm)
{
  upf_nat_dpo_type =
    dpo_register_new_type (&upf_nat_dpo_vft, upf_nat_dpo_nodes);
  return (NULL);
}

VLIB_INIT_FUNCTION (upf_nat_dpo_module_init);
