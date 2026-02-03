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

#ifndef UPF_INTEGRATIONS_UPF_NETCAP_H_
#define UPF_INTEGRATIONS_UPF_NETCAP_H_

#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/api_errno.h>

#include "upf/core/upf_types.h"
#include "upf/utils/llist.h"

/* captures for imsi */
UPF_LLIST_TEMPLATE_TYPES (upf_imsi_capture_list);

typedef struct
{
  u8 *target;
  u8 *tag;
  u16 packet_max_bytes;

  upf_imsi_capture_list_anchor_t imsi_list_anchor;
} upf_imsi_capture_t;

typedef u16 upf_imsi_capture_list_id_t;
typedef u32 upf_imsi_capture_id_t;

UPF_LLIST_TEMPLATE_DEFINITIONS (upf_imsi_capture_list, upf_imsi_capture_t,
                                imsi_list_anchor);

unformat_function_t unformat_upf_imsi_key;

clib_error_t *upf_imsi_netcap_enable_disable (upf_imsi_t imsi, u8 *target,
                                              u8 *tag, u16 packet_max_bytes,
                                              bool enable);

#endif // UPF_INTEGRATIONS_UPF_NETCAP_H_
