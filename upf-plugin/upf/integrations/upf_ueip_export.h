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

#ifndef UPF_INTEGRATIONS_UPF_UEIP_EXPORT_H_
#define UPF_INTEGRATIONS_UPF_UEIP_EXPORT_H_

#include <vppinfra/types.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip46_address.h>

/**
 * @brief Enable or disable the UEIP export feature.
 *
 * When enabled, the UPF will export the ueip to the kernel table
 * as a fake route to the specified interface.
 *
 * @param enable Enable or disable the feature.
 * @param table_id The kernel table ID.
 * @param if_name The interface name.
 * @param ns_filename The network namespace file path.
 */
vnet_api_error_t upf_ueip_export_enable_disable (bool enable, u32 table_id,
                                                 u8 *if_name, u8 *ns_filename);
void upf_ueip_export_add_ueip_hook (const ip46_address_t *ip);
void upf_ueip_export_del_ueip_hook (const ip46_address_t *ip);

#endif // UPF_INTEGRATIONS_UPF_UEIP_EXPORT_H_
