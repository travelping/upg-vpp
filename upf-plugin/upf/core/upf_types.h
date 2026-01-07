/*
 * Copyright (c) 2025 Travelping GmbH
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

#ifndef UPF_CORE_UPF_TYPES_H_
#define UPF_CORE_UPF_TYPES_H_

#include <vppinfra/format.h>

#include "upf/utils/common.h"

typedef struct __key_packed
{
  u8 tbcd[8];
} upf_imsi_t;

// Direction of traffic.
// It is often convenient for systems to use UL/DL directions, so it is
// recommended to convert data to it as soon as possible.
typedef enum : u8
{
  UPF_DIR_UL = 0, // Uplink direction. From UE to Remote.
  UPF_DIR_DL = 1, // Downlink direction. From Remote to UE.
  UPF_N_DIR = 2,
} __clib_packed upf_dir_t;

// Helpers to select proper field from array like IP or Port.
typedef enum : u8
{
  UPF_EL_UE = 0,              // Select UE field
  UPF_EL_RMT = 1,             // Select Remote (or Internet) field
  UPF_EL_UL_SRC = UPF_EL_UE,  // Select uplink SRC field (UE)
  UPF_EL_UL_DST = UPF_EL_RMT, // Select uplink DST field (Remote)
  UPF_EL_DL_SRC = UPF_EL_RMT, // Select downlink SRC field (Remote)
  UPF_EL_DL_DST = UPF_EL_UE,  // Select downlink DST field (UE)
  UPF_N_EL = 2,
} __clib_packed upf_el_t;

// Intended to be XORed with upf_dir_t or upf_el_t.
typedef enum : u8
{
  UPF_DIR_OP_SAME = 0, // Original direction/field
  UPF_DIR_OP_FLIP = 1, // Reversed direction/field
} __clib_packed upf_dir_op_t;

typedef enum : u8
{
  UPF_PACKET_SOURCE_GTPU = 0,
  UPF_PACKET_SOURCE_IP = 1,
  UPF_PACKET_SOURCE_NAT = 2,
  UPF_PACKET_SOURCE_TCP_STACK = 3,
} upf_packet_source_t;

unformat_function_t unformat_upf_imsi_key;

#endif // UPF_CORE_UPF_TYPES_H_
