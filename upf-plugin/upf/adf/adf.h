/*
 * Copyright (c) 2020-2025 Travelping GmbH
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

#ifndef UPF_ADF_ADF_H_
#define UPF_ADF_ADF_H_

#include <hs/hs_common.h>
#include <hs/hs_runtime.h>

#include <vnet/vnet.h>

#include "upf/rules/upf_ipfilter.h"

typedef struct
{
  u32 id;
  u8 *regex;
  ipfilter_rule_t acl_rule;
} upf_adf_rule_t;

typedef enum
{
  ADR_FAIL = 0,
  ADR_OK,
  ADR_NEED_MORE_DATA
} adf_result_t;

typedef struct
{
  u32 rule_index;     /* referenced ADR rule index */
  index_t next;       /* link to the next less specific ACL ref */
  index_t dpoi_index; /* DPO id */
  u8 src_preflen;     /* src prefix length */
  u8 is_ip4 : 1;
} upf_app_dpo_t;

// A snapshot of what the application should match on
typedef struct
{
  u32 app_index; /* index in app vec */
  u32 uid;       /* version increasing id, hashmap key */

  u8 is_commited : 1;

  u32 next_rule_id;
  uword *rules_by_id;      /* hash over rule ids */
  upf_adf_rule_t *rules;   /* pool */
  u8 **regexp_expressions; /* vec */
  ipfilter_rule_t *acl;    /* vec */
  u32 *hs_flags;           /* vec */
  u32 *rule_ids;           /* vec */
  hs_database_t *database;
  hs_scratch_t *scratch;
  u32 fib_index_ip4;       /* IP rule FIB table index (IP4) */
  u32 fib_index_ip6;       /* IP rule FIB table index (IP6) */
  upf_app_dpo_t *app_dpos; /* vector of APP DPOs */
} upf_adf_app_version_t;

// Management of ADF versions for application name
typedef struct
{
  u32 id;
  u8 *name;
  u32 ref_count;          /* how many sessions use this app */
  u32 ref_versions_count; /* how many versions of this app */

  // active version id protected by barrier, since used by workers
  u32 active_ver_idx; /* index of the latest active version */
  u32 uncommited_ver_idx;
  u32 next_version_uid;
  u32 *version_idx_by_id; /* hash map */
} upf_adf_app_t;

typedef struct
{
  upf_adf_app_t *apps;             /* pool */
  uword *app_index_by_name;        /* map */
  upf_adf_app_version_t *versions; /* pool */

  u32 next_app_id;
} upf_adf_main_t;

vnet_api_error_t upf_adf_app_create (u8 *name);
upf_adf_app_t *upf_adf_app_get_by_name (u8 *app_name);

vnet_api_error_t upf_adf_app_version_create (upf_adf_app_t *app,
                                             u32 *result_ver_id);
vnet_api_error_t upf_adf_app_rule_create_by_regexp (upf_adf_app_t *app,
                                                    u8 *regex);
vnet_api_error_t upf_adf_app_rule_create_by_acl (upf_adf_app_t *app,
                                                 ipfilter_rule_t *acl_rule);
upf_adf_app_version_t *upf_adf_app_version_get (upf_adf_app_t *app,
                                                u32 version_id);
vnet_api_error_t upf_adf_commit_version (upf_adf_app_t *app);
vnet_api_error_t upf_adf_drop_uncommited_version (upf_adf_app_t *app);

bool upf_adf_app_match_regex (upf_adf_app_t *app, u8 *str, uint16_t length,
                              u32 *id);

void upf_adf_init ();

adf_result_t upf_adf_dpi_extract_uri (u8 *p, u16 server_port, u8 **p_uri);

#endif // UPF_ADF_ADF_H_
