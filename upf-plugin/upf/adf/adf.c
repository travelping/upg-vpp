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

#include <hs/hs_compile.h>

#include <vlib/vlib.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>

#include "upf/upf.h"
#include "upf/adf/adf.h"
#include "upf/adf/matcher.h"

#define UPF_DEBUG_ENABLE 0

static clib_error_t *
_upf_adf_app_compile_rules (upf_adf_app_t *app, upf_adf_app_version_t *ver)
{
  hs_compile_error_t *compile_err = NULL;
  clib_error_t *error = NULL;
  u32 index = 0;
  u32 rule_index = 0;
  upf_adf_rule_t *rule = NULL;

  ver->fib_index_ip4 = ~0;
  ver->fib_index_ip6 = ~0;

  /* clang-format off */
  hash_foreach(rule_index, index, ver->rules_by_id,
    ({
       rule = pool_elt_at_index(ver->rules, index);

       if (rule->regex)
       {
         u8* regex = vec_dup(rule->regex);

         vec_add1(ver->regexp_expressions, regex);
         vec_add1(ver->hs_flags, HS_FLAG_SINGLEMATCH);
         vec_add1(ver->rule_ids, rule->id);
       }
       else
       {
         vec_add1(ver->acl, rule->acl_rule);
       }
    }));
  /* clang-format on */

  ASSERT (!ver->database);

  if ((error = upf_adf_ip_matcher_prepare (ver)))
    return clib_error_return (error, "rules prepare");

  if (vec_len (ver->regexp_expressions) == 0)
    return 0;

  if (hs_compile_multi ((const char **) ver->regexp_expressions, ver->hs_flags,
                        ver->rule_ids, vec_len (ver->regexp_expressions),
                        HS_MODE_BLOCK, NULL, &ver->database,
                        &compile_err) != HS_SUCCESS)
    {
      error = clib_error_return (0, "error compiling regex: %s",
                                 compile_err->message);
      hs_free_compile_error (compile_err);
      return error;
    }

  hs_error_t alloc_rv = hs_alloc_scratch (ver->database, &ver->scratch);
  if (alloc_rv != HS_SUCCESS)
    {
      hs_free_database (ver->database);
      ver->database = NULL;
      return clib_error_return (0, "hs_alloc_scratch failed: %d", alloc_rv);
    }

  return 0;
}

void
upf_adf_init (void)
{
  upf_adf_main_t *am = &upf_main.adf_main;
  memset (am, 0, sizeof (*am));

  am->app_index_by_name = hash_create_vec (0, sizeof (u8), sizeof (uword));
}

vnet_api_error_t
upf_adf_app_create (u8 *name)
{
  upf_adf_main_t *am = &upf_main.adf_main;

  if (upf_adf_app_get_by_name (name))
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

  // create app
  upf_adf_app_t *app;

  vlib_worker_thread_barrier_sync (vlib_get_main ());

  pool_get (am->apps, app);
  memset (app, 0, sizeof (*app));

  app->id = am->next_app_id++;
  app->name = vec_dup (name);

  app->active_ver_idx = ~0;
  app->uncommited_ver_idx = ~0;

  hash_set_mem (am->app_index_by_name, app->name, app - am->apps);

  vlib_worker_thread_barrier_release (vlib_get_main ());

  return 0;
}

static void
_upf_adf_version_free (upf_adf_app_t *app, upf_adf_app_version_t *ver)
{
  hash_free (ver->rules_by_id);
  pool_free (ver->rules);

  u8 **regex = NULL;
  vec_foreach (regex, ver->regexp_expressions)
    {
      vec_free (*regex);
    }
  vec_free (ver->regexp_expressions);

  vec_free (ver->hs_flags);
  vec_free (ver->rule_ids);

  if (ver->database)
    hs_free_database (ver->database);

  hs_free_scratch (ver->scratch);

  /* free vector of APP DPOs */
  if (ver->app_dpos)
    {
      upf_app_dpo_t *app_dpo;

      vec_foreach (app_dpo, ver->app_dpos)
        {
          ipfilter_rule_t *rule =
            vec_elt_at_index (ver->acl, app_dpo->rule_index);
          fib_prefix_t pfx;

          ip46_address_copy (&pfx.fp_addr, &rule->address_rmt);
          pfx.fp_proto = app_dpo->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
          pfx.fp_len = app_dpo->src_preflen;

          fib_table_entry_special_remove (
            app_dpo->is_ip4 ? ver->fib_index_ip4 : ver->fib_index_ip6, &pfx,
            FIB_SOURCE_SPECIAL);
        }

      ip4_fib_table_destroy (ver->fib_index_ip4);
      ip6_fib_table_destroy (ver->fib_index_ip6);

      ver->fib_index_ip4 = ~0;
      ver->fib_index_ip6 = ~0;

      vec_free (ver->app_dpos);
    }

  vec_free (ver->acl);

  memset (ver, 0, sizeof (upf_adf_app_version_t));
}

static void
_upf_adf_app_try_cleanup_old_versions (upf_adf_app_t *app)
{
  upf_adf_main_t *am = &upf_main.adf_main;

  u32 ver_id;
  u32 ver_idx;

  u32 *remove_list = vec_new (u32, 0);

  /* clang-format off */
  hash_foreach(ver_id, ver_idx, app->version_idx_by_id,
    ({
      if (ver_idx != app->active_ver_idx && ver_idx != app->uncommited_ver_idx)
          vec_add1(remove_list, ver_idx);
    }));
  /* clang-format on */

  u32 *remove_idx;
  vec_foreach (remove_idx, remove_list)
    {
      upf_adf_app_version_t *ver =
        pool_elt_at_index (am->versions, *remove_idx);
      hash_unset (app->version_idx_by_id, ver->uid);
      _upf_adf_version_free (app, ver);
      pool_put (am->versions, ver);
    }
}

vnet_api_error_t
upf_adf_app_version_create (upf_adf_app_t *app, u32 *result_ver_id)
{
  upf_adf_main_t *am = &upf_main.adf_main;

  // only one version at a time
  if (is_valid_id (app->uncommited_ver_idx))
    return VNET_API_ERROR_INVALID_REGISTRATION;

  // create version
  upf_adf_app_version_t *ver;
  pool_get (am->versions, ver);
  memset (ver, 0, sizeof (*ver));

  ver->app_index = app - am->apps;
  ver->uid = app->next_version_uid++;
  ver->rules_by_id = hash_create (0, sizeof (uword));

  app->uncommited_ver_idx = ver - am->versions;

  hash_set (app->version_idx_by_id, ver->uid, ver - am->versions);

  // versions also hold apps
  app->ref_versions_count += 1;

  _upf_adf_app_try_cleanup_old_versions (app);

  if (result_ver_id)
    *result_ver_id = ver->uid;

  return 0;
}

vnet_api_error_t
upf_adf_commit_version (upf_adf_app_t *app)
{
  upf_adf_main_t *am = &upf_main.adf_main;

  if (!is_valid_id (app->uncommited_ver_idx))
    return VNET_API_ERROR_INVALID_REGISTRATION;

  upf_adf_app_version_t *ver =
    pool_elt_at_index (am->versions, app->uncommited_ver_idx);

  vlib_worker_thread_barrier_sync (vlib_get_main ());

  ver->is_commited = 1;
  app->active_ver_idx = app->uncommited_ver_idx;
  app->uncommited_ver_idx = ~0;

  clib_error_t *error = _upf_adf_app_compile_rules (app, ver);
  vlib_worker_thread_barrier_release (vlib_get_main ());

  if (error)
    {
      clib_warning ("error: %U", format_clib_error, error);
      clib_error_free (error);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  return 0;
}

vnet_api_error_t
upf_adf_drop_uncommited_version (upf_adf_app_t *app)
{
  if (!is_valid_id (app->uncommited_ver_idx))
    return VNET_API_ERROR_INVALID_REGISTRATION;

  app->uncommited_ver_idx = ~0;

  _upf_adf_app_try_cleanup_old_versions (app);

  return 0;
}

typedef struct
{
  int res;
  u32 id;
} upf_adf_cb_args_t;

static int
_upf_adf_event_handler (unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx)
{
  (void) from;
  (void) to;
  (void) flags;

  upf_adf_cb_args_t *args = (upf_adf_cb_args_t *) ctx;

  args->res = 1;
  args->id = id;

  return 0;
}

bool
upf_adf_app_match_regex (upf_adf_app_t *app, u8 *str, uint16_t length, u32 *id)
{
  upf_adf_main_t *am = &upf_main.adf_main;

  int ret = 0;
  upf_adf_cb_args_t args = {};

  upf_adf_app_version_t *ver =
    pool_elt_at_index (am->versions, app->active_ver_idx);

  if (!ver->database)
    return false;

  ret = hs_scan (ver->database, (const char *) str, length, 0, ver->scratch,
                 _upf_adf_event_handler, (void *) &args);
  if (ret != HS_SUCCESS)
    return false;

  if (args.res == 0)
    return false;

  if (id)
    *id = args.id;

  return true;
}

static vnet_api_error_t
_upf_adf_app_rule_new (upf_adf_app_t *app, upf_adf_rule_t **result_rule)
{
  upf_adf_main_t *am = &upf_main.adf_main;

  if (!is_valid_id (app->uncommited_ver_idx))
    return VNET_API_ERROR_INVALID_REGISTRATION;

  upf_adf_app_version_t *ver =
    pool_elt_at_index (am->versions, app->uncommited_ver_idx);

  u32 rule_id = ver->next_rule_id++;

  upf_adf_rule_t *rule = NULL;
  pool_get (ver->rules, rule);
  memset (rule, 0, sizeof (*rule));
  rule->id = rule_id;

  hash_set (ver->rules_by_id, rule_id, rule - ver->rules);

  *result_rule = rule;
  return 0;
}

vnet_api_error_t
upf_adf_app_rule_create_by_regexp (upf_adf_app_t *app, u8 *regex)
{
  upf_adf_rule_t *rule;
  vnet_api_error_t r = _upf_adf_app_rule_new (app, &rule);
  if (r)
    return r;

  rule->regex = vec_dup (regex);
  vec_terminate_c_string (rule->regex);
  return 0;
}

vnet_api_error_t
upf_adf_app_rule_create_by_acl (upf_adf_app_t *app, ipfilter_rule_t *acl_rule)
{
  upf_adf_rule_t *rule;
  vnet_api_error_t r = _upf_adf_app_rule_new (app, &rule);
  if (r)
    return r;

  rule->acl_rule = *acl_rule;
  return 0;
}

upf_adf_app_t *
upf_adf_app_get_by_name (u8 *app_name)
{
  upf_adf_main_t *am = &upf_main.adf_main;
  uword *p = hash_get (am->app_index_by_name, app_name);
  if (!p)
    return NULL;

  return pool_elt_at_index (am->apps, p[0]);
}

upf_adf_app_version_t *
upf_adf_get_app_version (upf_adf_app_t *app, u32 version_id)
{
  upf_adf_main_t *am = &upf_main.adf_main;

  uword *p = hash_get (app->version_idx_by_id, version_id);
  if (!p)
    return NULL;

  return pool_elt_at_index (am->versions, p[0]);
}
