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

#include <vlib/vlib.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vppinfra/vec_bootstrap.h>

#include "upf/upf.h"
#include "upf/rules/upf_ipfilter.h"
#include "upf/adf/adf.h"

static clib_error_t *
adf_cli_create_application_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;

  u8 *app_name = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %_%v%_", &app_name))
        ;
      else if (unformat (line_input, "proxy"))
        clib_warning ("deprecated adf argument 'proxy'");
      else
        {
          error = unformat_parse_error (line_input);
          goto cleanup;
        }
    }

  if (!app_name)
    {
      error = clib_error_return (0, "name is required...");
      goto cleanup;
    }

  vnet_api_error_t rv = upf_adf_app_create (app_name);
  if (rv != 0)
    {
      error = clib_error_return (0, "upf_adf_app_create returned %U",
                                 format_vnet_api_errno, rv);
      goto cleanup;
    }

cleanup:
  vec_free (app_name);
  unformat_free (line_input);
  return error;
}

static clib_error_t *
adf_cli_delete_application_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;

  u8 *app_name = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %_%v%_", &app_name))
        ;
      else
        {
          error = unformat_parse_error (line_input);
          goto cleanup;
        }
    }

  if (!app_name)
    {
      error = clib_error_return (0, "name is required...");
      goto cleanup;
    }

  vlib_cli_output (vm, "Unimplemented");

cleanup:
  vec_free (app_name);
  unformat_free (line_input);
  return error;
}

static clib_error_t *
adf_cli_create_app_version_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;

  u8 *app_name = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "app %_%v%_", &app_name))
        ;
      else
        {
          error = unformat_parse_error (line_input);
          goto cleanup;
        }
    }

  if (!app_name)
    {
      error = clib_error_return (0, "name is required...");
      goto cleanup;
    }

  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);
  if (!app)
    {
      error = clib_error_return (0, "No app with name %v", app_name);
      goto cleanup;
    }

  u32 new_ver_id;
  vnet_api_error_t rv = upf_adf_app_version_create (app, &new_ver_id);
  if (rv != 0)
    {
      error = clib_error_return (0, "upf_adf_app_version_create returned %U",
                                 format_vnet_api_errno, rv);
      goto cleanup;
    }

  vlib_cli_output (vm, "New version id: %u", new_ver_id);

cleanup:
  vec_free (app_name);
  unformat_free (line_input);
  return error;
}

static clib_error_t *
adf_cli_add_application_rule_fn (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  clib_error_t *error = NULL;

  u8 *app_name = 0;
  u8 *regex = NULL;
  bool has_rule = false;
  ipfilter_rule_t rule = {};

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "app %_%v%_", &app_name))
        ;
      else if (unformat (line_input, "l7 regex %_%s%_", &regex))
        ;
      else if (unformat (line_input, "ipfilter %_%U%_", unformat_upf_ipfilter,
                         &rule))
        has_rule = true;
      else
        {
          error = unformat_parse_error (line_input);
          goto cleanup;
        }
    }

  if (!app_name)
    {
      error = clib_error_return (0, "name is required...");
      goto cleanup;
    }

  if (vec_len (regex) && has_rule)
    {
      error = clib_error_return (0, "please provide only regexp or ACL rule");
      goto cleanup;
    }

  if (!vec_len (regex) && !has_rule)
    {
      error = clib_error_return (0, "please provide regexp or ACL rule");
      goto cleanup;
    }

  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);
  if (!app)
    {
      error = clib_error_return (0, "No app with name %v", app_name);
      goto cleanup;
    }

  vnet_api_error_t rv;
  if (has_rule)
    rv = upf_adf_app_rule_create_by_acl (app, &rule);
  else
    rv = upf_adf_app_rule_create_by_regexp (app, regex);

  if (rv)
    {
      error = clib_error_return (0, "upf_adf_create_app_rule returned %U",
                                 format_vnet_api_errno, rv);
      goto cleanup;
    }

cleanup:
  vec_free (regex);
  vec_free (app_name);
  unformat_free (line_input);
  return error;
}

static clib_error_t *
adf_cli_commit_version_fn (vlib_main_t *vm, unformat_input_t *input,
                           vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  clib_error_t *error = NULL;

  u8 *app_name = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "app %_%v%_", &app_name))
        ;
      else
        {
          error = unformat_parse_error (line_input);
          goto cleanup;
        }
    }

  if (!app_name)
    {
      error = clib_error_return (0, "name is required...");
      goto cleanup;
    }

  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);
  if (!app)
    {
      error = clib_error_return (0, "No app with name %v", app_name);
      goto cleanup;
    }

  vnet_api_error_t rv = upf_adf_commit_version (app);
  if (rv != 0)
    {
      error = clib_error_return (0, "upf_adf_commit_version returned %U",
                                 format_vnet_api_errno, rv);
      goto cleanup;
    }

cleanup:
  vec_free (app_name);
  unformat_free (line_input);
  return error;
}

static clib_error_t *
adf_cli_drop_version_fn (vlib_main_t *vm, unformat_input_t *input,
                         vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  clib_error_t *error = NULL;

  u8 *app_name = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "app %_%v%_", &app_name))
        ;
      else
        {
          error = unformat_parse_error (line_input);
          goto cleanup;
        }
    }

  if (!app_name)
    {
      error = clib_error_return (0, "name is required...");
      goto cleanup;
    }

  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);
  if (!app)
    {
      error = clib_error_return (0, "No app with name %v", app_name);
      goto cleanup;
    }

  u32 rv = upf_adf_drop_uncommited_version (app);

  switch (rv)
    {
    case 0:
      break;

    default:
      error = clib_error_return (0, "%s returned %d", __FUNCTION__, rv);
      break;
    }

cleanup:
  vec_free (app_name);
  unformat_free (line_input);
  return error;
}

static clib_error_t *
adf_cli_show_apps_fn (vlib_main_t *vm, unformat_input_t *input,
                      vlib_cli_command_t *cmd)
{
  upf_adf_main_t *am = &upf_main.adf_main;
  clib_error_t *error = NULL;

  vlib_cli_output (vm, "Applications:");

  upf_adf_app_t *app = NULL;
  vec_foreach (app, am->apps)
    {
      vlib_cli_output (
        vm,
        "Name: %v, in use by %d entities, active ver index = %d, "
        "uncommited ver index = %d",
        app->name, app->ref_count, app->active_ver_idx,
        app->uncommited_ver_idx);
    }

  return error;
}

static clib_error_t *
adf_cli_show_versions_fn (vlib_main_t *vm, unformat_input_t *input,
                          vlib_cli_command_t *cmd)
{
  upf_adf_main_t *am = &upf_main.adf_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;

  u8 *app_name = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "app %_%v%_", &app_name))
        ;
      else
        {
          error = unformat_parse_error (line_input);
          goto cleanup;
        }
    }

  if (!app_name)
    {
      error = clib_error_return (0, "name is required...");
      goto cleanup;
    }

  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);

  if (!app)
    {
      error = clib_error_return (0, "app not found...");
      goto cleanup;
    }

  vlib_cli_output (vm, "Versions for application %v:", app_name);

  upf_adf_app_version_t *ver = NULL;
  pool_foreach (ver, am->versions)
    {
      if (ver->app_index == app - am->apps)
        {
          vlib_cli_output (
            vm, "id %d, commited: %d, num ip rules: %d, num l7 rules: %d %s",
            ver->uid, ver->is_commited, vec_len (ver->acl),
            vec_len (ver->regexp_expressions),
            app->active_ver_idx == ver - am->versions ? "(active)" : "");
        }
    }

cleanup:
  vec_free (app_name);
  unformat_free (line_input);
  return error;
}

static clib_error_t *
adf_cli_show_version_fn (vlib_main_t *vm, unformat_input_t *input,
                         vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;

  u8 *app_name = 0;
  u32 ver_id = ~0;
  bool show_active = false, show_uncommited = false;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "app %_%v%_", &app_name))
        ;
      else if (unformat (line_input, "ver %u", &ver_id))
        ;
      else if (unformat (line_input, "active"))
        show_active = true;
      else if (unformat (line_input, "uncommited"))
        show_uncommited = true;
      else
        {
          error = unformat_parse_error (line_input);
          goto cleanup;
        }
    }

  if (!vec_len (app_name))
    {
      error = clib_error_return (0, "app name is required...");
      goto cleanup;
    }

  upf_adf_app_t *app = upf_adf_app_get_by_name (app_name);
  if (!app)
    {
      error = clib_error_return (0, "app not found...");
      goto cleanup;
    }

  upf_adf_app_version_t *ver = NULL;
  if (show_active)
    {
      if (!is_valid_id (app->active_ver_idx))
        {
          error = clib_error_return (0, "no active version exists...");
          goto cleanup;
        }
      ver =
        pool_elt_at_index (upf_main.adf_main.versions, app->active_ver_idx);
    }
  else if (show_uncommited)
    {
      if (!is_valid_id (app->uncommited_ver_idx))
        {
          error = clib_error_return (0, "no uncommited version exists...");
          goto cleanup;
        }
      ver = pool_elt_at_index (upf_main.adf_main.versions,
                               app->uncommited_ver_idx);
    }
  else
    {
      if (!is_valid_id (ver_id))
        {
          error = clib_error_return (0, "version is required...");
          goto cleanup;
        }

      ver = upf_adf_app_version_get (app, ver_id);
    }

  if (!ver)
    {
      error = clib_error_return (0, "version not found...");
      goto cleanup;
    }

  vlib_cli_output (vm,
                   "Application %v version %u rules (total %d):", app->name,
                   ver->uid, pool_elts (ver->rules));

  upf_adf_rule_t *rule = NULL;
  pool_foreach (rule, ver->rules)
    {
      if (rule->regex)
        vlib_cli_output (vm, " L7 rule: %s", rule->regex);
      else
        vlib_cli_output (vm, " IP rule: %U", format_upf_ipfilter,
                         &rule->acl_rule);
    }

cleanup:
  vec_free (app_name);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (adf_cli_create_application, static) = {
  .path = "adf create application",
  .short_help = "adf create application name <app_name> [proxy]",
  .function = adf_cli_create_application_fn,
};

VLIB_CLI_COMMAND (adf_cli_delete_application, static) = {
  .path = "adf delete application",
  .short_help = "adf delete application name <app_name>",
  .function = adf_cli_delete_application_fn,
};

VLIB_CLI_COMMAND (adf_cli_create_app_version, static) = {
  .path = "adf create version",
  .short_help = "adf create version app <name>",
  .function = adf_cli_create_app_version_fn,
};

VLIB_CLI_COMMAND (adf_add_application_rule, static) = {
  .path = "adf create rule",
  .short_help = "adf create rule app <name> "
                "[l7 regex <regex> | ipfilter <ipfilter>]",
  .function = adf_cli_add_application_rule_fn,
};

VLIB_CLI_COMMAND (adf_cli_commit_version, static) = {
  .path = "adf version commit",
  .short_help = "adf version commmit app <name> ",
  .function = adf_cli_commit_version_fn,
};

VLIB_CLI_COMMAND (adf_cli_drop_version, static) = {
  .path = "adf version drop",
  .short_help = "adf version drop app <name>",
  .function = adf_cli_drop_version_fn,
};

VLIB_CLI_COMMAND (adf_cli_show_apps, static) = {
  .path = "show adf apps",
  .short_help = "Show summary of apps",
  .function = adf_cli_show_apps_fn,
  .is_mp_safe = 1,
};

VLIB_CLI_COMMAND (adf_cli_show_versions, static) = {
  .path = "show adf versions",
  .short_help = "show adf versions app <name>",
  .function = adf_cli_show_versions_fn,
  .is_mp_safe = 1,
};

VLIB_CLI_COMMAND (adf_cli_show_version, static) = {
  .path = "show adf version",
  .short_help = "show adf version app <name>"
                " [ver <ver_id> | active | uncommited]",
  .function = adf_cli_show_version_fn,
  .is_mp_safe = 1,
};
