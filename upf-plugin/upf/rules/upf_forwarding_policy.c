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

#include "upf/rules/upf_forwarding_policy.h"
#include "upf/upf.h"

static void
_upf_forwarding_policy_fib_lock (upf_forwarding_policy_t *fp)
{
  if (is_valid_id (fp->ip4_fib_id))
    fib_table_lock (fp->ip4_fib_id, FIB_PROTOCOL_IP4, FIB_SOURCE_API);
  if (is_valid_id (fp->ip6_fib_id))
    fib_table_lock (fp->ip6_fib_id, FIB_PROTOCOL_IP6, FIB_SOURCE_API);
}

static void
_upf_forwarding_policy_fib_unlock (upf_forwarding_policy_t *fp)
{
  if (is_valid_id (fp->ip4_fib_id))
    fib_table_unlock (fp->ip4_fib_id, FIB_PROTOCOL_IP4, FIB_SOURCE_API);
  if (is_valid_id (fp->ip6_fib_id))
    fib_table_unlock (fp->ip6_fib_id, FIB_PROTOCOL_IP6, FIB_SOURCE_API);
}

static void
_upf_forwarding_policy_free (upf_forwarding_policy_t *fp)
{
  upf_main_t *um = &upf_main;

  hash_unset_mem (um->forwarding_policy_by_id, fp->policy_id);
  vec_free (fp->policy_id);
  pool_put (um->forwarding_policies, fp);
}

u8 *
format_upf_forwarding_policy (u8 *s, va_list *args)
{
  upf_main_t *um = &upf_main;
  upf_forwarding_policy_t *fp = va_arg (*args, upf_forwarding_policy_t *);

  s = format (s, "id:%d %spolicy:%v ip4_fib:%d ip6_fib:%d refs:%d",
              fp - um->forwarding_policies, fp->is_removed ? "[deleted] " : "",
              fp->policy_id, fp->ip4_fib_id, fp->ip6_fib_id, fp->locks);

  return s;
}

upf_forwarding_policy_t *
upf_forwarding_policy_get_by_name (u8 *policy_id)
{
  upf_main_t *um = &upf_main;

  uword *hash_ptr = hash_get_mem (um->forwarding_policy_by_id, policy_id);
  if (!hash_ptr)
    return NULL;

  upf_forwarding_policy_t *fp =
    pool_elt_at_index (um->forwarding_policies, hash_ptr[0]);

  return fp->is_removed ? NULL : fp;
}

/*
 * upf policy actions
 * 0 - delete
 * 1 - add
 * 2 - update
 */
clib_error_t *
upf_forwarding_policy_add_del (u8 *policy_id, u32 ip4_table_id,
                               u32 ip6_table_id, u8 action)
{
  vlib_main_t *vm = vlib_get_main ();
  upf_main_t *um = &upf_main;

  u32 ip4_fib_id = ~0, ip6_fib_id = ~0;

  if (action != 0) // not delete
    {
      if (is_valid_id (ip4_table_id))
        {
          ip4_fib_id = fib_table_find (FIB_PROTOCOL_IP4, ip4_table_id);
          if (!is_valid_id (ip4_fib_id))
            return clib_error_return_code (0, VNET_API_ERROR_NO_SUCH_TABLE, 0,
                                           "no such ip4 table %d",
                                           ip4_table_id);
        }
      if (is_valid_id (ip6_table_id))
        {
          ip6_fib_id = fib_table_find (FIB_PROTOCOL_IP6, ip6_table_id);
          if (!is_valid_id (ip6_fib_id))
            return clib_error_return_code (0, VNET_API_ERROR_NO_SUCH_TABLE, 0,
                                           "no such ip6 table %d",
                                           ip6_table_id);
        }
    }

  upf_forwarding_policy_t *fp = NULL;
  uword *hash_ptr = hash_get_mem (um->forwarding_policy_by_id, policy_id);
  if (hash_ptr)
    fp = pool_elt_at_index (um->forwarding_policies, hash_ptr[0]);

  if (action == 1) // create
    {
      if (fp && !fp->is_removed)
        return clib_error_return_code (0, VNET_API_ERROR_ENTRY_ALREADY_EXISTS,
                                       0, "policy '%v' already exists",
                                       policy_id);

      vlib_worker_thread_barrier_sync (vm);

      if (!fp)
        {
          pool_get_zero (um->forwarding_policies, fp);
          fp->policy_id = vec_dup (policy_id);
          hash_set_mem (um->forwarding_policy_by_id, fp->policy_id,
                        fp - um->forwarding_policies);
        }
      fp->is_removed = false;
      fp->ip4_fib_id = ip4_fib_id;
      fp->ip6_fib_id = ip6_fib_id;
      _upf_forwarding_policy_fib_lock (fp);

      vlib_worker_thread_barrier_release (vm);
      return NULL;
    }

  if (!fp || fp->is_removed)
    return clib_error_return_code (0, VNET_API_ERROR_NO_SUCH_ENTRY, 0,
                                   "no such policy '%v'", policy_id);

  vlib_worker_thread_barrier_sync (vm);

  if (action == 2) // update
    {
      _upf_forwarding_policy_fib_unlock (fp);
      fp->ip4_fib_id = ip4_fib_id;
      fp->ip6_fib_id = ip6_fib_id;
      _upf_forwarding_policy_fib_lock (fp);
    }
  else // delete
    {
      _upf_forwarding_policy_fib_unlock (fp);
      fp->ip4_fib_id = ~0;
      fp->ip6_fib_id = ~0;
      fp->is_removed = true;

      if (fp->locks == 0)
        _upf_forwarding_policy_free (fp);
    }

  vlib_worker_thread_barrier_release (vm);
  return NULL;
}

void
upf_forwarding_policy_ref (upf_forwarding_policy_t *fp)
{
  fp->locks += 1;
}

void
upf_forwarding_policy_unref (upf_forwarding_policy_t *fp)
{
  ASSERT (fp->locks != 0);
  fp->locks -= 1;
  if (fp->locks == 0 && fp->is_removed)
    _upf_forwarding_policy_free (fp);
}

u32
upf_forwarding_policy_get_table_id (upf_forwarding_policy_t *fp, bool is_ip4)
{
  fib_protocol_t fib_proto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  u32 fib_index = is_ip4 ? fp->ip4_fib_id : fp->ip6_fib_id;
  if (!is_valid_id (fib_index))
    return ~0;

  return fib_table_get_table_id (fib_index, fib_proto);
}
