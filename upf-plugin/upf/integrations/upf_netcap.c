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

#include "upf/upf.h"

#define UPF_DEBUG_ENABLE 0

clib_error_t *
upf_imsi_netcap_enable_disable (upf_imsi_t imsi, u8 *target,
                                u16 packet_max_bytes, bool enable)
{
  upf_main_t *um = &upf_main;

  if (!um->netcap.enabled)
    return clib_error_return_code (0, VNET_API_ERROR_FEATURE_DISABLED, 0,
                                   "feature disabled");

  upf_imsi_capture_list_id_t *p_imsi_capture_list_id =
    (upf_imsi_capture_list_id_t *) mhash_get (
      &um->mhash_imsi_to_capture_list_id, &imsi);

  upf_imsi_sessions_list_t *p_session_imsi_list =
    (upf_imsi_sessions_list_t *) mhash_get (&um->mhash_imsi_to_session_list,
                                            &imsi);

  upf_imsi_capture_list_id_t imsi_capture_list_id = ~0;
  upf_imsi_capture_list_t *imsi_capture_list = NULL;
  upf_imsi_capture_t *capture = NULL;

  if (p_imsi_capture_list_id)
    {
      imsi_capture_list_id = *p_imsi_capture_list_id;
      imsi_capture_list =
        pool_elt_at_index (um->netcap.capture_lists, imsi_capture_list_id);

      upf_llist_foreach (cap, um->netcap.captures, imsi_list_anchor,
                         imsi_capture_list)
        {
          if (vec_is_equal (cap->target, target))
            {
              capture = cap;
              break;
            }
        }
    }

  upf_debug (
    "imsi %U target %v mb %d enable %d imsi_capture_list_id %d cap %lx",
    format_pfcp_tbcd, &imsi.tbcd, sizeof (imsi.tbcd), target, packet_max_bytes,
    enable, imsi_capture_list_id, capture);

  if (enable)
    {
      if (capture)
        return clib_error_return_code (
          0, VNET_API_ERROR_ENTRY_ALREADY_EXISTS, 0,
          "capture streams already exists for imsi");

      if (!p_imsi_capture_list_id)
        {
          // create new list
          pool_get_zero (um->netcap.capture_lists, imsi_capture_list);
          upf_imsi_capture_list_init (imsi_capture_list);
          imsi_capture_list_id = imsi_capture_list - um->netcap.capture_lists;

          mhash_set (&um->mhash_imsi_to_capture_list_id, &imsi,
                     imsi_capture_list_id, NULL);
        }

      pool_get_zero (um->netcap.captures, capture);
      capture->packet_max_bytes = packet_max_bytes;
      capture->target = vec_dup (target);
      upf_imsi_capture_list_anchor_init (capture);

      upf_imsi_capture_list_insert_tail (um->netcap.captures,
                                         imsi_capture_list, capture);
    }
  else
    {
      if (capture == NULL)
        return clib_error_return_code (0, VNET_API_ERROR_NO_SUCH_ENTRY, 0,
                                       "stream doesn't exists");

      upf_imsi_capture_list_remove (um->netcap.captures, imsi_capture_list,
                                    capture);
      vec_free (capture->target);
      pool_put (um->netcap.captures, capture);

      if (upf_imsi_capture_list_is_empty (imsi_capture_list))
        {
          mhash_unset (&um->mhash_imsi_to_capture_list_id, &imsi, NULL);
          pool_put_index (um->netcap.capture_lists, imsi_capture_list_id);
          imsi_capture_list_id = ~0;
        }
    }

  if (p_session_imsi_list)
    upf_llist_foreach (sx, um->sessions, imsi_list_anchor, p_session_imsi_list)
      {
        sx->imsi_capture_list_id = imsi_capture_list_id;
        upf_session_queue_rules_refresh (sx);
      }
  return NULL;
}
