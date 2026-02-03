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

#ifndef UPF_UTILS_UPF_MT_H_
#define UPF_UTILS_UPF_MT_H_

#include <stdbool.h>
#include <vppinfra/types.h>

#include "upf/utils/upf_localids.h"
#include "upf/pfcp/upf_session_report.h"

// We not sure yet which way of MT communication will be used, here we define
// simplified API which is suitable enough for UPF needs and implimented with
// simple locking.

typedef enum : u8
{
  // main to worker threads
  UPF_MT_EVENT_M2W_SESSION_REQ,

  // worker to main thread
  UPF_MT_EVENT_W2M_SESSION_RESP,
  UPF_MT_EVENT_W2M_SESSION_REPORT,
  UPF_MT_EVENT_W2M_USAGE_REPORT,

  UPF_MT_N_EVENT,
} upf_mt_event_kind_t;

typedef enum : u8
{
  UPF_MT_SESSION_REQ_CREATE,
  UPF_MT_SESSION_REQ_UPDATE,
  UPF_MT_SESSION_REQ_DELETE,
} upf_mt_session_req_kind_t;

typedef struct
{
  u64 up_seid;      // for verification
  u32 session_id;   // required
  u32 new_rules_id; // required on creation, invalid on deletion
  u32 procedure_id;

  u8 is_terminated_by_up : 1; // if it is local termination

  // to return created values
  upf_lidset_t created_pdr_lids;

  // to init or remove timers and etc
  // are valid only during create and update
  upf_lidset_t created_urr_lids;
  upf_lidset_t removed_urr_lids;

  // list of urrs ids (old ids) to be reported
  upf_lidset_t immediate_report_urrs;

  upf_mt_session_req_kind_t kind;
} upf_mt_session_req_t;

typedef struct
{
  u64 up_seid; // for verification
  u32 session_id;
  u32 new_rules_id; // for verification
  u32 procedure_id;
  u32 usage_reports_count;

  u8 is_dp_terminated_before : 1;

  upf_mt_session_req_kind_t kind; // for verification
} upf_mt_session_resp_t;

typedef struct
{
  u64 up_seid; // for verification
  u32 session_id;

  upf2_session_report_t report;
} upf_mt_session_report_t;

typedef struct
{
  u64 up_seid; // for verification
  u32 session_id;

  u32 is_error_indication : 1;
} upf_mt_session_event_t;

typedef struct
{
  upf2_usage_report_t report;
} upf_mt_usage_report_t;

typedef struct
{
  upf_mt_event_kind_t kind;
  union
  {
    upf_mt_session_req_t m2w_session_req;
    upf_mt_session_resp_t w2m_session_resp;
    upf_mt_session_report_t w2m_session_report;
    upf_mt_usage_report_t w2m_usage_report;
    // upf_mt_session_event_t w2m_session_event;
  };
} upf_mt_event_t;

typedef struct
{
  // avoid cache line sharing between workers
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  clib_spinlock_t lock;
  upf_mt_event_t *ring_m2w;
  upf_mt_event_t *ring_w2m;
} upf_mt_wk_t;

typedef struct
{
  // workers count equals to all threads count
  // we do not do separation between worker and non-worker to simplify thread
  // index to worker index conversion
  upf_mt_wk_t *workers; // vec
} upf_mt_main_t;

extern upf_mt_main_t upf_mt_main;

void upf_mt_init ();

// used to atomically send multiple events
void upf_mt_enqueue_to_main (u16 wk_thread_id, upf_mt_event_t *ev, u32 count);
void upf_mt_enqueue_to_wk (u16 wk_thread_id, upf_mt_event_t *ev, u32 count);

// Handlers for events. Maybe these should be defined in other places
void handle_mt_event_m2w_session_req (u16 wk_thread_id,
                                      upf_mt_session_req_t *ev);
void handle_mt_event_w2m_session_resp (u16 wk_thread_id,
                                       upf_mt_session_resp_t *ev);
void handle_mt_event_w2m_session_report (u16 wk_thread_id,
                                         upf_mt_session_report_t *ev);
void handle_mt_event_w2m_usage_report (u16 wk_thread_id,
                                       upf_mt_usage_report_t *ev);

#endif // UPF_UTILS_UPF_MT_H_
