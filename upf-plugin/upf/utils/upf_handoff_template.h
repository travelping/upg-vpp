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

#ifndef UPF_UTILS_UPF_HANDOFF_TEMPLATE_H_
#define UPF_UTILS_UPF_HANDOFF_TEMPLATE_H_

#include <vlib/vlib.h>

#define foreach_upf_handoff_template_error                                    \
  _ (CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym, str) UPF_HANDOFF_ERROR_##sym,
  foreach_upf_handoff_template_error
#undef _
    UPF_HANDOFF_TEMPLATE_N_ERROR,
} upf_handoff_template_error_t;

extern char *upf_handoff_template_error_strings[UPF_HANDOFF_TEMPLATE_N_ERROR];

typedef struct
{
  u32 next_worker_index;
} upf_handoff_template_trace_t;

#define UPF_HANDOFF_TEMPLATE_NODE_REGISTRATION(node_name)                     \
  (vlib_node_registration_t)                                                  \
  {                                                                           \
    .name = node_name, .vector_size = sizeof (u32),                           \
    .format_trace = format_upf_handoff_template_trace,                        \
    .type = VLIB_NODE_TYPE_INTERNAL,                                          \
    .n_errors = ARRAY_LEN (upf_handoff_template_error_strings),               \
    .error_strings = upf_handoff_template_error_strings,                      \
  }

uword upf_handoff_template_node (vlib_main_t *vm, vlib_node_runtime_t *node,
                                 vlib_frame_t *frame, u32 fq_index);

u8 *format_upf_handoff_template_trace (u8 *s, va_list *args);

#endif // UPF_UTILS_UPF_HANDOFF_TEMPLATE_H_
