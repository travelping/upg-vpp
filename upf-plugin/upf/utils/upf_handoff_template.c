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

#include <vnet/buffer.h>

#include "upf/core/upf_buffer_opaque.h"
#include "upf/utils/upf_handoff_template.h"

char *upf_handoff_template_error_strings[] = {
#define _(sym, string) string,
  foreach_upf_handoff_template_error
#undef _
};

u8 *
format_upf_handoff_template_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_handoff_template_trace_t *t =
    va_arg (*args, upf_handoff_template_trace_t *);

  s = format (s, "next-worker %d", t->next_worker_index);
  return s;
}

uword
upf_handoff_template_node (vlib_main_t *vm, vlib_node_runtime_t *node,
                           vlib_frame_t *frame, u32 fq_index)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 n_enq, n_left_from, *from;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from > 0)
    {
      ti[0] = upf_buffer_opaque (b[0])->handoff.thread_id;

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
        {
          upf_handoff_template_trace_t *t =
            vlib_add_trace (vm, node, b[0], sizeof (*t));
          t->next_worker_index = ti[0];
        }

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
                                         thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
                                 UPF_HANDOFF_ERROR_CONGESTION_DROP,
                                 frame->n_vectors - n_enq);

  return n_enq;
}
