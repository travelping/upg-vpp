// memory_trace_test.go - 3GPP TS 29.244 GTP-U UP plug-in
//
// Copyright (c) 2021 Travelping GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vpp

import (
	"testing"
)

func TestMemoryTrace(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{
			name: "single trace",
			text: sampleMemoryTrace,
		},
		{
			name: "2 core trace",
			text: sampleMemoryTrace2Core,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseMemoryTrace(tc.text)
			if err != nil {
				t.Fatalf("ParseMemoryTrace failed: %v", err)
			}
			for _, name := range []string{"handle_create_pdr", "pfcp_create_session"} {
				if !parsed.FindSuspectedLeak(name, 2000) {
					t.Errorf("didn't find the leak that's present there: %s", name)
				}
			}
			for _, name := range []string{"pfcp_add_del_ue_ip", "foobar"} {
				if parsed.FindSuspectedLeak(name, 2000) {
					t.Errorf("found a leak that's not there: %s", name)
				}
			}
		})
	}
}

// NOTE: 'totals' below at the bottom of the sample traces don't add up
// and aren't used in the checks
var sampleMemoryTrace = `Thread 0 vpp_main
  virtual memory start 0x7fffb46c9000, size 1048640k, 262160 pages, page size 4k
    numa 0: 212252 pages, 849008k
    not mapped: 49908 pages, 199632k
  total: 1.00G, used: 825.16M, free: 198.91M, trimmable: 197.96M

  Bytes    Count     Sample   Traceback
  2100096    10000 0x7fffe80c7f98 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0xa8
                                  _vec_resize_inline + 0x240
                                  handle_create_pdr + 0x391
                                  handle_session_establishment_request + 0x30a
                                  session_msg + 0x2cc
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
  1149456    10000 0x7fffe80c6550 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0xa8
                                  _vec_resize_inline + 0x240
                                  sparse_vec_new + 0xdd
                                  pfcp_create_session + 0x44a
                                  handle_session_establishment_request + 0x266
                                  session_msg + 0x2cc
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
   838064    10000 0x7fffe80c65f8 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0xa8
                                  _vec_resize_inline + 0x240
                                  sparse_vec_new + 0x22d
                                  pfcp_create_session + 0x44a
                                  handle_session_establishment_request + 0x266
                                  session_msg + 0x2cc
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
   643088    10000 0x7fffe80c7da8 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0xa8
                                  _vec_resize_inline + 0x240
                                  sparse_vec_new + 0x357
                                  pfcp_create_session + 0x44a
                                  handle_session_establishment_request + 0x266
                                  session_msg + 0x2cc
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
    62336        1 0x7fffe7a4ac08 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0x22d
                                  _vec_resize_inline + 0x240
                                  pfcp_create_session + 0x260
                                  handle_session_establishment_request + 0x266
                                  session_msg + 0x2cc
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
    39392        1 0x7fffe7aa7dc8 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0x22d
                                  _vec_resize_inline + 0x240
                                  pfcp_msg_pool_get + 0x491
                                  upf_pfcp_send_response + 0x32
                                  handle_session_deletion_request + 0x366
                                  session_msg + 0x350
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
     1056        1 0x7fffe799b528 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0x22d
                                  _vec_resize_inline + 0x240
                                  fib_node_list_destroy + 0x406
                                  fib_node_child_remove + 0x6d
                                  fib_path_list_child_remove + 0x1e
                                  fib_entry_src_action_deactivate + 0x1d9
                                  fib_entry_src_action_remove + 0x8d
                                  fib_entry_src_action_remove_or_update_inherit + 0x19c
                                  fib_entry_special_remove + 0x143
                                  fib_table_entry_special_remove + 0x6c
                                  pfcp_add_del_ue_ip + 0xe9
100 total traced objects
`

var sampleMemoryTrace2Core = `Thread 0 vpp_main
  virtual memory start 0x7fffb46c9000, size 1048640k, 262160 pages, page size 4k
    numa 0: 212252 pages, 849008k
    not mapped: 49908 pages, 199632k
  total: 1.00G, used: 825.16M, free: 198.91M, trimmable: 197.96M

  Bytes    Count     Sample   Traceback
  2100096    10000 0x7fffe80c7f98 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0xa8
                                  _vec_resize_inline + 0x240
                                  handle_create_pdr + 0x391
                                  handle_session_establishment_request + 0x30a
                                  session_msg + 0x2cc
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
    62336        1 0x7fffe7a4ac08 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0x22d
                                  _vec_resize_inline + 0x240
                                  pfcp_create_session + 0x260
                                  handle_session_establishment_request + 0x266
                                  session_msg + 0x2cc
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
    39392        1 0x7fffe7aa7dc8 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0x22d
                                  _vec_resize_inline + 0x240
                                  pfcp_msg_pool_get + 0x491
                                  upf_pfcp_send_response + 0x32
                                  handle_session_deletion_request + 0x366
                                  session_msg + 0x350
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
     1056        1 0x7fffe799b528 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0x22d
                                  _vec_resize_inline + 0x240
                                  fib_node_list_destroy + 0x406
                                  fib_node_child_remove + 0x6d
                                  fib_path_list_child_remove + 0x1e
                                  fib_entry_src_action_deactivate + 0x1d9
                                  fib_entry_src_action_remove + 0x8d
                                  fib_entry_src_action_remove_or_update_inherit + 0x19c
                                  fib_entry_special_remove + 0x143
                                  fib_table_entry_special_remove + 0x6c
                                  pfcp_add_del_ue_ip + 0xe9
505 total traced objects


Thread 1 vpp_wk_0
  virtual memory start 0x7fffb46c9000, size 1048640k, 262160 pages, page size 4k
    numa 0: 231914 pages, 927656k
    not mapped: 30246 pages, 120984k
  total: 1.00G, used: 840.02M, free: 184.04M, trimmable: 126.22M

  Bytes    Count     Sample   Traceback
  1149456    10000 0x7fffe80c6550 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0xa8
                                  _vec_resize_inline + 0x240
                                  sparse_vec_new + 0xdd
                                  pfcp_create_session + 0x44a
                                  handle_session_establishment_request + 0x266
                                  session_msg + 0x2cc
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
   838064    10000 0x7fffe80c65f8 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0xa8
                                  _vec_resize_inline + 0x240
                                  sparse_vec_new + 0x22d
                                  pfcp_create_session + 0x44a
                                  handle_session_establishment_request + 0x266
                                  session_msg + 0x2cc
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
   643088    10000 0x7fffe80c7da8 clib_mem_alloc_aligned_at_offset + 0x8f
                                  vec_resize_allocate_memory + 0xa8
                                  _vec_resize_inline + 0x240
                                  sparse_vec_new + 0x357
                                  pfcp_create_session + 0x44a
                                  handle_session_establishment_request + 0x266
                                  session_msg + 0x2cc
                                  upf_pfcp_handle_msg + 0x6f
                                  upf_pfcp_server_rx_msg + 0x46b
                                  pfcp_process + 0x23e
                                  vlib_process_bootstrap + 0x5d
                                  0x7ffff561c7a4
100 total traced objects
`
