/*
 * upf_app_db.h - 3GPP TS 29.244 UPF adf header file
 *
 * Copyright (c) 2017 Travelping GmbH
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

#ifndef __included_upf_app_db_h__
#define __included_upf_app_db_h__

#include <stddef.h>
#include <upf/upf.h>
#include <hs/hs.h>

#if CLIB_DEBUG > 1
#define adf_debug clib_warning
#else
#define adf_debug(...)                                                        \
  do                                                                          \
    {                                                                         \
    }                                                                         \
  while (0)
#endif

#define TLS_HANDSHAKE    22
#define TLS_CLIENT_HELLO 1
#define TLS_EXT_SNI      0

CLIB_PACKED (struct tls_record_hdr {
  u8 type;
  u8 major;
  u8 minor;
  u16 length;
});

CLIB_PACKED (struct tls_handshake_hdr {
  u8 type;
  u8 length[3];
});

CLIB_PACKED (struct tls_client_hello_hdr {
  u8 major;
  u8 minor;
  u8 random[32]; /* gmt_unix_time + random_bytes[28] */
});

typedef struct
{
  u32 rule_index;     /* referenced ADR rule index */
  index_t next;       /* link to the next less specific ACL ref */
  index_t dpoi_index; /* DPO id */
  u8 src_preflen;     /* src prefix length */
  u8 is_ip4 : 1;
} upf_app_dpo_t;

typedef struct
{
  regex_t *expressions;
  acl_rule_t *acl;
  u32 *flags;
  unsigned int *ids;
  hs_database_t *database;
  hs_scratch_t *scratch;
  u32 ref_cnt;
  u32 fib_index_ip4;       /* IP rule FIB table index (IP4) */
  u32 fib_index_ip6;       /* IP rule FIB table index (IP6) */
  upf_app_dpo_t *app_dpos; /* vector of APP DPOs */
} upf_adf_entry_t;

int upf_adf_lookup (u32 db_index, u8 *str, uint16_t length, u32 *id);
int upf_app_add_del (upf_main_t *sm, u8 *name, u32 flags, int add);
int upf_rule_add_del (upf_main_t *sm, u8 *name, u32 id, int add, u8 *regex,
                      acl_rule_t *acl);

u32 upf_adf_get_adr_db (u32 application_id);
void upf_adf_put_adr_db (u32 db_index);

int upf_update_app (upf_main_t *sm, u8 *app_name, u32 num_rules, u32 *ids,
                    u32 *regex_lengths, u8 **regexes);

adr_result_t upf_application_detection (vlib_main_t *vm, u8 *p,
                                        flow_entry_t *flow,
                                        struct rules *active);

int upf_app_ip_rule_match (u32 db_index, flow_entry_t *flow,
                           ip46_address_t *assigned);

/* perfect hash over the HTTP keywords:
 *   GET
 *   PUT
 *   HEAD
 *   POST
 *   COPY
 *   MOVE
 *   LOCK
 *   MKCOL
 *   TRACE
 *   PATCH
 *   DELETE
 *   UNLOCK
 *   CONNECT
 *   OPTIONS
 *   PROPPATCH
 */
#if CLIB_ARCH_IS_BIG_ENDIAN
#define char_to_u32(A, B, C, D) (((A) << 24) | ((B) << 16) | ((C) << 8) | (D))
#define char_to_u64(A, B, C, D, E, F, G, H)                                   \
  (((u64) (A) << 56) | ((u64) (B) << 48) | ((u64) (C) << 40) |                \
   ((u64) (D) << 32) | ((u64) (E) << 24) | ((u64) (F) << 16) |                \
   ((u64) (G) << 8) | (u64) (H))
#else
#define char_to_u32(A, B, C, D) (((D) << 24) | ((C) << 16) | ((B) << 8) | (A))
#define char_to_u64(A, B, C, D, E, F, G, H)                                   \
  (((u64) (H) << 56) | ((u64) (G) << 48) | ((u64) (F) << 40) |                \
   ((u64) (E) << 32) | ((u64) (D) << 24) | ((u64) (C) << 16) |                \
   ((u64) (B) << 8) | (u64) (A))
#endif

#define char_mask_64_5 char_to_u64 (0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0)
#define char_mask_64_6 char_to_u64 (0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0)
#define char_mask_64_7                                                        \
  char_to_u64 (0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0)

always_inline int
is_http_request (u8 **payload, word *len)
{
  u32 c0 = *(u32 *) *payload;
  u64 d0 = *(u64 *) *payload;

  if (*len < 10)
    return ADR_NEED_MORE_DATA;

  if (c0 == char_to_u32 ('G', 'E', 'T', ' ') ||
      c0 == char_to_u32 ('P', 'U', 'T', ' '))
    {
      *payload += 4;
      *len -= 4;
      return ADR_OK;
    }
  else if ((c0 == char_to_u32 ('H', 'E', 'A', 'D') ||
            c0 == char_to_u32 ('P', 'O', 'S', 'T') ||
            c0 == char_to_u32 ('C', 'O', 'P', 'Y') ||
            c0 == char_to_u32 ('M', 'O', 'V', 'E') ||
            c0 == char_to_u32 ('L', 'O', 'C', 'K')) &&
           (*payload)[4] == ' ')
    {
      *payload += 5;
      *len -= 5;
      return ADR_OK;
    }
  else if (((d0 & char_mask_64_6) ==
            char_to_u64 ('M', 'K', 'C', 'O', 'L', ' ', 0, 0)) ||
           ((d0 & char_mask_64_6) ==
            char_to_u64 ('T', 'R', 'A', 'C', 'E', ' ', 0, 0)) ||
           ((d0 & char_mask_64_6) ==
            char_to_u64 ('P', 'A', 'T', 'C', 'H', ' ', 0, 0)))
    {
      *payload += 6;
      *len -= 6;
      return ADR_OK;
    }
  else if (((d0 & char_mask_64_7) ==
            char_to_u64 ('D', 'E', 'L', 'E', 'T', 'E', ' ', 0)) ||
           ((d0 & char_mask_64_7) ==
            char_to_u64 ('U', 'N', 'L', 'O', 'C', 'K', ' ', 0)))
    {
      *payload += 7;
      *len -= 7;
      return ADR_OK;
    }
  else if ((d0 == char_to_u64 ('C', 'O', 'N', 'N', 'E', 'C', 'T', ' ')) ||
           (d0 == char_to_u64 ('O', 'P', 'T', 'I', 'O', 'N', 'S', ' ')))
    {
      *payload += 8;
      *len -= 8;
      return ADR_OK;
    }
  if (c0 == char_to_u32 ('P', 'R', 'O', 'P'))
    {
      u64 d1 = *(u64 *) (*payload + 4);

      if ((d1 & char_mask_64_5) ==
          char_to_u64 ('F', 'I', 'N', 'D', ' ', 0, 0, 0))
        {
          *payload += 9;
          *len -= 9;
          return ADR_OK;
        }
      else if ((d1 & char_mask_64_6) ==
               char_to_u64 ('P', 'A', 'T', 'C', 'H', ' ', 0, 0))
        {
          *payload += 10;
          *len -= 10;
          return ADR_OK;
        }
    }

  return ADR_FAIL;
}

#endif /* __included_upf_app_db_h__ */
