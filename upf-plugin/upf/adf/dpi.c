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

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include "upf/adf/adf.h"

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
_is_http_request (u8 **payload, word *len)
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

always_inline adf_result_t
_upf_adf_try_tls (u16 server_port, u8 *p, u8 **uri)
{
  struct tls_record_hdr *hdr = (struct tls_record_hdr *) p;
  struct tls_handshake_hdr *hsk = (struct tls_handshake_hdr *) (hdr + 1);
  struct tls_client_hello_hdr *hlo = (struct tls_client_hello_hdr *) (hsk + 1);
  u8 *data = (u8 *) (hlo + 1);
  word frgmt_len, hsk_len, len;
  uword length = vec_len (p);

  upf_debug ("Length: %d", length);
  if (length < sizeof (*hdr))
    return ADR_NEED_MORE_DATA;

  upf_debug ("HDR: %u, v: %u.%u, Len: %d", hdr->type, hdr->major, hdr->minor,
             clib_net_to_host_u16 (hdr->length));
  if (hdr->type != TLS_HANDSHAKE)
    return ADR_FAIL;

  if (hdr->major != 3 || hdr->minor < 1 || hdr->minor > 3)
    /* TLS 1.0, 1.1 and 1.2 only (for now)
     * SSLv2 backward-compatible hello is not supported
     */
    return ADR_FAIL;

  length -= sizeof (*hdr);
  frgmt_len = clib_net_to_host_u16 (hdr->length);

  if (length < frgmt_len)
    /* TLS fragment is longer then IP payload */
    return ADR_NEED_MORE_DATA;

  hsk_len = hsk->length[0] << 16 | hsk->length[1] << 8 | hsk->length[2];
  upf_debug ("TLS Hello: %u, v: Len: %d", hsk->type, hsk_len);

  if (hsk_len + sizeof (*hsk) < frgmt_len)
    /* Hello is longer that the current fragment */
    return ADR_NEED_MORE_DATA;

  if (hsk->type != TLS_CLIENT_HELLO)
    return ADR_FAIL;

  upf_debug ("TLS Client Hello: %u.%u", hlo->major, hlo->minor);
  if (hlo->major != 3 || hlo->minor < 1 || hlo->minor > 3)
    /* TLS 1.0, 1.1 and 1.2 only (for now) */
    return ADR_FAIL;

  len = hsk_len - sizeof (*hlo);

  /* Session Id */
  if (len < *data + 1)
    return ADR_NEED_MORE_DATA;

  len -= *data + 1;
  data += *data + 1;

  /* Cipher Suites */
  if (len < clib_net_to_host_unaligned_mem_u16 ((u16 *) data) + 2)
    return ADR_NEED_MORE_DATA;

  len -= clib_net_to_host_unaligned_mem_u16 ((u16 *) data) + 2;
  data += clib_net_to_host_unaligned_mem_u16 ((u16 *) data) + 2;

  /* Compression Methods */
  if (len < *data + 1)
    return ADR_NEED_MORE_DATA;

  len -= *data + 1;
  data += *data + 1;

  /* Extensions */
  if (len < clib_net_to_host_unaligned_mem_u16 ((u16 *) data) + 2)
    return ADR_NEED_MORE_DATA;

  len = clib_net_to_host_unaligned_mem_u16 ((u16 *) data);
  data += 2;

  while (len > 4)
    {
      u16 ext_type, ext_len, sni_len, name_len;

      ext_type = clib_net_to_host_unaligned_mem_u16 ((u16 *) data);
      ext_len = clib_net_to_host_unaligned_mem_u16 ((u16 *) (data + 2));

      upf_debug ("TLS Hello Extension: %u, %u", ext_type, ext_len);

      if (ext_type != TLS_EXT_SNI)
        goto skip_extension;

      if (ext_len < 5 || ext_len + 4 > len)
        {
          upf_debug ("invalid extension len: %u (%u)", ext_len, len);
          goto skip_extension;
        }

      sni_len = clib_net_to_host_unaligned_mem_u16 ((u16 *) (data + 4));
      if (sni_len != ext_len - 2)
        {
          upf_debug ("invalid SNI extension len: %u != %u", sni_len,
                     ext_len - 2);
          goto skip_extension;
        }

      if (*(data + 6) != 0)
        {
          upf_debug ("invalid SNI name type: %u", *(data + 6));
          goto skip_extension;
        }

      name_len = clib_net_to_host_unaligned_mem_u16 ((u16 *) (data + 7));
      if (name_len != sni_len - 3)
        {
          upf_debug ("invalid server name len: %u != %u", name_len,
                     sni_len - 3);
          goto skip_extension;
        }

      vec_add (*uri, "https://", strlen ("https://"));
      vec_add (*uri, data + 9, name_len);
      if (server_port != 443)
        *uri = format (*uri, ":%u", server_port);
      vec_add1 (*uri, '/');

      return ADR_OK;

    skip_extension:
      len -= ext_len + 4;
      data += ext_len + 4;
    }

  return ADR_FAIL;
}

always_inline adf_result_t
_upf_adf_try_http (u16 server_port, u8 *p, u8 **uri)
{
  word len = vec_len (p);
  word uri_len;
  u8 *eol;
  u8 *s;
  adf_result_t r;

  if ((r = _is_http_request (&p, &len)) != ADR_OK)
    return r;

  upf_debug ("p: %*s", len, p);
  eol = memchr (p, '\n', len);
  upf_debug ("eol %p", eol);
  if (!eol)
    /* not EOL found */
    return ADR_NEED_MORE_DATA;

  s = memchr (p, ' ', eol - p);
  upf_debug ("s: %p", s);
  if (!s)
    /* HTTP/0.9 - can find the Host Header */
    return ADR_FAIL;

  uri_len = s - p;

  {
    u64 d0 = *(u64 *) (s + 1);

    upf_debug ("d0: 0x%016x, 1.0: 0x%016x, 1.1: 0x%016x", d0,
               char_to_u64 ('H', 'T', 'T', 'P', '/', '1', '.', '0'),
               char_to_u64 ('H', 'T', 'T', 'P', '/', '1', '.', '1'));
    if (d0 != char_to_u64 ('H', 'T', 'T', 'P', '/', '1', '.', '0') &&
        d0 != char_to_u64 ('H', 'T', 'T', 'P', '/', '1', '.', '1'))
      /* not HTTP 1.0 or 1.1 compatible */
      return ADR_FAIL;
  }

  s = eol + 1;
  len -= (eol - p) + 1;

  while (len > 0)
    {
      u64 d0 = *(u64 *) s;
      uword ll;

      eol = memchr (s, '\n', len);
      if (!eol)
        return ADR_NEED_MORE_DATA;

      upf_debug ("l: %*s", eol - s, s);

      ll = eol - s;
      if (ll == 0 || (ll == 1 && s[0] == '\r'))
        /* end of headers */
        return ADR_FAIL;

      /* upper case 1st 4 characters of header */
      if ((d0 & char_to_u64 (0xdf, 0xdf, 0xdf, 0xdf, 0xff, 0, 0, 0)) ==
          char_to_u64 ('H', 'O', 'S', 'T', ':', 0, 0, 0))
        {
          s += 5;

          /* find first non OWS */
          for (; s < eol && *s <= ' '; s++)
            ;
          /* find last non OWS */
          for (; eol > s && *eol <= ' '; eol--)
            ;

          if (eol == s)
            /* there could be a non OWS at *s, but single letter host
             * names are not possible, so ignore that
             */
            return ADR_FAIL;

          vec_add (*uri, "http://", strlen ("http://"));
          vec_add (*uri, s, eol - s + 1);
          if (server_port != 80)
            *uri = format (*uri, ":%u", server_port);
          vec_add (*uri, p, uri_len);

          return ADR_OK;
        }

      s = eol + 1;
      len -= ll + 1;
    }

  return ADR_NEED_MORE_DATA;
}

adf_result_t
upf_adf_dpi_extract_uri (u8 *p, u16 server_port, u8 **p_uri)
{
  ASSERT (p);

  if (*p == TLS_HANDSHAKE)
    return _upf_adf_try_tls (server_port, p, p_uri);
  else
    return _upf_adf_try_http (server_port, p, p_uri);
}
