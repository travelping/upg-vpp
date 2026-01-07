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

#ifndef UPF_UTILS_LLIST_H_
#define UPF_UTILS_LLIST_H_

#include <stdbool.h>

#include <vppinfra/error_bootstrap.h>
#include <vppinfra/types.h>
#include <vppinfra/clib.h>

// This is analog of vpp dlist, but intrusive version with anchor.
// Recommendation is to use typed helpers created via UPF_LLIST_TEMPLATE_*.

#if CLIB_ASSERT_ENABLE
/* llist debug adds count field to list to verify it's length */
#define UPF_LLIST_DEBUG
#endif

typedef struct
{
  /*
    if empty, then ~0
    if non empty, then idx of element
  */
  u32 head;
#ifdef UPF_LLIST_DEBUG
  u32 _debug_count;
#endif
} upf_llist_t;

typedef struct
{
  /*
    if not in a list, next = ~0 and prev = ~0
    if single element in list next = this el, prev = this el
    if in list next = next el, prev = prev el
  */
  u32 next;
  u32 prev;
} upf_llist_anchor_t;

#ifdef UPF_LLIST_DEBUG
#define _UPF_LLIST_LIST_ASSERT_CHANGE_COUNT(LIST, CHANGE)                     \
  do                                                                          \
    {                                                                         \
      LIST->_debug_count += (CHANGE);                                         \
      ASSERT (LIST->_debug_count + 1 != 0);                                   \
                                                                              \
      u32 head_id = LIST->head;                                               \
      u32 debug_count = LIST->_debug_count;                                   \
      ASSERT ((head_id != ~0) == (debug_count != 0));                         \
    }                                                                         \
  while (0)
#else
#define _UPF_LLIST_LIST_ASSERT_CHANGE_COUNT(LIST, CHANGE)                     \
  {                                                                           \
  }
#endif

__clib_unused static void
upf_llist_init (upf_llist_t *list)
{
  list->head = ~0;
#ifdef UPF_LLIST_DEBUG
  list->_debug_count = 0;
#endif
}

__clib_unused static bool
upf_llist_list_is_empty (upf_llist_t *list)
{
#ifdef UPF_LLIST_DEBUG
  u32 head_id = list->head;
  u32 debug_count = list->_debug_count;
  ASSERT ((head_id != ~0) == (debug_count != 0));
#endif
  return list->head == ~0;
}

__clib_unused static void
_upf_llist_anchor_init (upf_llist_anchor_t *anchor)
{
  anchor->next = ~0;
  anchor->prev = ~0;
}

__clib_unused static bool
_upf_llist_anchor_inserted (upf_llist_anchor_t *anchor)
{
#ifdef UPF_LLIST_DEBUG
  ASSERT ((anchor->next != ~0) == (anchor->prev != ~0));
#endif
  return anchor->next != ~0;
}

#define __upf_llist_get(VEC, INDEX) (&VEC[INDEX])
#define upf_llist_anchor_init(ANCHOR, ELEMENT)                                \
  _upf_llist_anchor_init (&ELEMENT->ANCHOR);
#define upf_llist_el_is_part_of_list(ANCHOR, ELEMENT)                         \
  _upf_llist_anchor_inserted (&ELEMENT->ANCHOR)

#define _upf_llist_el_insert_middle(VEC, ANCHOR, PREV, NEXT, NEW)             \
  do                                                                          \
    {                                                                         \
      typeof (VEC) _new_el = (NEW), _prev_el = (PREV), _next_el = (NEXT);     \
                                                                              \
      ASSERT (_new_el &&_prev_el &&_next_el);                                 \
      ASSERT (upf_llist_el_is_part_of_list (ANCHOR, _prev_el));               \
      ASSERT (upf_llist_el_is_part_of_list (ANCHOR, _next_el));               \
      ASSERT (!upf_llist_el_is_part_of_list (ANCHOR, _new_el));               \
      ASSERT (_new_el != _prev_el && _new_el != _next_el);                    \
                                                                              \
      u32 _new_id = _new_el - VEC;                                            \
      u32 _prev_id = _prev_el - VEC;                                          \
      u32 _next_id = _next_el - VEC;                                          \
      ASSERT (_prev_el->ANCHOR.next == _next_id);                             \
      ASSERT (_next_el->ANCHOR.prev == _prev_id);                             \
      _prev_el->ANCHOR.next = _new_id;                                        \
      _next_el->ANCHOR.prev = _new_id;                                        \
      _new_el->ANCHOR.prev = _prev_id;                                        \
      _new_el->ANCHOR.next = _next_id;                                        \
    }                                                                         \
  while (0)

#define _upf_llist_el_insert_rel(VEC, ANCHOR, BASE, INSERT_BEFORE, NEW)       \
  do                                                                          \
    {                                                                         \
      typeof (VEC) _base = (BASE), _other;                                    \
                                                                              \
      if (INSERT_BEFORE)                                                      \
        {                                                                     \
          _other = __upf_llist_get (VEC, _base->ANCHOR.prev);                 \
          _upf_llist_el_insert_middle (VEC, ANCHOR, _other, _base, NEW);      \
        }                                                                     \
      else                                                                    \
        {                                                                     \
          _other = __upf_llist_get (VEC, _base->ANCHOR.next);                 \
          _upf_llist_el_insert_middle (VEC, ANCHOR, _base, _other, NEW);      \
        }                                                                     \
    }                                                                         \
  while (0)

#define upf_llist_el_insert_before(VEC, ANCHOR, BASE, NEW)                    \
  _upf_llist_el_insert_rel (VEC, ANCHOR, BASE, 1, NEW)

#define upf_llist_el_insert_after(VEC, ANCHOR, BASE, NEW)                     \
  _upf_llist_el_insert_rel (VEC, ANCHOR, BASE, 0, NEW)

#define upf_llist_insert_before(VEC, ANCHOR, LIST, BASE, NEW)                 \
  do                                                                          \
    {                                                                         \
      upf_llist_el_insert_before (VEC, ANCHOR, BASE, NEW);                    \
      _UPF_LLIST_LIST_ASSERT_CHANGE_COUNT (LIST, 1);                          \
    }                                                                         \
  while (0)

#define upf_llist_insert_after(VEC, ANCHOR, LIST, BASE, NEW)                  \
  do                                                                          \
    {                                                                         \
      upf_llist_el_insert_after (VEC, ANCHOR, BASE, NEW);                     \
      _UPF_LLIST_LIST_ASSERT_CHANGE_COUNT (LIST, 1);                          \
    }                                                                         \
  while (0)

#define _upf_llist_insert_rel_to_head(VEC, ANCHOR, LIST, MAKE_HEAD, NEW)      \
  do                                                                          \
    {                                                                         \
      typeof (VEC) __new_el = (NEW);                                          \
      upf_llist_t *__list = (LIST);                                           \
      ASSERT (!upf_llist_el_is_part_of_list (ANCHOR, __new_el));              \
      u32 __new_id = __new_el - VEC;                                          \
                                                                              \
      if (upf_llist_list_is_empty (LIST))                                     \
        {                                                                     \
          __new_el->ANCHOR.next = __new_id;                                   \
          __new_el->ANCHOR.prev = __new_id;                                   \
          __list->head = __new_id;                                            \
          _UPF_LLIST_LIST_ASSERT_CHANGE_COUNT (LIST, 1);                      \
        }                                                                     \
      else                                                                    \
        {                                                                     \
          u32 __head_id = __list->head;                                       \
          typeof (VEC) __head_el = __upf_llist_get (VEC, __head_id);          \
                                                                              \
          upf_llist_insert_before (VEC, ANCHOR, LIST, __head_el, __new_el);   \
          if (MAKE_HEAD)                                                      \
            __list->head = __new_id;                                          \
        }                                                                     \
    }                                                                         \
  while (0)

#define upf_llist_insert_tail(VEC, ANCHOR, LIST, NEW)                         \
  _upf_llist_insert_rel_to_head (VEC, ANCHOR, LIST, 0, NEW)
#define upf_llist_insert_head(VEC, ANCHOR, LIST, NEW)                         \
  _upf_llist_insert_rel_to_head (VEC, ANCHOR, LIST, 1, NEW)

#define upf_llist_remove(VEC, ANCHOR, LIST, ELEMENT)                          \
  do                                                                          \
    {                                                                         \
      typeof (VEC) __el = ELEMENT;                                            \
      u32 __el_idx = __el - VEC;                                              \
                                                                              \
      ASSERT (LIST);                                                          \
      ASSERT (VEC);                                                           \
      ASSERT (ELEMENT);                                                       \
      ASSERT (__el->ANCHOR.next != ~0);                                       \
      ASSERT (__el->ANCHOR.prev != ~0);                                       \
      ASSERT (LIST->head != ~0);                                              \
      ASSERT (upf_llist_el_is_part_of_list (ANCHOR, __el));                   \
      ASSERT (!upf_llist_list_is_empty (LIST));                               \
                                                                              \
      /* If list has only one element */                                      \
      if (__el->ANCHOR.next == __el_idx)                                      \
        {                                                                     \
          LIST->head = ~0;                                                    \
        }                                                                     \
      else                                                                    \
        {                                                                     \
          typeof (VEC) __next_el = __upf_llist_get (VEC, __el->ANCHOR.next);  \
          typeof (VEC) __prev_el = __upf_llist_get (VEC, __el->ANCHOR.prev);  \
          ASSERT (upf_llist_el_is_part_of_list (ANCHOR, __next_el));          \
          ASSERT (upf_llist_el_is_part_of_list (ANCHOR, __prev_el));          \
                                                                              \
          /* __next and __prev can be same element, */                        \
          __next_el->ANCHOR.prev = __el->ANCHOR.prev;                         \
          __prev_el->ANCHOR.next = __el->ANCHOR.next;                         \
                                                                              \
          if (LIST->head == __el_idx)                                         \
            {                                                                 \
              LIST->head = __next_el - VEC;                                   \
            }                                                                 \
        }                                                                     \
      upf_llist_anchor_init (ANCHOR, ELEMENT);                                \
                                                                              \
      _UPF_LLIST_LIST_ASSERT_CHANGE_COUNT (LIST, -1);                         \
    }                                                                         \
  while (0)

#define _upf_llist_foreach_next(VAR, VEC, ANCHOR)                             \
  ({                                                                          \
    typeof (VEC) __cur;                                                       \
    if (VAR == __last) /* looped over */                                      \
      __cur = NULL;                                                           \
    else                                                                      \
      {                                                                       \
        __cur = __next;                                                       \
        __next = __upf_llist_get (__vec, __next->ANCHOR.next);                \
        ASSERT (upf_llist_el_is_part_of_list (ANCHOR, __cur));                \
      }                                                                       \
                                                                              \
    __cur;                                                                    \
  })

// Should be safe to remove current VAR element in this loop body.
// For this maintain __next and __last elements during loop.
#define upf_llist_foreach(VAR, VEC, ANCHOR, LIST)                             \
  if (!upf_llist_list_is_empty (LIST))                                        \
    for (typeof (VEC) __vec = VEC,                                            \
                      VAR = __upf_llist_get (__vec, (LIST)->head),            \
                      __next = __upf_llist_get (__vec, VAR->ANCHOR.next),     \
                      __last = __upf_llist_get (__vec, VAR->ANCHOR.prev);     \
         VAR != NULL; VAR = _upf_llist_foreach_next (VAR, VEC, ANCHOR))

#define upf_llist_head(VEC, LIST)                                             \
  ({                                                                          \
    typeof (VEC) _rv = NULL;                                                  \
    u32 __head_idx = (LIST)->head;                                            \
    if (__head_idx != (~0))                                                   \
      _rv = __upf_llist_get (VEC, __head_idx);                                \
                                                                              \
    (_rv);                                                                    \
  })

#define upf_llist_tail(VEC, LIST, ANCHOR)                                     \
  ({                                                                          \
    typeof (VEC) _rv = NULL;                                                  \
    u32 __head_idx = (LIST)->head;                                            \
    if (__head_idx != (~0))                                                   \
      {                                                                       \
        typeof (VEC) __head_el = __upf_llist_get (VEC, __head_idx);           \
        _rv = (__upf_llist_get (VEC, __head_el->ANCHOR.prev));                \
      }                                                                       \
                                                                              \
    (_rv);                                                                    \
  })

/* Create type aliases for specific type */
#define UPF_HEADLESS_LLIST_TEMPLATE_TYPES(NAME)                               \
  typedef upf_llist_anchor_t NAME##_anchor_t;

/* Create type aliases for specific type */
#define UPF_LLIST_TEMPLATE_TYPES(NAME)                                        \
  typedef upf_llist_t NAME##_t;                                               \
  typedef upf_llist_anchor_t NAME##_anchor_t;

#define UPF_LLIST_HEADLESS_TEMPLATE_DEFINITIONS(NAME, TYPE, ANCHOR)           \
  static inline void __clib_unused NAME##_el_init (TYPE *el)                  \
  {                                                                           \
    upf_llist_anchor_init (ANCHOR, el);                                       \
  }                                                                           \
  static bool __clib_unused NAME##_el_is_part_of_list (TYPE *el)              \
  {                                                                           \
    return upf_llist_el_is_part_of_list (ANCHOR, el);                         \
  }                                                                           \
  satic void __clib_unused NAME##_init_list (TYPE *vec, TYPE *el)             \
  {                                                                           \
    ASSERT (!NAME##_el_is_part_of_list (el));                                 \
    el->ANCHOR.next = el->ANCHOR.prev = el - VEC;                             \
  }                                                                           \
  static bool __clib_unused NAME##_insert_before (TYPE *vec, TYPE *base,      \
                                                  TYPE *el)                   \
  {                                                                           \
    upf_llist_el_insert_before (vec, ANCHOR, el, NEW);                        \
  }                                                                           \
  static bool __clib_unused NAME##_insert_after (TYPE *vec, TYPE *base,       \
                                                 TYPE *el)                    \
  {                                                                           \
    upf_llist_el_insert_after (vec, ANCHOR, el, NEW);                         \
  }

/* Create methods instead of macros for type verification */
#define UPF_LLIST_TEMPLATE_DEFINITIONS(NAME, TYPE, ANCHOR)                    \
  static inline void __clib_unused NAME##_init (NAME##_t *list)               \
  {                                                                           \
    upf_llist_init (list);                                                    \
  }                                                                           \
  static inline void __clib_unused NAME##_anchor_init (TYPE *el)              \
  {                                                                           \
    upf_llist_anchor_init (ANCHOR, el);                                       \
  }                                                                           \
  static bool __clib_unused NAME##_is_empty (NAME##_t *list)                  \
  {                                                                           \
    return upf_llist_list_is_empty (list);                                    \
  }                                                                           \
  static bool __clib_unused NAME##_el_is_part_of_list (TYPE *el)              \
  {                                                                           \
    return upf_llist_el_is_part_of_list (ANCHOR, el);                         \
  }                                                                           \
  static void __clib_unused NAME##_insert_head (TYPE *vec, NAME##_t *list,    \
                                                TYPE *el)                     \
  {                                                                           \
    upf_llist_insert_head (vec, ANCHOR, list, el);                            \
  }                                                                           \
  static void __clib_unused NAME##_insert_tail (TYPE *vec, NAME##_t *list,    \
                                                TYPE *el)                     \
  {                                                                           \
    upf_llist_insert_tail (vec, ANCHOR, list, el);                            \
  }                                                                           \
  static void __clib_unused NAME##_insert_before (TYPE *vec, NAME##_t *list,  \
                                                  TYPE *base, TYPE *el)       \
  {                                                                           \
    upf_llist_insert_before (vec, ANCHOR, list, base, el);                    \
  }                                                                           \
  static void __clib_unused NAME##_insert_after (TYPE *vec, NAME##_t *list,   \
                                                 TYPE *base, TYPE *el)        \
  {                                                                           \
    upf_llist_insert_after (vec, ANCHOR, list, base, el);                     \
  }                                                                           \
  static void __clib_unused NAME##_remove (TYPE *vec, NAME##_t *list,         \
                                           TYPE *el)                          \
  {                                                                           \
    upf_llist_remove (vec, ANCHOR, list, el);                                 \
  }                                                                           \
  static TYPE *__clib_unused NAME##_head (TYPE *vec, NAME##_t *list)          \
  {                                                                           \
    return upf_llist_head (vec, list);                                        \
  }                                                                           \
  static TYPE *__clib_unused NAME##_tail (TYPE *vec, NAME##_t *list)          \
  {                                                                           \
    return upf_llist_tail (vec, list, ANCHOR);                                \
  }

#endif // UPF_UTILS_LLIST_H_
