#include "vppinfra/error_bootstrap.h"
#include "vppinfra/types.h"
#include "vppinfra/clib.h"
#include "vppinfra/pool.h"
#include <stdbool.h>

/*
This is analog of vpp dlist, but intrusive version with anchor.
Also this implementation can create typed helpers.
*/

#if CLIB_ASSERT_ENABLE
  /* llist debug adds count field to list to verify it's length */
  // #define UPF_LLIST_DEBUG
#endif

typedef struct {
  /*
    if empty, then ~0
    if non empty, then idx of element
  */
  u32 head;
#ifdef UPF_LLIST_DEBUG
  u32 count;
#endif
} upf_llist_t;

typedef struct {
  /*
    if not in a list, next = ~0 and prev = ~0
    if single element in list next = this el, prev = this el
    if in list next = next el, prev = prev el
  */
  u32 next;
  u32 prev;
} upf_llist_anchor_t;

#ifdef UPF_LLIST_DEBUG
  #define _UPF_LLIST_LIST_ASSERT_CHANGE_COUNT(LIST, CHANGE) do { \
    LIST->count += (CHANGE); \
    ASSERT(LIST->count + 1 != 0); \
  } while (0)
#else
  #define _UPF_LLIST_LIST_ASSERT_CHANGE_COUNT(LIST, CHANGE) {}
#endif

static void
upf_llist_init(upf_llist_t *list) {
  list->head = ~0;
#ifdef UPF_LLIST_DEBUG
  list->count = 0;
#endif
}

static bool
upf_llist_list_is_empty(upf_llist_t *list) {
#ifdef UPF_LLIST_DEBUG
  ASSERT((list->head != ~0) == (list->count != 0));
#endif
  return list->head == ~0;
}

static void
_upf_llist_anchor_init(upf_llist_anchor_t *anchor) {
  anchor->next = ~0;
  anchor->prev = ~0;
}

static bool
_upf_llist_anchor_inserted(upf_llist_anchor_t *anchor) {
#ifdef UPF_LLIST_DEBUG
  ASSERT((anchor->next != ~0) == (anchor->prev != ~0));
#endif
  return anchor->next != ~0;
}

/*
  Conflicts with pfcp msg pool
  #define __upf_llist_get(POOL, INDEX) (pool_elt_at_index(POOL, INDEX))
*/
#define __upf_llist_get(POOL, INDEX) (&POOL[INDEX])
#define upf_llist_anchor_init(ANCHOR, ELEMENT) _upf_llist_anchor_init(&ELEMENT->ANCHOR);
#define upf_llist_el_is_part_of_list(ANCHOR, ELEMENT) _upf_llist_anchor_inserted(&ELEMENT->ANCHOR)

#define upf_llist_insert_tail(POOL, ANCHOR, LIST, NEW) \
do { \
  typeof(POOL) __new_el = NEW; \
  u32 __new_idx = __new_el - POOL; \
  \
  ASSERT(LIST); \
  ASSERT(POOL); \
  ASSERT(NEW); \
  if (0) { ASSERT(!pool_is_free_index(POOL, __new_idx)); /* Conflicts with pfcp msg pool */ } \
  ASSERT(!upf_llist_el_is_part_of_list(ANCHOR, __new_el)); \
  \
  if (upf_llist_list_is_empty(LIST)) { \
    __new_el->ANCHOR.next = __new_idx; \
    __new_el->ANCHOR.prev = __new_idx; \
    LIST->head = __new_idx; \
  } else { \
    u32 __first_idx = LIST->head; \
    typeof(POOL) __first_el = __upf_llist_get(POOL, __first_idx); \
    u32 __last_idx = __first_el->ANCHOR.prev; \
    typeof(POOL) __last_el = __upf_llist_get(POOL, __last_idx); \
    \
    ASSERT(upf_llist_el_is_part_of_list(ANCHOR, __first_el)); \
    ASSERT(upf_llist_el_is_part_of_list(ANCHOR, __last_el)); \
    \
    __last_el->ANCHOR.next = __new_idx; \
    __first_el->ANCHOR.prev = __new_idx; \
    __new_el->ANCHOR.next = __first_idx; \
    __new_el->ANCHOR.prev = __last_idx; \
  } \
  \
  _UPF_LLIST_LIST_ASSERT_CHANGE_COUNT(LIST, 1); \
} while(0)

#define upf_llist_remove(POOL, ANCHOR, LIST, ELEMENT) \
do { \
  typeof(POOL) __el = ELEMENT; \
  u32 __el_idx = __el - POOL; \
  \
  ASSERT(LIST); \
  ASSERT(POOL); \
  ASSERT(ELEMENT); \
  ASSERT(__el->ANCHOR.next != ~0); \
  ASSERT(__el->ANCHOR.prev != ~0); \
  ASSERT(LIST->head != ~0); \
  if (0) { ASSERT(!pool_is_free_index(POOL, __el_idx)); /* Conflicts with pfcp msg pool */ } \
  ASSERT(upf_llist_el_is_part_of_list(ANCHOR, __el)); \
  ASSERT(!upf_llist_list_is_empty(LIST)); \
  \
  /* If list has only one element */ \
  if (__el->ANCHOR.next == __el_idx) { \
    LIST->head = ~0; \
  } else { \
    typeof(POOL) __next_el = __upf_llist_get(POOL, __el->ANCHOR.next); \
    typeof(POOL) __prev_el = __upf_llist_get(POOL, __el->ANCHOR.prev); \
    ASSERT(upf_llist_el_is_part_of_list(ANCHOR, __next_el)); \
    ASSERT(upf_llist_el_is_part_of_list(ANCHOR, __prev_el)); \
    \
    /* __next and __prev can be same element, */ \
    __next_el->ANCHOR.prev = __el->ANCHOR.prev; \
    __prev_el->ANCHOR.next = __el->ANCHOR.next; \
    \
    if (LIST->head == __el_idx) { \
      LIST->head = __next_el - POOL; \
    } \
  } \
  upf_llist_anchor_init(ANCHOR, ELEMENT); \
  \
  _UPF_LLIST_LIST_ASSERT_CHANGE_COUNT(LIST, -1); \
} while(0)

/* Should be safe to remove current VAR element in this loop body */
#define upf_llist_foreach(VAR, POOL, ANCHOR, LIST, BODY) \
do { \
  upf_llist_t *__list = LIST; \
  /* Save head in case it's removed inside loop */ \
  if (!upf_llist_list_is_empty(__list)) { \
    u32 __head_idx = __list->head; \
    u32 __cur_idx = __head_idx; \
    do { \
      typeof(POOL) __cur_el = __upf_llist_get(POOL, __cur_idx); \
      u32 __next_idx = __cur_el->ANCHOR.next; \
      ASSERT(upf_llist_el_is_part_of_list(ANCHOR, __cur_el)); \
      typeof(POOL) VAR = __cur_el; \
      BODY; \
      __cur_idx = __next_idx; \
    } while (__cur_idx != __head_idx); \
  } \
} while (0)

/* Create type aliases for specific type */
#define UPF_LLIST_TEMPLATE_TYPES(NAME) \
typedef upf_llist_t NAME ## _t; \
typedef upf_llist_anchor_t NAME ## _anchor_t; \

/* Create methods instead of macros for type verification */
#define UPF_LLIST_TEMPLATE_DEFINITIONS(NAME, TYPE, ANCHOR) \
static inline void __clib_unused \
NAME ## _init(NAME ## _t *list) { \
  upf_llist_init(list); \
} \
static void __clib_unused \
NAME ## _anchor_init(TYPE *el) { \
  upf_llist_anchor_init(ANCHOR, el); \
} \
static bool __clib_unused \
NAME ## _is_empty(NAME ## _t *list) { \
  return upf_llist_list_is_empty(list); \
} \
static bool __clib_unused \
NAME ## _el_is_part_of_list(TYPE *el) { \
  return upf_llist_el_is_part_of_list(ANCHOR, el); \
} \
static void __clib_unused \
NAME ## _insert_tail(TYPE *pool, NAME ## _t *list, TYPE *el) { \
  upf_llist_insert_tail(pool, ANCHOR, list, el); \
} \
static void __clib_unused \
NAME ## _remove(TYPE *pool, NAME ## _t *list, TYPE *el) { \
  upf_llist_remove(pool, ANCHOR, list, el); \
}
