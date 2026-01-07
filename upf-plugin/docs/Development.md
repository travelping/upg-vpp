# Development Guide

This guide outlines key development practices, architectural patterns, and conventions for developers working on the User Plane Function (UPF) module for Vector Packet Processor (VPP).

## Table of Contents
- [Testing](#Testing)
- [Packet metadata](#Packet-metadata)
- [Naming convention](#Naming-convention)
- [Multithreading](#Multithreading)
  - [Core](#Core)
  - [Handoff](#Handoff)
  - [Allocation](#Allocation)
  - [Event delivery](#Event-delivery)
  - [Memory update during event transfer](#Memory-update-during-event-transfer)
  - [Typical example of events communication](#Typical-example-of-events-communication)
- [Objects management](#Objects-management)
  - [Local Ids](#Local-Ids)
  - [Session update procedure](#Session-update-procedure)
- [Utilities](#Utilities)
  - [Intrusive linked list](#Intrusive-linked-list)
  - [Worker pool](#Worker-pool)

## Testing

Simplest way to run tests in docker is to use such script:

```bash
# Use docker
export UPG_BUILDENV=docker
# Filter specific test
# export E2E_FOCUS='PGW.*IPv4.*counts ICMP echo requests and responses'
# Create and keep test artifacts
export E2E_KEEP_ALL_ARTIFACTS=y
export E2E_ARTIFACTS_DIR=/src/artifacts
# Create ./artifacts/test_name/dispatch-trace.pcap
export E2E_DISPATCH_TRACE=y
# Speed up some downloading tests
export E2E_QUICK=y
# Do multithreading
export E2E_MULTICORE=y

# run tests
make e2e
```

It will start docker container from development image, build project from sources and start e2e tests against it.

## Packet metadata

UPF injects multiple entry points into UPF subgraph using [FIB DPO entires][vpp-fib-dataplane] or [punt](vpp-punt). After packet reaches UPF node, custom packet opaque metadata (of type `vnet_buffer_opaque2_t`) is populated with UPF specific metadata like `session_id` or `flow_id`. This metadata depends on node order and extended as packet traverses it.

## Naming convention

To keep naming predictable some recommendation to naming are established.

Static methods should be prefixed with underscore (`_`) to indicate locality.

Because of huge amount of objects, specific lifespan management naming scheme is recommended:
- `{ns}_{object}_new` - only allocation
- `{ns}_{object}_free` - only deallocation
- `{ns}_{object}_init` - initialization of already allocated or global object
- `{ns}_{object}_deinit` - deinitialization without deallocation
- `{ns}_{object}_create` - allocation + initialization
- `{ns}_{object}_delete` - deinitialization + deallocation
- `{ns}_{object}_get` - get using objects unique object key or id
- `{ns}_{object}_get_by_{key}` - get using key
- `{ns}_{object}_search_by_{key}` - same as `get`, but implies that operation is not constant, like loop
- `{ns}_{object}_get_{subtype}_by_{key}` - get specific subobject by key
- `{ns}_{object}_ensure_{subtype}_by_{key}` - get or create if not exists
- `{ns}_{object}_ref_{subtype}_by_{key}` - reference object
- `{ns}_{object}_unref_{subtype}_by_{key}` - dereference object with possible deallocation

Examples: `_upf_nwi_ensure_by_name`, `flowtable_get_flow_by_id`, `upf_session_deinit`.

## Multithreading

### Core

Multithreading is implemented by assigning sessions to threads and keeping all information related to that session locally on assigned thread. This per thread information (only worker thread is allowed to be modify it) includes: flow table and flows (nat, proxy), URRs state and etc.

Worker objects management is done using asynchronous lifecycle when first object allocated on main thread, then information about them transferred to worker threads, and after acknowledge received by main thread these objects are allowed to participate in forwarding. Same thing done in reverse during destruction: disable forwarding, request objects removal, wait for acknowledge, deallocate on main thread. Such system allows to avoid most of spinlocks and simplifies management.

Forwarding of traffic to workers is done by using global maps which contain destination thread with other information.

### Handoff

Handoff to assigned thread is done only once and as early as possible, when target thread is known. Once a packet is handed off to its assigned worker thread, no further state specific to this packet is transferred between threads. The target worker thread should repeat the same thread lookup to extract fresh forwarding information, which could be changed during handoff.

### Allocation

Most of objects are allocated in pools on main thread when possible. For thread safety worker barrier is used if reallocation is needed. Because of shared global pools such worker barriers will be needed only few times before pools reach some stable size. If objects need to be modified by worker threads (like URRs or flows structure), then such objects should be allocated using per-thread pools, or should use CACHE_LINE alignment, to avoid false sharing and need of spinlocks.

### Event delivery

VPPs built-in RPC was found to be overly complex for UPF needs, so own multithreading event system is implemented. It is much simpler and always guarantee delivery and order. During send and receive memory fencing is used to ensure that all changes in memory made by main thread are visible to destination worker thread and vice versa.

### Memory update during event transfer

This is example of a sequence of events during event transfer which ensures that worker threads receive udpated rules.

| Action | Main thread view (caches) | Memory | Worker thread view (caches) |
|--------|---------------------------|--------|-----------------------------|
| Rules initialization | Correct | Outdated | Outdated |
| Cache flush before sending event | Correct | Correct | Outdated |
| Event sending. Ownership of rules is transferred to worker | Correct | Correct | Outdated |
| Worker receives event and flushes caches | Correct | Correct | Correct |

### Typical example of events communication

Here is example of communication between PFCP endpoint, Main thread, Worker threads and dataplane interfaces with user traffic. Session first created and then Usage Report is sent for session.

```
PFCP   Main  Worker  Traffic || Notes:
 |      |      |       |     ||
 |---->>|      |       |     || - Session Establishment Request received from PFCP.
 |      #      |       |     || # Session creation, rules creation.
 |      #      |       |     || # Global tables do not allow traffic forwarding yet.
 |      |---->>|       |     || - Session creation event to worker thread.
 |      |      #       |     || # Worker acknowledges creation, creates timers and etc.
 |      |<<----|       |     || - Session creation event to main thread.
 |      #      |       |     || # Now main thread enables traffic forwarding to workers
 |      #      |       |     ||   by updating global tables with session and thread indexes.
 |<<----|      |       |     || - Response sent to PFCP endpoint.
 |      |      |<<-----|     || - User traffic is received on worker thread.
 |      |      #       |     || # Worker checks thread index and if needed performs
 |      |      |----┐  |     ||   handower of packet to different worker thread.
 |      |      |<<--┘  |     || - Handower of packet to proper thread.
 |      |      #       |     || # Worker performs packet processing with possibilty
 |      |      #       |     ||   of generating Usage Report.
 |      |<<----|       |     || - Usage Report event sent to main thread.
 |      |      |----->>|     || - Processed packets sent to outgoing interface.
 |<<----|      |       |     || - Session Report Request is sent to PFCP.
 |---->>|      |       |     || - Session Report Response is received from PFCP.
```

Here is more complex example, where collision between procedures happens and Session Modification Request with Remove URR was received on main thread during Usage Report trigger for this URR on worker thread. Main thread keeps both old and new rules, what allows to perform operations in parallel.

```
PFCP   Main  Worker  Traffic || Notes:
 |      |      |       |     ||
 |      |      |<<-----|     || - User traffic reaches worker and triggers Usage Report.
 |      |      #       |     || # Worker generates Usage Report.
 |      |<<----|       |     || - Usage Report sent to main thread.
 |      |      |----->>|     || - Packet forwarded according to rules.
 |---->>|      |       |     || - Session Modification Request received from PFCP.
 |      #      |       |     || # Main thread updates rules and sends event to worker.
 |      |---->>|       |     || - Session modification event sent to worker thread.
 |      #      |       |     || # Now main tread processes Usage Report event and processes
 |      #      |       |     ||   it against previous rules, since worker haven't acknowledged
 |      #      |       |     ||   new rules yet.
 |<<----|      |       |     || - Session Report Request sent to PFCP.
 |      |      #       |     || # Worker acknowledes new rules.
 |      |<<----|       |     || - Worker sends session updated acknowledgment event.
 |<<----|      |       |     || - Session Modification Response sent to PFCP.
 |---->>|      |       |     || - Session Report Response received from PFCP.
```

## Objects management

### Local Ids

Because lots of objects are required to be managed per sessions, it is beneficial if specific convention will be followed.

Session objects (like PDR or FAR) are called "Local" and indexed using "Local IDs", LIDs for short or via type `upf_lid_t`. For simplicity we limit total amount of local objects to 32-128 elements. This allows to store multiple objects indexes in 32-128 bits set without allocation of clib_bitmaps and indirection in runtime. A lot of code depends on such sets of LIDs and use `upf_lidset_t` type for this.

Local per session pools are allocated in global pools using `vppinfra/heap.h` structure, which allows to allocate multiple elements in vector sequentially. To manage such "vector inside vector" allocations UPF implements `upf_heap_handle_t` or `upf_hh_t` optimized wrapper around VPP heap handler.

For example, when session needs multple PDRs, instead of allocating each PDR individually from global pool, the session requests contiguous block of PDRs. `upf_heap_handle_t` would then point to the start and size of this block within the global pool. This is like having a small, private vector of PDRs for the session, allocated from a larger shared heap/pool of PDRs.

LIDs which are in use by worker threads can benefit from "pool" behavior, when allocated objects do not change index between updates during lifetime. Contrary to this during session rules update it is convenient to use usual "vector", since it has no gaps between objects. To indicate this difference with LIDs special kind of local index is defined as XID. Type `upf_xid_t` is used during rules creation/removal to indicate temporary update index, which will be remapped after rules creation to allocated or reused `upf_lid_t` index.

### Session update procedure

Session update procedure (or `sxu`) structure represents temporary state needed during session rules update. It contains created, modified and removed objects state. After procedure temporary state is freed and only resulted rules are kept.

Session modification is more complex, and rarely tested. Because of this one of `sxu` procedure goal is to do rules creation and removal the same way as modification, and reuse modification code path for creation and removal as much as possible. This is done by removing modification step as early as possible and replacing it with creation or removal of dynamic objects.

Additonally to PFCP objects, separated local object is managed for each global object reference (like FIB entry or TEID allocation). This helps to cover lots of ownership cases when multiple local objects reference the same global object. Like when multiple PDRs use the same TEID allocation. Such objects reuse the same infra as PFCP objects, but created and removed using reference counts.

Because order of objects creation is not known, they are managed "lazely" using `slots` structure. The slots structure acts as a placeholder, storage and dependency resolver for objects during rule updates. During object creations references to other objects are always successful and result in creation of `slot` structure, which contains requested object key without populating values. `slot` structure ensures valid `xid` index for objects before their creation, allowing to reference not yet created objects. Later unprovided `slots` are fulfilled, and if it is not possible to fullfil such slot key, then then procedure fails. For example when reference to invalid NAT pool is requested.

Schematic example of PDR 42 referencing URRs 100 and 200 before they are created:

```yaml
slots_PDRs:
- key: { pfcp_id: 42 }
  value:
    pdi: { ... }
    urrs: [0, 1]
slots_URRs:
- key: { pfcp_id: 100 }
  value: not yet provided
- key: { pfcp_id: 200 }
  value: not yet provided
```

## Utilities

### Intrusive linked list

Usually it is not adviced to use linked lists on their own due to cache locality issues. But linked lists sometimes have huge advantages in insertion or removal operations compared to vector-based collections.

For such cases UPF implements own version of intrusive linked list - `upf_llist_t` for objects managed in vectors or pools. Additionally, for typesafety there are `UPF_LLIST_TEMPLATE_*` macros to create inline wrappers around linked list.

Only doubly linked list implementation is provided, since singly linked are often not practical due to O(n) runtime cost for element removal.

### Worker pool

Scenarios when the main thread pre-allocates elements in a global pool for a worker typically require avoiding cache line contention. Traditional approaches include:
  - **Per-worker pools** - requires per-worker pool and per-worker ID management which increases complexity
  - **Cache-line-aligned elements** - wastes space by padding each element to cache line size

The `upf_worker_pool` implementation solves these drawbacks. It packs allocated elements into cache-line-aligned blocks assigned to specific workers. The only additional requirement compared to basic VPP pool is thread index argument during allocation. See `upf/utils/worker_pool.h` for implementation details.

[vpp-fib-dataplane]: https://s3-docs.fd.io/vpp/24.02/developer/corefeatures/fib/dataplane.html (FPP FIB dataplane Documentation)
[vpp-punt]: https://s3-docs.fd.io/vpp/24.02/developer/corefeatures/punt.html (FPP Punt Documentation)
