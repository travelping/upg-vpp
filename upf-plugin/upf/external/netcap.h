#ifndef __included_netcap_exports_h__
#define __included_netcap_exports_h__

#define NETCAP_PLUGIN_EXTERNAL_EXPORTS

#include <stdbool.h>
#include <vlib/vlib.h>

typedef u8 netcap_class_id_t;
typedef u16 netcap_stream_id_t;

typedef struct netcap_v1_dump_context_t_
{
  u32 writer_pos;
  u32 reader_pos;
  u8 *ring_mem;
  struct netcap_ring_t_ *ring;
  struct netcap_ring_header_t_ *sh_ring;
  u16 thread_index;
  u8 shared_packet_flags;
} netcap_v1_dump_context_t;

typedef clib_error_t *(*netcap_plugin_v1_add_metadata_fn_t) (u8 **output,
                                                             const char *key,
                                                             const u8 *val,
                                                             u8 val_len);

typedef clib_error_t *(*netcap_plugin_v1_register_class_fn_t) (
  const char *name, u8 packet_metadata_size, netcap_class_id_t *result_class);

typedef clib_error_t *(*netcap_plugin_v1_create_stream_fn_t) (
  netcap_stream_id_t *, netcap_class_id_t class_id, u8 *interface, u8 *target,
  u8 *metadata);

typedef void (*netcap_plugin_v1_delete_stream_fn_t) (
  netcap_stream_id_t stream_id);

typedef bool (*netcap_plugin_v1_dump_context_init_fn_t) (
  netcap_v1_dump_context_t *ctx, u32 thread_index, bool is_rx);

typedef bool (*netcap_plugin_v1_dump_context_capture_fn_t) (
  netcap_v1_dump_context_t *ctx, netcap_class_id_t class_id,
  netcap_stream_id_t stream_id, u64 now_unix_ns, void **dst_data,
  u32 data_bytes, u16 data_orig_bytes, void **dst_metadata,
  u8 packet_metadata_size);

typedef void (*netcap_plugin_v1_dump_context_flush_fn_t) (
  netcap_v1_dump_context_t *ctx);

typedef struct netcap_plugin_methods_t_
{
  netcap_plugin_v1_add_metadata_fn_t add_metadata;

  netcap_plugin_v1_register_class_fn_t register_class;

  netcap_plugin_v1_create_stream_fn_t create_stream;
  netcap_plugin_v1_delete_stream_fn_t delete_stream;

  netcap_plugin_v1_dump_context_init_fn_t dump_context_init;
  netcap_plugin_v1_dump_context_capture_fn_t dump_context_capture;
  netcap_plugin_v1_dump_context_flush_fn_t dump_context_flush;
} netcap_plugin_methods_t;

typedef clib_error_t *(*netcap_plugin_v1_methods_vtable_init_fn_t) (
  netcap_plugin_methods_t *m);

#endif
