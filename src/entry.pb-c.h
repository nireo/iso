/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: entry.proto */

#ifndef PROTOBUF_C_entry_2eproto__INCLUDED
#define PROTOBUF_C_entry_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct Entry Entry;


/* --- enums --- */


/* --- messages --- */

struct  Entry
{
  ProtobufCMessage base;
  size_t n_volumes;
  char **volumes;
  char *hash;
  int32_t deleted;
};
#define ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&entry__descriptor) \
    , 0,NULL, (char *)protobuf_c_empty_string, 0 }


/* Entry methods */
void   entry__init
                     (Entry         *message);
size_t entry__get_packed_size
                     (const Entry   *message);
size_t entry__pack
                     (const Entry   *message,
                      uint8_t             *out);
size_t entry__pack_to_buffer
                     (const Entry   *message,
                      ProtobufCBuffer     *buffer);
Entry *
       entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   entry__free_unpacked
                     (Entry *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Entry_Closure)
                 (const Entry *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor entry__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_entry_2eproto__INCLUDED */
