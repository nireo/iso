// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: entry.proto

#include "entry.pb.h"

#include <algorithm>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
#include <google/protobuf/wire_format_lite.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG

namespace _pb = ::PROTOBUF_NAMESPACE_ID;
namespace _pbi = _pb::internal;

PROTOBUF_CONSTEXPR Entry::Entry(::_pbi::ConstantInitialized)
    : _impl_{
          /*decltype(_impl_.volumes_)*/ {}, /*decltype(_impl_.hash_)*/
          {&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}},
          /*decltype(_impl_.deleted_)*/ 0,
          /*decltype(_impl_._cached_size_)*/ {}} {}
struct EntryDefaultTypeInternal {
  PROTOBUF_CONSTEXPR EntryDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~EntryDefaultTypeInternal() {}
  union {
    Entry _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT
    PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 EntryDefaultTypeInternal
        _Entry_default_instance_;
static ::_pb::Metadata file_level_metadata_entry_2eproto[1];
static constexpr ::_pb::EnumDescriptor const *
    *file_level_enum_descriptors_entry_2eproto = nullptr;
static constexpr ::_pb::ServiceDescriptor const *
    *file_level_service_descriptors_entry_2eproto = nullptr;

const uint32_t TableStruct_entry_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(
    protodesc_cold) = {
    ~0u, // no _has_bits_
    PROTOBUF_FIELD_OFFSET(::Entry, _internal_metadata_),
    ~0u, // no _extensions_
    ~0u, // no _oneof_case_
    ~0u, // no _weak_field_map_
    ~0u, // no _inlined_string_donated_
    PROTOBUF_FIELD_OFFSET(::Entry, _impl_.volumes_),
    PROTOBUF_FIELD_OFFSET(::Entry, _impl_.hash_),
    PROTOBUF_FIELD_OFFSET(::Entry, _impl_.deleted_),
};
static const ::_pbi::MigrationSchema
    schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
        {0, -1, -1, sizeof(::Entry)},
};

static const ::_pb::Message *const file_default_instances[] = {
    &::_Entry_default_instance_._instance,
};

const char descriptor_table_protodef_entry_2eproto[] PROTOBUF_SECTION_VARIABLE(
    protodesc_cold) =
    "\n\013entry.proto\"7\n\005Entry\022\017\n\007volumes\030\001 \003(\t\022"
    "\014\n\004hash\030\002 \001(\t\022\017\n\007deleted\030\003 "
    "\001(\005b\006proto3";
static ::_pbi::once_flag descriptor_table_entry_2eproto_once;
const ::_pbi::DescriptorTable descriptor_table_entry_2eproto = {
    false,
    false,
    78,
    descriptor_table_protodef_entry_2eproto,
    "entry.proto",
    &descriptor_table_entry_2eproto_once,
    nullptr,
    0,
    1,
    schemas,
    file_default_instances,
    TableStruct_entry_2eproto::offsets,
    file_level_metadata_entry_2eproto,
    file_level_enum_descriptors_entry_2eproto,
    file_level_service_descriptors_entry_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::_pbi::DescriptorTable *
descriptor_table_entry_2eproto_getter() {
  return &descriptor_table_entry_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY2 static ::_pbi::AddDescriptorsRunner
    dynamic_init_dummy_entry_2eproto(&descriptor_table_entry_2eproto);

// ===================================================================

class Entry::_Internal {
public:
};

Entry::Entry(::PROTOBUF_NAMESPACE_ID::Arena *arena, bool is_message_owned)
    : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:Entry)
}
Entry::Entry(const Entry &from) : ::PROTOBUF_NAMESPACE_ID::Message() {
  Entry *const _this = this;
  (void)_this;
  new (&_impl_) Impl_{decltype(_impl_.volumes_){from._impl_.volumes_},
                      decltype(_impl_.hash_){}, decltype(_impl_.deleted_){},
                      /*decltype(_impl_._cached_size_)*/ {}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(
      from._internal_metadata_);
  _impl_.hash_.InitDefault();
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.hash_.Set("", GetArenaForAllocation());
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_hash().empty()) {
    _this->_impl_.hash_.Set(from._internal_hash(),
                            _this->GetArenaForAllocation());
  }
  _this->_impl_.deleted_ = from._impl_.deleted_;
  // @@protoc_insertion_point(copy_constructor:Entry)
}

inline void Entry::SharedCtor(::_pb::Arena *arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{decltype(_impl_.volumes_){arena},
                      decltype(_impl_.hash_){}, decltype(_impl_.deleted_){0},
                      /*decltype(_impl_._cached_size_)*/ {}};
  _impl_.hash_.InitDefault();
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.hash_.Set("", GetArenaForAllocation());
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

Entry::~Entry() {
  // @@protoc_insertion_point(destructor:Entry)
  if (auto *arena =
          _internal_metadata_
              .DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
    (void)arena;
    return;
  }
  SharedDtor();
}

inline void Entry::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.volumes_.~RepeatedPtrField();
  _impl_.hash_.Destroy();
}

void Entry::SetCachedSize(int size) const { _impl_._cached_size_.Set(size); }

void Entry::Clear() {
  // @@protoc_insertion_point(message_clear_start:Entry)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void)cached_has_bits;

  _impl_.volumes_.Clear();
  _impl_.hash_.ClearToEmpty();
  _impl_.deleted_ = 0;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char *Entry::_InternalParse(const char *ptr, ::_pbi::ParseContext *ctx) {
#define CHK_(x)                                                                \
  if (PROTOBUF_PREDICT_FALSE(!(x)))                                            \
  goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
    // repeated string volumes = 1;
    case 1:
      if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
        ptr -= 1;
        do {
          ptr += 1;
          auto str = _internal_add_volumes();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
          CHK_(::_pbi::VerifyUTF8(str, "Entry.volumes"));
          if (!ctx->DataAvailable(ptr))
            break;
        } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<10>(ptr));
      } else
        goto handle_unusual;
      continue;
    // string hash = 2;
    case 2:
      if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
        auto str = _internal_mutable_hash();
        ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
        CHK_(ptr);
        CHK_(::_pbi::VerifyUTF8(str, "Entry.hash"));
      } else
        goto handle_unusual;
      continue;
    // int32 deleted = 3;
    case 3:
      if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 24)) {
        _impl_.deleted_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint32(&ptr);
        CHK_(ptr);
      } else
        goto handle_unusual;
      continue;
    default:
      goto handle_unusual;
    } // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_
            .mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  } // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t *Entry::_InternalSerialize(
    uint8_t *target,
    ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream *stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:Entry)
  uint32_t cached_has_bits = 0;
  (void)cached_has_bits;

  // repeated string volumes = 1;
  for (int i = 0, n = this->_internal_volumes_size(); i < n; i++) {
    const auto &s = this->_internal_volumes(i);
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
        s.data(), static_cast<int>(s.length()),
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
        "Entry.volumes");
    target = stream->WriteString(1, s, target);
  }

  // string hash = 2;
  if (!this->_internal_hash().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
        this->_internal_hash().data(),
        static_cast<int>(this->_internal_hash().length()),
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
        "Entry.hash");
    target = stream->WriteStringMaybeAliased(2, this->_internal_hash(), target);
  }

  // int32 deleted = 3;
  if (this->_internal_deleted() != 0) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteInt32ToArray(
        3, this->_internal_deleted(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_
            .unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(
                ::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance),
        target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:Entry)
  return target;
}

size_t Entry::ByteSizeLong() const {
  // @@protoc_insertion_point(message_byte_size_start:Entry)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void)cached_has_bits;

  // repeated string volumes = 1;
  total_size += 1 * ::PROTOBUF_NAMESPACE_ID::internal::FromIntSize(
                        _impl_.volumes_.size());
  for (int i = 0, n = _impl_.volumes_.size(); i < n; i++) {
    total_size += ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        _impl_.volumes_.Get(i));
  }

  // string hash = 2;
  if (!this->_internal_hash().empty()) {
    total_size +=
        1 + ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
                this->_internal_hash());
  }

  // int32 deleted = 3;
  if (this->_internal_deleted() != 0) {
    total_size +=
        ::_pbi::WireFormatLite::Int32SizePlusOne(this->_internal_deleted());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData Entry::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck, Entry::MergeImpl};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData *Entry::GetClassData() const {
  return &_class_data_;
}

void Entry::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message &to_msg,
                      const ::PROTOBUF_NAMESPACE_ID::Message &from_msg) {
  auto *const _this = static_cast<Entry *>(&to_msg);
  auto &from = static_cast<const Entry &>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:Entry)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void)cached_has_bits;

  _this->_impl_.volumes_.MergeFrom(from._impl_.volumes_);
  if (!from._internal_hash().empty()) {
    _this->_internal_set_hash(from._internal_hash());
  }
  if (from._internal_deleted() != 0) {
    _this->_internal_set_deleted(from._internal_deleted());
  }
  _this->_internal_metadata_
      .MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(
          from._internal_metadata_);
}

void Entry::CopyFrom(const Entry &from) {
  // @@protoc_insertion_point(class_specific_copy_from_start:Entry)
  if (&from == this)
    return;
  Clear();
  MergeFrom(from);
}

bool Entry::IsInitialized() const { return true; }

void Entry::InternalSwap(Entry *other) {
  using std::swap;
  auto *lhs_arena = GetArenaForAllocation();
  auto *rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  _impl_.volumes_.InternalSwap(&other->_impl_.volumes_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.hash_, lhs_arena, &other->_impl_.hash_, rhs_arena);
  swap(_impl_.deleted_, other->_impl_.deleted_);
}

::PROTOBUF_NAMESPACE_ID::Metadata Entry::GetMetadata() const {
  return ::_pbi::AssignDescriptors(&descriptor_table_entry_2eproto_getter,
                                   &descriptor_table_entry_2eproto_once,
                                   file_level_metadata_entry_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
PROTOBUF_NAMESPACE_OPEN
template <>
PROTOBUF_NOINLINE ::Entry *Arena::CreateMaybeMessage<::Entry>(Arena *arena) {
  return Arena::CreateMessageInternal<::Entry>(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
