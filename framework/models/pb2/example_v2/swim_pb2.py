# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: swim.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import framework.models.pb2.example_v2.athlete_pb2 as athlete__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='swim.proto',
  package='query',
  syntax='proto2',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\nswim.proto\x12\x05query\x1a\rathlete.proto\"\x93\x02\n\x04Swim\x1a\xb3\x01\n\x08\x46\x61\x63ility\x12\x0e\n\x06seg_id\x18\x01 \x02(\r\x12\x0c\n\x04name\x18\x02 \x02(\t\x12\x30\n\x0bhearth_data\x18\x06 \x01(\x0b\x32\x1b.query.Swim.Facility.Hearth\x1aW\n\x06Hearth\x12\x1b\n\x13\x61verage_hearth_rate\x18\x01 \x01(\r\x12\x17\n\x0fmin_hearth_rate\x18\x02 \x01(\r\x12\x17\n\x0fmax_hearth_rate\x18\x03 \x01(\r\x1aU\n\x05Query\x12%\n\x07\x61thlete\x18\x02 \x02(\x0b\x32\x14.query.Athlete.Query\x12%\n\x07segment\x18\x03 \x03(\x0b\x32\x14.query.Swim.Facility'
  ,
  dependencies=[athlete__pb2.DESCRIPTOR,])




_SWIM_FACILITY_HEARTH = _descriptor.Descriptor(
  name='Hearth',
  full_name='query.Swim.Facility.Hearth',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='average_hearth_rate', full_name='query.Swim.Facility.Hearth.average_hearth_rate', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='min_hearth_rate', full_name='query.Swim.Facility.Hearth.min_hearth_rate', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='max_hearth_rate', full_name='query.Swim.Facility.Hearth.max_hearth_rate', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=138,
  serialized_end=225,
)

_SWIM_FACILITY = _descriptor.Descriptor(
  name='Facility',
  full_name='query.Swim.Facility',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='seg_id', full_name='query.Swim.Facility.seg_id', index=0,
      number=1, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='name', full_name='query.Swim.Facility.name', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='hearth_data', full_name='query.Swim.Facility.hearth_data', index=2,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_SWIM_FACILITY_HEARTH, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=46,
  serialized_end=225,
)

_SWIM_QUERY = _descriptor.Descriptor(
  name='Query',
  full_name='query.Swim.Query',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='athlete', full_name='query.Swim.Query.athlete', index=0,
      number=2, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='segment', full_name='query.Swim.Query.segment', index=1,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=227,
  serialized_end=312,
)

_SWIM = _descriptor.Descriptor(
  name='Swim',
  full_name='query.Swim',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[_SWIM_FACILITY, _SWIM_QUERY, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=37,
  serialized_end=312,
)

_SWIM_FACILITY_HEARTH.containing_type = _SWIM_FACILITY
_SWIM_FACILITY.fields_by_name['hearth_data'].message_type = _SWIM_FACILITY_HEARTH
_SWIM_FACILITY.containing_type = _SWIM
_SWIM_QUERY.fields_by_name['athlete'].message_type = athlete__pb2._ATHLETE_QUERY
_SWIM_QUERY.fields_by_name['segment'].message_type = _SWIM_FACILITY
_SWIM_QUERY.containing_type = _SWIM
DESCRIPTOR.message_types_by_name['Swim'] = _SWIM
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Swim = _reflection.GeneratedProtocolMessageType('Swim', (_message.Message,), {

  'Facility' : _reflection.GeneratedProtocolMessageType('Facility', (_message.Message,), {

    'Hearth' : _reflection.GeneratedProtocolMessageType('Hearth', (_message.Message,), {
      'DESCRIPTOR' : _SWIM_FACILITY_HEARTH,
      '__module__' : 'swim_pb2'
      # @@protoc_insertion_point(class_scope:query.Swim.Facility.Hearth)
      })
    ,
    'DESCRIPTOR' : _SWIM_FACILITY,
    '__module__' : 'swim_pb2'
    # @@protoc_insertion_point(class_scope:query.Swim.Facility)
    })
  ,

  'Query' : _reflection.GeneratedProtocolMessageType('Query', (_message.Message,), {
    'DESCRIPTOR' : _SWIM_QUERY,
    '__module__' : 'swim_pb2'
    # @@protoc_insertion_point(class_scope:query.Swim.Query)
    })
  ,
  'DESCRIPTOR' : _SWIM,
  '__module__' : 'swim_pb2'
  # @@protoc_insertion_point(class_scope:query.Swim)
  })
_sym_db.RegisterMessage(Swim)
_sym_db.RegisterMessage(Swim.Facility)
_sym_db.RegisterMessage(Swim.Facility.Hearth)
_sym_db.RegisterMessage(Swim.Query)


# @@protoc_insertion_point(module_scope)
