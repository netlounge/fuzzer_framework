# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: bike.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import framework.models.pb2.example_v2.athlete_pb2 as athlete__pb2
import framework.models.pb2.example_v2.route_pb2 as route__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='bike.proto',
  package='query',
  syntax='proto2',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\nbike.proto\x12\x05query\x1a\rathlete.proto\x1a\x0broute.proto\"\xd8\x02\n\x04\x42ike\x1a\xf9\x01\n\x07Segment\x12\x0e\n\x06seg_id\x18\x01 \x02(\r\x12\x0c\n\x04name\x18\x02 \x02(\t\x12!\n\x05route\x18\x03 \x02(\x0b\x32\x12.query.Route.Query\x12\x11\n\telev_high\x18\x04 \x01(\r\x12\x10\n\x08\x65lev_low\x18\x05 \x01(\r\x12/\n\x0bhearth_data\x18\x06 \x01(\x0b\x32\x1a.query.Bike.Segment.Hearth\x1aW\n\x06Hearth\x12\x1b\n\x13\x61verage_hearth_rate\x18\x01 \x01(\r\x12\x17\n\x0fmin_hearth_rate\x18\x02 \x01(\r\x12\x17\n\x0fmax_hearth_rate\x18\x03 \x01(\r\x1aT\n\x05Query\x12%\n\x07\x61thlete\x18\x02 \x02(\x0b\x32\x14.query.Athlete.Query\x12$\n\x07segment\x18\x03 \x03(\x0b\x32\x13.query.Bike.Segment'
  ,
  dependencies=[athlete__pb2.DESCRIPTOR,route__pb2.DESCRIPTOR,])




_BIKE_SEGMENT_HEARTH = _descriptor.Descriptor(
  name='Hearth',
  full_name='query.Bike.Segment.Hearth',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='average_hearth_rate', full_name='query.Bike.Segment.Hearth.average_hearth_rate', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='min_hearth_rate', full_name='query.Bike.Segment.Hearth.min_hearth_rate', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='max_hearth_rate', full_name='query.Bike.Segment.Hearth.max_hearth_rate', index=2,
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
  serialized_start=221,
  serialized_end=308,
)

_BIKE_SEGMENT = _descriptor.Descriptor(
  name='Segment',
  full_name='query.Bike.Segment',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='seg_id', full_name='query.Bike.Segment.seg_id', index=0,
      number=1, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='name', full_name='query.Bike.Segment.name', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='route', full_name='query.Bike.Segment.route', index=2,
      number=3, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='elev_high', full_name='query.Bike.Segment.elev_high', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='elev_low', full_name='query.Bike.Segment.elev_low', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='hearth_data', full_name='query.Bike.Segment.hearth_data', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_BIKE_SEGMENT_HEARTH, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=59,
  serialized_end=308,
)

_BIKE_QUERY = _descriptor.Descriptor(
  name='Query',
  full_name='query.Bike.Query',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='athlete', full_name='query.Bike.Query.athlete', index=0,
      number=2, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='segment', full_name='query.Bike.Query.segment', index=1,
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
  serialized_start=310,
  serialized_end=394,
)

_BIKE = _descriptor.Descriptor(
  name='Bike',
  full_name='query.Bike',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[_BIKE_SEGMENT, _BIKE_QUERY, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=50,
  serialized_end=394,
)

_BIKE_SEGMENT_HEARTH.containing_type = _BIKE_SEGMENT
_BIKE_SEGMENT.fields_by_name['route'].message_type = route__pb2._ROUTE_QUERY
_BIKE_SEGMENT.fields_by_name['hearth_data'].message_type = _BIKE_SEGMENT_HEARTH
_BIKE_SEGMENT.containing_type = _BIKE
_BIKE_QUERY.fields_by_name['athlete'].message_type = athlete__pb2._ATHLETE_QUERY
_BIKE_QUERY.fields_by_name['segment'].message_type = _BIKE_SEGMENT
_BIKE_QUERY.containing_type = _BIKE
DESCRIPTOR.message_types_by_name['Bike'] = _BIKE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Bike = _reflection.GeneratedProtocolMessageType('Bike', (_message.Message,), {

  'Segment' : _reflection.GeneratedProtocolMessageType('Segment', (_message.Message,), {

    'Hearth' : _reflection.GeneratedProtocolMessageType('Hearth', (_message.Message,), {
      'DESCRIPTOR' : _BIKE_SEGMENT_HEARTH,
      '__module__' : 'bike_pb2'
      # @@protoc_insertion_point(class_scope:query.Bike.Segment.Hearth)
      })
    ,
    'DESCRIPTOR' : _BIKE_SEGMENT,
    '__module__' : 'bike_pb2'
    # @@protoc_insertion_point(class_scope:query.Bike.Segment)
    })
  ,

  'Query' : _reflection.GeneratedProtocolMessageType('Query', (_message.Message,), {
    'DESCRIPTOR' : _BIKE_QUERY,
    '__module__' : 'bike_pb2'
    # @@protoc_insertion_point(class_scope:query.Bike.Query)
    })
  ,
  'DESCRIPTOR' : _BIKE,
  '__module__' : 'bike_pb2'
  # @@protoc_insertion_point(class_scope:query.Bike)
  })
_sym_db.RegisterMessage(Bike)
_sym_db.RegisterMessage(Bike.Segment)
_sym_db.RegisterMessage(Bike.Segment.Hearth)
_sym_db.RegisterMessage(Bike.Query)


# @@protoc_insertion_point(module_scope)
