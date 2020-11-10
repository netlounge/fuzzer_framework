# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: route.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='route.proto',
  package='query',
  syntax='proto2',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x0broute.proto\x12\x05query\"\xb6\x02\n\x05Route\x1a\x38\n\x05Place\x12\x0f\n\x07\x63ountry\x18\x01 \x02(\t\x12\x0c\n\x04\x63ity\x18\x02 \x02(\t\x12\x10\n\x08\x64istance\x18\x03 \x02(\r\x1aj\n\x03Map\x12\x15\n\rstart_at_long\x18\x01 \x02(\t\x12\x13\n\x0b\x65nd_at_long\x18\x02 \x02(\t\x12\x0e\n\x06height\x18\x03 \x01(\r\x12\'\n\x08\x63\x61tegory\x18\x04 \x01(\x0e\x32\x15.query.Route.Category\x1a_\n\x05Query\x12\x14\n\televation\x18\x01 \x01(\r:\x01\x30\x12!\n\x05place\x18\x02 \x03(\x0b\x32\x12.query.Route.Place\x12\x1d\n\x03map\x18\x03 \x02(\x0b\x32\x10.query.Route.Map\"&\n\x08\x43\x61tegory\x12\x05\n\x01\x41\x10\x01\x12\x05\n\x01\x42\x10\x02\x12\x05\n\x01\x43\x10\x03\x12\x05\n\x01\x44\x10\x04'
)



_ROUTE_CATEGORY = _descriptor.EnumDescriptor(
  name='Category',
  full_name='query.Route.Category',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='A', index=0, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='B', index=1, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='C', index=2, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='D', index=3, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=295,
  serialized_end=333,
)
_sym_db.RegisterEnumDescriptor(_ROUTE_CATEGORY)


_ROUTE_PLACE = _descriptor.Descriptor(
  name='Place',
  full_name='query.Route.Place',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='country', full_name='query.Route.Place.country', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='city', full_name='query.Route.Place.city', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='distance', full_name='query.Route.Place.distance', index=2,
      number=3, type=13, cpp_type=3, label=2,
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
  serialized_start=32,
  serialized_end=88,
)

_ROUTE_MAP = _descriptor.Descriptor(
  name='Map',
  full_name='query.Route.Map',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='start_at_long', full_name='query.Route.Map.start_at_long', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='end_at_long', full_name='query.Route.Map.end_at_long', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='height', full_name='query.Route.Map.height', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='category', full_name='query.Route.Map.category', index=3,
      number=4, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=1,
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
  serialized_start=90,
  serialized_end=196,
)

_ROUTE_QUERY = _descriptor.Descriptor(
  name='Query',
  full_name='query.Route.Query',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='elevation', full_name='query.Route.Query.elevation', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='place', full_name='query.Route.Query.place', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='map', full_name='query.Route.Query.map', index=2,
      number=3, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
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
  serialized_start=198,
  serialized_end=293,
)

_ROUTE = _descriptor.Descriptor(
  name='Route',
  full_name='query.Route',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[_ROUTE_PLACE, _ROUTE_MAP, _ROUTE_QUERY, ],
  enum_types=[
    _ROUTE_CATEGORY,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=23,
  serialized_end=333,
)

_ROUTE_PLACE.containing_type = _ROUTE
_ROUTE_MAP.fields_by_name['category'].enum_type = _ROUTE_CATEGORY
_ROUTE_MAP.containing_type = _ROUTE
_ROUTE_QUERY.fields_by_name['place'].message_type = _ROUTE_PLACE
_ROUTE_QUERY.fields_by_name['map'].message_type = _ROUTE_MAP
_ROUTE_QUERY.containing_type = _ROUTE
_ROUTE_CATEGORY.containing_type = _ROUTE
DESCRIPTOR.message_types_by_name['Route'] = _ROUTE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Route = _reflection.GeneratedProtocolMessageType('Route', (_message.Message,), {

  'Place' : _reflection.GeneratedProtocolMessageType('Place', (_message.Message,), {
    'DESCRIPTOR' : _ROUTE_PLACE,
    '__module__' : 'route_pb2'
    # @@protoc_insertion_point(class_scope:query.Route.Place)
    })
  ,

  'Map' : _reflection.GeneratedProtocolMessageType('Map', (_message.Message,), {
    'DESCRIPTOR' : _ROUTE_MAP,
    '__module__' : 'route_pb2'
    # @@protoc_insertion_point(class_scope:query.Route.Map)
    })
  ,

  'Query' : _reflection.GeneratedProtocolMessageType('Query', (_message.Message,), {
    'DESCRIPTOR' : _ROUTE_QUERY,
    '__module__' : 'route_pb2'
    # @@protoc_insertion_point(class_scope:query.Route.Query)
    })
  ,
  'DESCRIPTOR' : _ROUTE,
  '__module__' : 'route_pb2'
  # @@protoc_insertion_point(class_scope:query.Route)
  })
_sym_db.RegisterMessage(Route)
_sym_db.RegisterMessage(Route.Place)
_sym_db.RegisterMessage(Route.Map)
_sym_db.RegisterMessage(Route.Query)


# @@protoc_insertion_point(module_scope)
