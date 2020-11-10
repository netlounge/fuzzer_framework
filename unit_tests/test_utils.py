import os
import glob
import unittest
import json
import shutil
import time
import re

import google.protobuf.json_format as json_format
from framework.models.pb2.example_v2 import query_pb2
from framework.targets.protobuf_target import ProtobufTarget
from framework.utils.utils import FrameworkUtils
from framework.utils.generate_uuid import GenerateUUID

# sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

msg_encoded = b'\x16\x04\x00\x00\x08\x01\x10\x0f\x18\xd5\x9a\xe1\xa5\xff\xff\xff\xff\xff\x01"`\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,\xb2\xcb,*\x9c\x07\n\x83\x02\x12l\x08\xa9\xd0\xda\xf5\x05\x12-\n\th8nxqihz3\x12\rnndbvq2c32ddd\x1a\x113ktym9at91rnjr0wv\x1a\x0f\x08\x01\x12\x0b52bvd34sii8"\x18\x08\x01\x12\x142ykjie6fwqc3f9kwnyzx(\x94\xc6\xac\x88\r0\xcd\xf4\xf5\xba\x08\x1a\x92\x01\x08\x93\xfd\xa2\xc6\x08\x12\x0bqc9otrz5zid\x1a]\x08\x96\xb7\xfe\xe6\n\x120\n\x1407y2glfcwbyz0v52xfgr\x12\x12zwo1hqigstk4zpzdyx\x18\x89\x80\x85\xc7\x06\x1a#\n\x10h173nto1ug60k5zm\x12\x07y322z8s\x18\xdf\xb8\xce\x86\x03 \x01 \x9a\xe8\xe4\xf0\x0f(\xb2\xf0\xc2\xd9\x062\x12\x08\xd8\xaa\xcb\xbf\x0b\x10\xd6\x8a\xb3\xde\x01\x18\x8d\xb9\xb8\xfa\x04\x12\xa4\x01\x12p\x08\xf9\xd5\xaa\xbb\n\x129\n\x11icbrwgri5nk8nn47f\x12\x104rz397uooun1belj\x1a\x12f9m13nf64250y2zmse\x1a\x10\x08\x01\x12\x0cq00st6qht6as"\x0f\x08\x01\x12\x0b893bt8rijrs(\xef\x9d\xb9\xe0\r0\xde\xb0\x9e\xe2\x02\x1a0\x08\xf5\xb4\x86\xf3\x04\x12\x14bxmml84o8b0xja0vigb62\x12\x08\xc2\x94\xcc\xaf\x04\x10\xc3\xfd\xf8\xa1\x03\x18\xa2\xbb\x84\xb7\x06\x1a\xf4\x01\x12f\x08\xa5\xe2\xd5\xb1\x02\x125\n\x0eywm3u11vx3wfub\x12\x147kqtjdydz6v1z425spwy\x1a\ryyru9c7koo5nk\x1a\x0e\x08\x01\x12\newo96st1cc"\x0b\x08\x01\x12\x07bsbl4rs(\xf8\xbc\xc3\xcc\n0\xfe\xa1\xff\xb4\x04\x1a\x89\x01\x08\xcb\xcc\x96\x96\x0c\x12\rriyk6u6pkf573\x1aR\x08\x8a\x8c\x84\xff\x06\x12$\n\x06rbfrtz\x12\x14er76d45v5nlyy6slvxef\x18\xd1\xf5\xc3\xf9\x06\x1a$\n\t8f6zkqhlz\x12\x0fvjdy6ip79nncu9u\x18\x99\xde\xbe\xb5\x0c \x01 \xe2\xa1\xa0\xc7\x04(\xe6\xb4\x85\xda\n2\x12\x08\xe0\xbd\xf6\xf0\n\x10\xdc\xc0\xce\x80\x04\x18\xbe\xee\x82\x8d\r"\xf5\x01\x12^\x08\x95\x8e\xc6\xe8\x0c\x12#\n\x05n8xly\x12\x05t2pvl\x1a\x139phdsrfvyfj5g4fa680\x1a\x0f\x08\x01\x12\x0biuhtocaoqw7"\x14\x08\x01\x12\x10l6q7i84ye2ssap2a(\xdf\xe5\xb0\xac\r0\xce\xa5\xd7\xfb\t\x1a\x92\x01\x08\xdd\xc3\xff\x92\x05\x12\x10thv9sqg8o8bukvy2\x1aX\x08\x84\xb0\xce\xda\x05\x12"\n\x1329bmki3fiuc97qgnk8a\x12\x05j21kz\x18\xdb\x8b\xa4\x86\x02\x1a,\n\x134fgdxbuxko2qzh3z6fe\x12\r9bzzrkrs9jfqv\x18\xbe\xe0\xb3\xa2\n \x01 \xee\xa7\xbf\xd0\x07(\xc3\x9b\xb1\x8a\x0c2\x12\x08\x82\x88\x8a\xa5\n\x10\xf1\xeb\x96\x8f\x05\x18\xa0\xd3\xd5\xba\x070\x86\x84\xe9\x9c\x01'


class TestFramework(unittest.TestCase):

    def __init__(self, name='TestFramework'):
        super(TestFramework, self).__init__(name)
        self.framework_utils = FrameworkUtils()
        self.protobuf_target = ProtobufTarget()

    def test_01_convert_filepath_to_module_path(self):
        module_import_path = \
            self.framework_utils.convert_filepath_to_module_path(file_path='/framework/models/pb2/api/')
        self.assertEqual(module_import_path, 'framework.models.pb2.api.')

    def test_02_encode_message(self):
        with open(os.path.abspath(os.path.join(os.path.dirname(__file__))) + '/msg_encode_assert') as file_data:
            data = file_data.read().encode()
        file_data.close()
        msg = self.protobuf_target._construct_message(data, query_pb2)
        msg_encoded = self.framework_utils.encode_message(msg)
        self.assertEqual(msg_encoded, msg_encoded)

    def test_03_decode_message(self):
        result = self.framework_utils.decode_message(msg_encoded, query_pb2, 'Request')
        msg = json_format.MessageToDict(result[0])
        with open(os.path.join(os.path.dirname(__file__)) + '/msg_decoded_assert') as file_data:
            msg_decoded_assert = json.load(file_data)
        self.assertEqual(msg, msg_decoded_assert)

    def test_04_create_result_dir_if_not_exists(self):
        is_exits = False
        self.framework_utils.results_dir()
        if os.path.exists(os.getcwd() + '/results/'):
            is_exits = True
        self.assertTrue(is_exits, True)
        #shutil.rmtree(os.getcwd() + '/results/', ignore_errors=True)

    def test_05_rename_log_file(self):
        self._uuid = GenerateUUID.generate_uuid()
        self.framework_utils.rename_log_file()
        file_name = glob.glob(os.getcwd() + '/kittylogs/' + '*.log')[0].split('/')[-1:]
        expected_file_name = str(self._uuid) + '-kitty_' + time.strftime("%Y%m%d-%H%M%S") + '.log'
        shutil.rmtree(os.getcwd() + '/kittylogs/', ignore_errors=True)
        self.assertAlmostEqual(file_name[0], expected_file_name)

    def test_06_rename_log_file_file_not_found(self):
        shutil.rmtree(os.getcwd() + '/kittylogs/', ignore_errors=True)
        with self.assertRaises(FileNotFoundError):
            self.framework_utils.rename_log_file()

    def test_07_rename_log_file_could_not_read_from_file(self):
        os.makedirs(os.getcwd() + '/kittylogs/')
        with open(os.getcwd() + '/kittylogs/foo.gld', 'w') as file:
            file.write('dummy')
        file.close()
        with self.assertLogs('fuzzer', level='WARNING') as cm:
             self.framework_utils.rename_log_file()
        self.assertIn('WARNING:fuzzer:Could not read from file ' + os.getcwd() + '/kittylogs/', cm.output)
        shutil.rmtree(os.getcwd() + '/kittylogs/', ignore_errors=True)

    def test_08_archive_locally(self):
        dir_exists = False
        self.framework_utils.archive_locally()
        self._uuid = GenerateUUID.generate_uuid()
        dir_ = str(self._uuid) + '-log'
        if os.path.exists(os.getcwd() + '/' + dir_):
            dir_exists = True
        self.assertTrue(dir_exists, True)

    def test_09_extract_values(self):
        input_ = {
            "a": 1,
            "b": 2,
            "c": {
                "d": 3,
                "e": 4,
                "f": [
                    {
                        "g": 5
                    }
                ],
                "h": {
                    "i": 6
                }
            }
        }
        key_ = 'i'
        self.assertEqual(self.framework_utils.extract_values(input_, key_), [6])

    def test_10_update_nested_object(self):
        context_ = [("a", 1), ("c", 2), ("h", 1), ("j", 1)]
        appnd_ = {"m": 9}
        key_ = "j"
        input_ = {
            "a": 1,
            "b": 2,
            "c": {
                "d": 3,
                "e": 4,
                "f": [
                    {
                        "g": 5
                    }
                ],
                "h": {
                    "i": 6,
                    "j": [
                        {
                            "k": 7,
                            "l": 8
                        }
                    ]
                }
            }
        }

        result = self.framework_utils.update_nested(input_, key_, appnd_, context_)
        expected = {'a': 1, 'b': 2, 'c': {'d': 3, 'e': 4, 'f': [{'g': 5}], 'h': {'i': 6, 'j': [{'k': 7, 'l': 8, 'm': 9}]}}}
        self.assertEqual(result, expected)

    def test_11_update_nested_object_same_name(self):
        context_ = [("a", 1), ("c", 2), ("h", 1)]
        appnd_ = {"h": 9}
        key_ = "h"
        input_ = {
            "a": 1,
            "b": 2,
            "c": {
                "d": 3,
                "e": 4,
                "f": {
                        "g": 5
                },
                "h": {
                    "i": 6,
                    "j": [
                        {
                            "k": 7,
                            "l": 8
                        }
                    ]
                }
            }
        }

        result = self.framework_utils.update_nested(input_, key_, appnd_, context_)
        expected = {'a': 1, 'b': 2, 'c': {'d': 3, 'e': 4, 'f': {'g': 5}, 'h': {'i': 6, 'j': [{'k': 7, 'l': 8}], 'h': 9}}}
        self.assertEqual(result, expected)

    def test_12_update_nested_object_same_name_nested(self):
        context_ = [("a", 1), ("q", 2), ("q", 1)]
        appnd_ = {"q": 9}
        key_ = "q"
        input_ = {
            "a": 1,
            "b": 2,
            "q": {
                    "q": {"x": 1}
                  },
            "c": {
                "d": 3,
                "e": 4,
                "f": {
                        "g": 5
                },
                "h": {
                    "i": 6,
                    "j": [
                        {
                            "k": 7,
                            "l": 8
                        }
                    ]
                }
            }
        }

        result = self.framework_utils.update_nested(input_, key_, appnd_, context_)
        expected = {'a': 1, 'b': 2, 'q': {'q': {'x': 1, 'q': 9}}, 'c': {'d': 3, 'e': 4, 'f': {'g': 5}, 'h': {'i': 6, 'j': [{'k': 7, 'l': 8}]}}}
        self.assertEqual(result, expected)

    def test_13_field_randomizer_double(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(1, default_value=None, enum_list=None)
        if 1.0 <= result <= 1.9:
            is_close = True
        self.assertTrue(is_close, True)

    def test_13_field_randomizer_double_default_value(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(1, default_value=1.12345679, enum_list=None)
        if 1.0 <= result <= 1.9:
            is_close = True
        self.assertTrue(is_close, True)

    def test_14_field_randomizer_float(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(2, default_value=None, enum_list=None)
        if 1.0 <= result <= 1.9:
            is_close = True
        self.assertTrue(is_close, True)

    def test_15_field_randomizer_float_default(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(2, default_value=1.123456789, enum_list=None)
        if 1.0 <= result <= 1.9:
            is_close = True
        self.assertTrue(is_close, True)

    def test_14_field_randomizer_int64(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(3, default_value=None, enum_list=None)
        if -9223372036854775808 <= result <= 9223372036854775808:
            is_close = True
        self.assertTrue(is_close, True)

    def test_15_field_randomizer_int64_default(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(3, default_value=1234567899999999, enum_list=None)
        if -9223372036854775808 <= result <= 9223372036854775808:
            is_close = True
        self.assertTrue(is_close, True)

    def test_16_field_randomizer_uint64(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(4, default_value=None, enum_list=None)
        if -0 <= result <= 18446744073709551615:
            is_close = True
        self.assertTrue(is_close, True)

    def test_17_field_randomizer_uint64_default(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(4, default_value=1844674407370955161, enum_list=None)
        if -0 <= result <= 18446744073709551615:
            is_close = True
        self.assertTrue(is_close, True)

    def test_18_field_randomizer_int32(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(5, default_value=None, enum_list=None)
        if -2147483648 <= result <= 2147483648:
            is_close = True
        self.assertTrue(is_close, True)

    def test_19_field_randomizer_int32_default(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(5, default_value=1234567, enum_list=None)
        if -2147483648 <= result <= 2147483648:
            is_close = True
        self.assertTrue(is_close, True)

    def test_20_field_randomizer_fixed64(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(6, default_value=None, enum_list=None)
        if -9223372036854775808 <= result <= 9223372036854775808:
            is_close = True
        self.assertTrue(is_close, True)

    def test_21_field_randomizer_fixed64_default(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(6, default_value=92233720368547758, enum_list=None)
        if -9223372036854775808 <= result <= 9223372036854775808:
            is_close = True
        self.assertTrue(is_close, True)

    def test_22_field_randomizer_fixed32(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(7, default_value=None, enum_list=None)
        if -2147483648 <= result <= 2147483648:
            is_close = True
        self.assertTrue(is_close, True)

    def test_23_field_randomizer_fixed32_default(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(7, default_value=214748364, enum_list=None)
        if -2147483648 <= result <= 2147483648:
            is_close = True
        self.assertTrue(is_close, True)

    def test_22_field_randomizer_bool(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(8, default_value=None, enum_list=None)
        if result or not result:
            is_close = True
        self.assertTrue(is_close, True)

    def test_23_field_randomizer_bool_default(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(8, default_value=True, enum_list=None)
        if result or not result:
            is_close = True
        self.assertTrue(is_close, True)

    def test_24_field_randomizer_string(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        regex = re.compile('[a-zA-Z0-9]', re.I)
        result = self.framework_utils.field_randomizer(9, default_value=None, enum_list=None)
        res = bool(regex.match(str(result)))
        if isinstance(result, str) and res:
            is_close = True
        self.assertTrue(is_close, True)

    def test_25_field_randomizer_string_default(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        regex = re.compile('[a-zA-Z0-9]', re.I)
        result = self.framework_utils.field_randomizer(9, default_value='abcdefghijk', enum_list=None)
        res = bool(regex.match(str(result)))
        if isinstance(result, str) and res:
            is_close = True
        self.assertTrue(is_close, True)

    def test_26_field_randomizer_group(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        with self.assertRaises(NotImplementedError):
            self.framework_utils.field_randomizer(10, default_value=None, enum_list=None)

    def test_27_field_randomizer_bytes(self):
        #TODO finish
        self.framework_utils.field_randomizer(12, default_value=None, enum_list=None)

    def test_28_field_randomizer_bytes_default(self):
        #TODO
        self.framework_utils.field_randomizer(12, default_value=0x23, enum_list=None)

    def test_29_field_randomizer_uint32(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(13, default_value=None, enum_list=None)
        if 0 <= result <= 4294967295:
            is_close = True
        self.assertTrue(is_close, True)

    def test_30_field_randomizer_uint32_default(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        result = self.framework_utils.field_randomizer(13, default_value=429496729, enum_list=None)
        if 0 <= result <= 4294967295:
            is_close = True
        self.assertTrue(is_close, True)

    def test_31_field_randomizer_enum(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        enum_list = ['foo','bar','baz']
        result = self.framework_utils.field_randomizer(14, default_value=None, enum_list=enum_list)
        if result.split('+')[0] in enum_list:
            is_close = True
        self.assertTrue(is_close, True)

    def test_32_field_randomizer_enum_default(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        is_close = False
        enum_list = ['foo','bar','baz']
        result = self.framework_utils.field_randomizer(14, default_value='bar', enum_list=enum_list)
        if result.split('+')[0] in enum_list:
            is_close = True
        self.assertTrue(is_close, True)

    def test_33_field_randomizer_sfixed32(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        with self.assertRaises(NotImplementedError):
            self.framework_utils.field_randomizer(15, default_value=None, enum_list=None)

    def test_34_field_randomizer_sfixed64(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        with self.assertRaises(NotImplementedError):
            self.framework_utils.field_randomizer(16, default_value=None, enum_list=None)

    def test_35_field_randomizer_sint32(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        with self.assertRaises(NotImplementedError):
            self.framework_utils.field_randomizer(17, default_value=None, enum_list=None)

    def test_36_field_randomizer_sint64(self):
        # field_randomizer(self, field_type, default_value=None, enum_list=None)
        with self.assertRaises(NotImplementedError):
            self.framework_utils.field_randomizer(18, default_value=None, enum_list=None)

    def test_37_str_to_bool_true(self):
        result = self.framework_utils.str_to_bool('true')
        self.assertTrue(result, True)

    def test_38_str_to_bool_false(self):
        result = self.framework_utils.str_to_bool('false')
        self.assertFalse(result, False)

    def test_39_dir_files_to_archive(self):
        result = self.framework_utils.dir_files_to_archive()
        self.assertEqual(len(result), 1)

    def test_40_md5_checksum_for_proto_files(self):
        pass
