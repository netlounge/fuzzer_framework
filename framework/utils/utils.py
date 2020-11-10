""" FrameWork Utils module for common functions"""

import os
import sys
import glob
import struct
import shutil
import string
import hashlib
import random
from io import BytesIO
from collections import OrderedDict
from importlib import import_module

from framework.core.fuzz_object import FuzzObject
from framework.utils.generate_uuid import GenerateUUID


class Error(Exception):
    """Top-level module error for utils."""


class ParseError(Error):
    """Thrown in case of parsing error."""


class FrameworkUtils(FuzzObject):
    """Main FrameWork Utils class"""

    def __init__(self, name='FrameworkUtils', logger=None):
        """
        Constructor of utils
        :type name of the object: object
        """
        super(FrameworkUtils, self).__init__(name, logger)
        self.logger = FuzzObject.get_logger()
        self._uuid = GenerateUUID.generate_uuid()

    @classmethod
    def convert_filepath_to_module_path(cls, file_path=str) -> str:
        """
        From /foo/bar/baz/baz_pb2.py to foo.bar.baz.baz_pb2.py
        :rtype: object
        """
        module_path = file_path.replace('/', '.')  # noqa
        module_path = module_path.replace('.Env.fuzz_framework', 'framework')
        return module_path[1:]

    def encode_message(self, msg: object = list) -> object:
        """
        This method is to encode the given protobuf message into byte.
        :param msg: the message to decode
        :return: result, the message in list of byte types
        :rtype list
        """
        buffer = BytesIO()
        self.logger.debug('MSG-ENCODE - Message to encode %s' % msg)
        size = msg.ByteSize()
        buffer.write(struct.pack('i', size))
        buffer.write(msg.SerializeToString())
        result = buffer.getvalue()
        self.logger.debug('MSG-DECODE - Message decoded %s' % result)
        return result

    def decode_message(self,
                       result: object = bytes,
                       pb2_module: object = object,
                       class_: str = str) -> object:
        """
        Decode the encoded message from protobuf format.
        :type class_: object
        :param result: the output of the decode_message() method
        :param pb2_module: the actual, processed, imported pb2 api
        :param class_: a message type class to help rebuild the protobuf message
        :return: decoded temp_msg in list
        :rtype: list
        """
        temp_msg = []
        buffer = BytesIO(result)  # noqa
        self.logger.debug('MSGVAL-DECODE - Message to decode %s' % result)
        while True:
            bsize = buffer.read(4)
            if len(bsize) == 0:
                break
            size = struct.unpack('i', bsize)[0]
            data = buffer.read(size)
            item = getattr(pb2_module, class_).FromString(data)
            temp_msg.append(item)
            self.logger.debug('MSGVAL-DECODE - decoded %s' % temp_msg)

        return temp_msg

    def rename_log_file(self) -> None:
        """
        Add Fuzz session UUID to Kitty log name.
        """
        path = os.getcwd() + '/kittylogs/'
        if os.path.exists(path):
            try:
                list_of_files = glob.glob(path + '*.log')
                latest_file = max(list_of_files, key=os.path.getctime)
                os.rename(path + latest_file.split('/')[-1], path + str(self._uuid) + '-' + latest_file.split('/')[-1])
            except Exception:
                self.logger.warning(f'Could not read from file {path}')
        else:
            self.logger.error(f'No kitty log file at {path}')
            raise FileNotFoundError

    def results_dir(self) -> None:
        """
        Creates the result directory if not exists.
        :return:
        """
        if not os.path.exists(os.getcwd() + '/results/'):
            os.makedirs(os.getcwd() + '/results/')

    def archive_locally(self) -> None:
        """
        A helper function to archive component produced files into one
        directory named after the session uuid.
        """
        if not os.path.exists(os.getcwd() + '/' + str(self._uuid) + '-log' + '/'):
            os.makedirs(os.getcwd() + '/' + str(self._uuid) + '-log' + '/')
        if os.path.exists(os.getcwd() + '/kittylogs/'):
            try:
                actual_kitty_log_file = glob.glob(os.getcwd() + '/kittylogs/' + '*' + str(self._uuid) + '*.log')
                shutil.move(actual_kitty_log_file[0], os.getcwd() + '/' + str(self._uuid) + '-log' + '/')
            except Exception as e:
                self.logger.warning('Could not read from file %s %s' % (os.getcwd() + '/kittylogs/', e))
        if os.path.exists(os.getcwd() + '/fuzzer_logs/'):
            try:
                actual_fuzzer_log_file = glob.glob(os.getcwd() + '/fuzzer_logs/' + '*' + str(self._uuid) + '*.log')
                shutil.move(actual_fuzzer_log_file[0], os.getcwd() + '/' + str(self._uuid) + '-log' + '/')
            except Exception as e:
                self.logger.warning('Could not read from file %s %s' % (os.getcwd() + '/fuzzer_logs/', e))
        if os.path.exists(os.getcwd() + '/results/'):
            try:
                actual_results_json_file = glob.glob(os.getcwd() + '/results/' + '*' + str(self._uuid) + '*.json')
                for result_file in actual_results_json_file:
                    shutil.move(result_file, os.getcwd() + '/' + str(self._uuid) + '-log' + '/')
            except Exception as e:
                self.logger.warning('Could not read from file %s %s' % (os.getcwd() + '/results/', e))

    def archive_xml(self) -> None:
        """
        Copy the junit xml to the result dir.
        :return: None
        """
        if os.path.exists(os.getcwd() + '/results/'):
            try:
                actual_results_xml_file = glob.glob(os.getcwd() + '/results/' + 'results.xml')
                for result_file in actual_results_xml_file:
                    shutil.move(result_file, os.getcwd() + '/' + str(self._uuid) + '-log' + '/')
            except Exception as e:
                self.logger.warning('Could not read from file %s %s' % (os.getcwd() + '/results/', e))

    def dir_files_to_archive(self) -> list:
        """
        A helper function for the archiver class to collect json files from
        the archive directory.
        :return: list
        """
        file_list = []
        if os.path.exists(os.getcwd() + '/' + str(self._uuid) + '-log' + '/'):
            file_list = glob.glob(os.getcwd() + '/' + str(self._uuid) + '-log' + '/*', recursive=True)
        return file_list

    def md5_checksum_for_proto_files(self, files: list) -> list:
        """
        Creates file checksum.
        :rtype: object
        """
        file_checksum_list = []
        for fname in files:
            hash_md5 = hashlib.md5()
            with open(os.path.abspath('../') + '/data/proto/example/' + fname, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_md5.update(chunk)
            file_checksum_list.append([fname, hash_md5.hexdigest()])

        return file_checksum_list

    @staticmethod
    def load_pb2_module(module, module_path) -> object:
        """
        Helps to load the compiled protobuf api as module if not exists.
        :param module:
        :param module_path:
        :return:
        """
        if module not in sys.modules:
            return import_module(
                str(module_path)
                + module)  # Import module from variable
        return None

    @staticmethod
    def extract_values(_object: dict, _key: str) -> list:
        """Pull all values of specified key from nested JSON."""
        _array = []

        def extract(_object, _array, _key):
            """
            Recursively search for values of key in JSON tree.
            Based on https://hackersandslackers.com/extract-data-from-complex-json-python/
            """
            if isinstance(_object, dict):
                for _k, _value in _object.items():
                    if isinstance(_value, (dict, list)):
                        extract(_value, _array, _key)
                    elif _k == _key:
                        _array.append(_value)
            elif isinstance(_object, list):
                for item in _object:
                    extract(item, _array, _key)
            return _array

        results = extract(_object, _array, _key)
        return results

    @staticmethod
    def update_nested(_object: OrderedDict, _key: str, _appnd: dict, context: tuple) -> OrderedDict:
        """
        This function helps to traverse the dictionary along the given path (context)
        and finds the given key and update the values of it.
        The contexts besides that avoid duplicate appends it speeds up the recursion.

        :param _object: the OrderedDict to traverse
        :param _key: the key to find
        :param _appnd: the object to append (list, object)
        :param context: the path to walk along foo bar a b c
        :rtype: OrderedDict
        """
        # transform list of tuples context into a single list
        path = [k[0] for k in context]

        def extract(_object, _appnd, _key, path):
            if isinstance(_object, dict):
                for _k, _value in _object.items():
                    if isinstance(_value, dict) and _k == _key and _k in path:
                        if _key in _object[_key]:  # when key name is the same as the nested key name
                            # then go one step deeper
                            extract(_value, _appnd, _key, path)
                        else:
                            _object[_key].update(_appnd)
                    elif isinstance(_value, (dict, list)) and _k != _key and _k in path:
                        extract(_value, _appnd, _key, path)
                    elif isinstance(_value, list) and _k == _key and _k in path:
                        if _appnd not in _object[_key] and not len(_value):
                            _object[_key].append(_appnd)
                        elif len(_value):
                            _value[0].update(_appnd)
            elif isinstance(_object, list):
                for item in _object:
                    extract(item, _appnd, _key, path)
            return _object

        results = extract(_object, _appnd, _key, path)
        return results

    def rnd_bool(self) -> str:
        """
        Bool randomizer
        :rtype: str
        """
        bool_ = ['true', 'false']
        return random.choices(bool_)[0]

    @staticmethod
    def rnd_enum(enum_list) -> str:
        """
        Enum randomizer
        :rtype: str
        """
        return random.choices(enum_list)

    def str_to_bool(self, value):
        """
        Pythonic way to transform str values to bool.
        :rtype: object
        """
        if value:
            if value in 'true':
                return True
            if value in 'false':
                return False
            else:
                raise ParseError(f'Expected "true" or "false", not {value}.')

        if not isinstance(value, bool):
            raise ParseError('Expected true or false without quotes.')
        return value

    # Parts of the new parse_proto_api field randomizer:
    def field_randomizer(self, field_type, default_value=None, enum_list=None) -> object:
        """
        Kitty have no information about the underlying type structure of Protobuf. The current method
        creates an initial (Python type)value for the given field.
        :param field_type:
        :param default_value:
        :return:
        """

        if field_type == 1:  # double
            if default_value:
                return default_value
            return random.uniform(1.0, 1.9)

        if field_type == 2:  # float
            if default_value:
                return default_value
            return random.uniform(1.0, 1.9)

        if field_type == 3:  # int64
            # Uses variable-length encoding.
            # Inefficient for encoding negative numbers
            if default_value:
                return default_value
            return random.randint(-9223372036854775808, 9223372036854775808)

        if field_type == 4:  # uint64
            # Uses variable-length encoding.
            if default_value:
                return default_value
            return random.randint(0, 18446744073709551615)

        if field_type == 5:  # int32
            # Uses variable-length encoding.
            # Inefficient for encoding negative numbers
            if default_value:
                return default_value
            return random.randint(-2147483648, 2147483648)

        if field_type == 6:  # fixed64
            # Signed int value.
            # These more efficiently encode negative numbers than regular int64s.
            if default_value:
                return default_value
            return random.randint(-9223372036854775808, 9223372036854775808)

        if field_type == 7:  # fixed32
            # Always four bytes.
            # More efficient than uint32 if values are often greater than 2^28.
            if default_value:
                return default_value
            return random.randint(-2147483648, 2147483648)

        if field_type == 8:  # bool
            if default_value:
                return default_value
            return self.str_to_bool(self.rnd_bool())

        if field_type == 9:  # string
            if default_value:
                return default_value
            return ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(5, 20)))

        if field_type == 10:  # group
            # Deprecated according to Google protobuf documentation.
            raise NotImplementedError

        if field_type == 12:  # bytes
            if default_value:
                return default_value
            return hex(random.randint(1, 255))

        if field_type == 13:  # unit32
            # Uses variable-length encoding.
            if default_value:
                return default_value
            return random.randint(0, 4294967295)

        if field_type == 14:  # enum
            if default_value:
                return str(default_value) + '+enum'
            return str(random.choices(enum_list)[0]) + '+enum'

        if field_type == 15:  # sfixed32
            raise NotImplementedError

        if field_type == 16:  # sfixed64
            raise NotImplementedError

        if field_type == 17:  # sint32
            # Always four bytes.
            raise NotImplementedError

        if field_type == 18:  # sint64
            # Always four bytes.
            raise NotImplementedError

        return None
