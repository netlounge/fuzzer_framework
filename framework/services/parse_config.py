"""FrameWork main config parser module"""
import os
import sys
import json

from framework.core.fuzz_object import FuzzObject
from framework.utils.decorators import singleton
from framework.utils.utils import FrameworkUtils
from framework.utils.decorators import count_calls, debug, timer

CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..')) \
              + '/data/config/framework_config.json'


class ConfigParser(FuzzObject):
    """Config parser class"""

    def __init__(self, name='ConfigParser', logger=None):
        """
        :param name: name of the object
        :param logger: None, logger came from FuzzObject
        """
        super(ConfigParser, self).__init__(name, logger)
        self.data = json
        self.module_path = FrameworkUtils

    @property
    def parse_config_file(self) -> object:
        """

        :rtype: object
        """
        config_file = None
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH) as config_file:
                    data = json.load(config_file)
                    return data
            except Exception as err:
                self.logger.warning(f"Could not read from file from {CONFIG_PATH}, exception: {err}")
            finally:
                config_file.close()
        else:
            self.logger.error(f"No config file on path: {CONFIG_PATH}")
            raise FileNotFoundError

    # GENERIC CONFIGURATION FIELDS
    @singleton
    @debug
    def get_generic_verbosity(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['generic']['verbosity']

    @singleton
    def get_target_host_name(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['generic']['target_host']

    @singleton
    def get_target_port(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['generic']['target_port']

    @singleton
    def get_tls(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['generic']['tls']

    def get_archive_to_s3(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['generic']['archive_to_s3']

    def get_banner(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['generic']['banner']

    @singleton
    def get_protocol_protobuf(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['protocol']['PROTOBUF']

    @singleton
    def get_protocol_http(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['protocol']['HTTP']

    @singleton
    def get_protocol_dns(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['protocol']['DNS']

    # PROTOBUF CONFIGURATION FIELDS

    @singleton
    def get_protobuf_case_desc(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['protobuf']['test_case_desc']

    @singleton
    @count_calls
    def get_generic_proto_path(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['protobuf']['proto_path']

    @singleton
    @timer
    def get_generic_pb2_path(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['protobuf']['pb2_path']

    @singleton
    def get_module_path(self) -> object:
        """
        :rtype: object
        """
        return self.module_path.convert_filepath_to_module_path(self.get_generic_pb2_path())

    @singleton
    def get_protobuf_modules(self) -> object:
        """
        :return: 
        """
        return self.parse_config_file['protobuf']['modules']

    @singleton
    def get_protobuf_classes_to_send(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['protobuf']['classes_to_send']

    # DNS CONFIGURATION FIELDS

    @singleton
    def get_dns_case_desc(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['dns']['test_case_desc']

    @singleton
    def get_dns_tld(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['dns']['tld']

    @singleton
    def get_dns_timout(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['dns']['timeout']

    @singleton
    def get_dns_a_record_status(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['dns']['A']

    @singleton
    def get_dns_ns_record_status(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['dns']['NS']

    @singleton
    def get_dns_txt_record_status(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['dns']['TXT']

    def get_dns_default_labels(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['dns']['default_labels']

    # HTTP CONFIGURATION FIELDS

    @singleton
    def get_http_case_desc(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['http']['test_case_desc']

    @singleton
    def get_http_get_method(self) -> object:
        """
        :return: 
        """
        return self.parse_config_file['http']['GET']

    @singleton
    def get_http_post_put_method(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['http']['POST_PUT']

    @singleton
    def get_http_post_update_method(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['http']['POST_UPDATE']

    @singleton
    def get_http_delete_method(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['http']['DELETE']

    @singleton
    def get_http_fuzz_protocol(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['http']['fuzz_protocol']

    @singleton
    def get_http_path(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['http']['path']

    @singleton
    def get_http_content_type(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['http']['content_type']

    @singleton
    def get_http_payload(self) -> object:
        """
        :rtype: object
        """
        return self.parse_config_file['http']['sample_payload']
