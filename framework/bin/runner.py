
"""
https://www.devdungeon.com/content/python-import-syspath-and-pythonpath-tutorial
https://dev.to/0xcrypto/dynamic-importing-stuff-in-python--1805
"""

import sys
import os
import time

sys.path.extend([os.path.abspath('../../')])

from framework.core.fuzz_object import FuzzObject
from framework.services.search_file import SearchFile
from framework.services.parse_proto_api import ParseProtoApi
from framework.services.parse_config import ConfigParser  # move here, lego here
from framework.runners.protobuf_runner import ProtobufRunner
from framework.runners.dns_runner import DnsRunner
from framework.runners.http_runner import HttpRunner
from framework.utils.utils import FrameworkUtils
from framework.services.put_archive_to_s3 import PutArchiveToS3
from framework.report.create_report import CreateReport


class FileNameError(Exception):
    def __init__(self, *args, **kwargs):  # real signature unknown
        pass


class Runner(FuzzObject):
    """
    This is the main runner class of the Fuzzer Framework.
    It integrates the kitty/katnip components and the framework components.
    See documentation for the usage.
    """

    def __init__(self, name='Runner', logger=None):
        super(Runner, self).__init__(name, logger)
        self.config = ConfigParser()
        self.framework_utils = FrameworkUtils()
        self.put_archive_to_s3 = PutArchiveToS3()
        self.proto_path = self.config.get_generic_proto_path()
        self.pb2_path = self.config.get_generic_pb2_path()
        self.verbosity = self.config.get_generic_verbosity()
        self.module_path = self.config.get_module_path()
        self.proto_modules = self.config.get_protobuf_modules()
        self.proto_classes = self.config.get_protobuf_classes_to_send()
        self.protocol_proto = self.config.get_protocol_protobuf()
        self.protocol_http = self.config.get_protocol_http()
        self.protocol_dns = self.config.get_protocol_dns()
        self.set_verbosity(self.verbosity)
        self.use_s3_to_archive = self.config.get_archive_to_s3()

    def search_files(self) -> tuple:
        """
        Creates lists of raw and compiled proto files paired into tuple;
        :return: raw and compiled proto file lists in tuple;
        """
        search_raw_proto = SearchFile(file_type='.proto', file_path=self.proto_path)
        raw_proto_files = search_raw_proto.search_file
        self.logger.debug(f'RAW proto files {raw_proto_files}')
        search_api = SearchFile(file_type='_pb2.py', file_path=self.pb2_path)
        compiled_proto_files = search_api.search_file
        self.logger.debug(f'Compiled proto files {compiled_proto_files}')

        return raw_proto_files, compiled_proto_files

    def checksum_files(self, raw_proto: list) -> list:
        # TODO for further usage, function not in use.
        checksum_files = self.framework_utils.md5_checksum_for_proto_files(raw_proto)
        self.logger.debug(f'Checksum {checksum_files}')
        return checksum_files

    @property
    def process_pb2(self) -> object:
        """
        This function parses the compiled protobuf API and
        produces a Dictionary representation of it.
        :return: object
        """
        compiled_proto_files = self.search_files()[1]
        for item in compiled_proto_files:
            if len(item.split('_')) > 2:
                raise FileNameError  # raise if file name contains more then 2 underline.
            elif item.split('_')[0] in self.config.get_protobuf_modules():
                parse_file = ParseProtoApi(pb2_api_file=item,
                                           module_path=self.module_path)
                return parse_file.execute_api_parse()
            else:
                self.logger.info(f'File {item} was not part of the inspection.')

    def tear_down(self):
        """
        The common tear down sequence of a fuzzing session
        :return: None
        """
        self.framework_utils.results_dir()
        self.framework_utils.rename_log_file()
        self.framework_utils.archive_locally()
        self.report()
        self.framework_utils.archive_xml()
        if self.use_s3_to_archive:
            self.put_archive_to_s3.do_upload(self.framework_utils.dir_files_to_archive())

    def report(self):
        _report = CreateReport()
        _report.run_report()

    def run(self):

        if self.config.get_banner():
            file1 = open(os.getcwd() + '/banner', 'r')
            Lines = file1.readlines()
            for line in Lines:
                print(f'     {line.strip()}')
            for i in range(5, 0, -1):
                sys.stdout.write(str(i) + '.....')
                sys.stdout.flush()
                time.sleep(1)

        if self.protocol_proto:
            self.logger.info(f"[{time.strftime('%H:%M:%S')}] Starting PROTOBUF Fuzzer session")
            try:
                api = self.process_pb2
                do_proto = ProtobufRunner(pb2_api=api)
                do_proto.run_proto()

            except SystemError as e:
                self.logger.error(f"Interpreter found an internal error: {e}")

            except EnvironmentError as e:
                self.logger(f"Error occur outside the Python environment: {e}")

            finally:
                self.logger.info(f"[{time.strftime('%H:%M:%S')}] Flush cache...")
                self.logger.info(f"[{time.strftime('%H:%M:%S')}] Rename kitty related log files...")
                self.tear_down()

        elif self.protocol_dns:
            self.logger.info(f"[{time.strftime('%H:%M:%S')}] Starting DNS Fuzzer session")
            try:
                # query record type
                do_dns = DnsRunner()
                do_dns.run_dns()
                self.logger.info(f"[{time.strftime('%H:%M:%S')}] DNS runner started")

            except SystemError as e:
                self.logger.error(f"Interpreter finds an internal problem {e}")

            except EnvironmentError as e:
                self.logger(f"Error occur outside the Python environment: {e}")

            finally:
                self.logger.info(f"[{time.strftime('%H:%M:%S')}] Rename kitty related log files...")
                self.tear_down()

        elif self.protocol_http:
            self.logger.info(f"[{time.strftime('%H:%M:%S')}] Starting HTTP Fuzzer session")
            try:
                do_http = HttpRunner()
                do_http.run_http()
                self.logger.info(f"[{time.strftime('%H:%M:%S')}] HTTP runner started")

            except SystemError as e:
                self.logger.error(f"Interpreter finds an internal problem {e}")

            except EnvironmentError as e:
                self.logger(f"Error occur outside the Python environment: {e}")

            finally:
                self.logger.info(f"[{time.strftime('%H:%M:%S')}] Rename kitty related log files...")
                self.tear_down()


if __name__ == '__main__':
    Runner().run()
