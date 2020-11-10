"""Reporter module"""
import os
import json
import base64
import time

from prettytable import PrettyTable
import xml.etree.cElementTree as ET
from datetime import timedelta

from framework.core.fuzz_object import FuzzObject
from framework.services.search_file import SearchFile
from framework.utils.generate_uuid import GenerateUUID
from framework.utils.utils import FrameworkUtils
from framework.services.parse_config import ConfigParser


class CreateReport(FuzzObject):
    """ This class is in charge to create an artifact after
        the current test session is finished.
        It collects the error reports occurred during the tests.
        Collects the kitty and framework related logs.
        Put all together into a directory named by the actual session id.
        Log to stdout a lazy report.
        Create a junit compatible XML report for the Jenkins.
    """

    def __init__(self, name='CreateReport', logger=None):
        super(CreateReport, self).__init__(name, logger)
        self._uuid = GenerateUUID.generate_uuid()
        self.files_to_report = None

    def search_for_result_files(self) -> object:
        """
        It initiates a search to collect the result files.
        :return: object
        """
        try:
            initiate_searching = SearchFile(file_type='-result-', file_path='/framework/bin/' + str(self._uuid) + '-log' + '/')
            return initiate_searching.search_file
        except FileNotFoundError as err:
            self.logger.error(f"MSGVAL file not found at {str(self._uuid)}, {err}")

    def parse_report_files(self) -> list:
        """
        Returns a list of json result objects.
        :return: list
        """
        global file
        report_list = []
        report_file_list = self.search_for_result_files()

        for report in report_file_list:
            try:
                with open(os.getcwd() + '/' + str(self._uuid) + '-log' + '/' + report) as file:
                    report_list.append(json.load(file))
            except FileNotFoundError as err:
                self.logger.error(f"MSGVAL file not found at {os.getcwd()}/{str(self._uuid)}-log/{report} {err}")
            finally:
                file.close()

        return report_list

    def lazy_result_report(self, report_list=list) -> None:
        """
        Create a lazy report using Pretty Table.
        :param report_list: list
        :return: None
        """
        report_num = 0

        x_report = PrettyTable()
        x_report.field_names = ['Test number', 'Fuzz duration', 'Transport duration', 'Failure reason']

        for report in report_list:
            trasport_start = report['transmission_0x0000']['request time']
            try:
                transport_stop = report['transmission_0x0000']['response time']
                transport_duration = transport_stop - trasport_start
            except KeyError as err:
                self.logger.error(f"Key Error %s, transport duration will be false! {err}")
                transport_duration = 0

            fuzz_start = report['controller']['start_time']
            fuzz_stop = report['controller']['stop_time']
            fuzz_duration = fuzz_stop - fuzz_start
            x_report.add_row([str(report['test_number']),
                              str(timedelta(seconds=fuzz_duration)),
                              str(timedelta(seconds=transport_duration)),
                              str(base64.b64decode(report['transmission_0x0000']['reason']))
                              ])
            report_num += 1

        print(x_report)
        x_report = PrettyTable()
        x_report.field_names = ['Sum report']
        x_report.add_row([report_num])
        print(x_report)

    def _get_case_description(self):
        get_desc = ConfigParser()
        if get_desc.get_protocol_dns() is True:
            return get_desc.get_dns_case_desc()
        elif get_desc.get_protocol_http() is True:
            return get_desc.get_http_case_desc()
        elif get_desc.get_protocol_protobuf is True:
            return get_desc.get_protobuf_case_desc()

    def junit_xml_report(self, report_list=list) -> None:
        """
        Creates a JUnit compatible XML output for CI systems.
        According to https://help.catchsoftware.com/display/ET/JUnit+Format

        :param report_list: list
        :return: None
        """

        if len(report_list) != 0:
            get_values = FrameworkUtils()
            test_suite = ET.Element("testsuite",
                                    errors="",
                                    failures=str(len(report_list)),
                                    name=str(self._get_case_description()),
                                    skipped="0",
                                    tests="",
                                    time="0",
                                    timestamp=str(time.strftime("%Y%m%d-%H%M%S")))

            for report in report_list:
                controller_start = report['controller']['start_time']
                try:
                    controller_stop = report['controller']['stop_time']
                    controller_duration = controller_stop - controller_start
                except KeyError as err:
                    self.logger.error(f"Key Error {err}, controller running duration value will be false!")
                    controller_duration = 0
                    self.logger.error(f"Duration has been set to {controller_duration}")
                reason = base64.b64decode(report['transmission_0x0000']['reason'])
                request = base64.b64decode(report['transmission_0x0000']['request (raw)'])
                controller_name = base64.b64decode(report['controller']['name'])
                test_case = ET.SubElement(test_suite, "testcase",
                                          classname=request.decode('utf-8'),
                                          name=controller_name.decode('utf-8'),
                                          time=str(timedelta(seconds=controller_duration)),
                                          timestamp=time.strftime("%Y%m%d-%H%M%S"))
                if len(get_values.extract_values(report, 'traceback')) != 0:
                    failure_traceback = base64.b64decode(report['transmission_0x0000']['traceback']).decode('utf-8')
                    ET.SubElement(test_case,
                                  "failure",
                                  message="Failure traceback",
                                  type=reason.decode('utf-8')).text = f"<![CDATA[{failure_traceback}]]>"
                else:
                    ET.SubElement(test_case,
                                  "failure",
                                  message="Failure traceback",
                                  type=reason.decode('utf-8')).text = f"<![CDATA[]]>"

                ET.SubElement(test_case, "system-out").text = "<![CDATA[]]>"
                ET.SubElement(test_case, "system-err").text = "<![CDATA[]]>"
            tree = ET.ElementTree(test_suite)
            tree.write(open(os.getcwd() + '/results/' + 'results.xml', 'wb'), encoding='utf-8', xml_declaration=True)

        else:
            test_suite = ET.Element("testsuite",
                                    errors="0",
                                    failures="0",
                                    name=str(self._get_case_description()),
                                    skipped="0",
                                    tests="",
                                    time="0",
                                    timestamp=str(time.strftime("%Y%m%d-%H%M%S")))

            test_case = ET.SubElement(test_suite, "testcase",
                                      classname="",
                                      name=str(self._get_case_description()),
                                      time="",
                                      timestamp=time.strftime("%Y%m%d-%H%M%S"))

            ET.SubElement(test_case, "system-out").text = "<![CDATA[]]>"
            ET.SubElement(test_case, "system-err").text = "<![CDATA[]]>"
            tree = ET.ElementTree(test_suite)
            tree.write(open(os.getcwd() + '/results/' + 'results.xml', 'wb'), encoding='utf-8', xml_declaration=True)

    def run_report(self) -> None:
        """
        Run one report from the above.
        :return: None
        """
        self.lazy_result_report(self.parse_report_files())
        self.junit_xml_report(self.parse_report_files())
