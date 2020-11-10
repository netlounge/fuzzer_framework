import os

import socket
import time
import traceback
import json
from binascii import hexlify

import google.protobuf.json_format as json_format
from kitty.targets.server import ServerTarget
from kitty.core import KittyException
from kitty.data.report import Report

from framework.utils.utils import FrameworkUtils
from framework.services.parse_config import ConfigParser
from framework.utils.generate_uuid import GenerateUUID


class ProtobufTarget(ServerTarget):
    """
    ProtobufTarget will create files with the fuzzed payloads
    """

    def __init__(self, name=str, host=str, port=int, max_retries=10, timeout=None, logger=None, pb2_module=None) -> None:
        """
        Class creates the protobuf payload with the marriage of Fuzzed data.

        :param name: name of the class
        :param host: target host
        :param port: target port
        :param max_retries: maximum retries of connection
        :param timeout: timeout
        :param logger: kitty logger
        """
        super(ProtobufTarget, self).__init__(name, logger)
        self.host = host
        self.port = port
        if (host is None) or (port is None):
            raise ValueError('Host and port may not be None')
        self.timeout = timeout
        self.socket = None
        self.max_retries = max_retries
        self.pb2_module = pb2_module
        self.set_expect_response(False)
        self.config = ConfigParser()
        self.verbosity = self.config.get_generic_verbosity()
        self.logger.setLevel(self.verbosity)
        self.module_path = self.config.get_module_path()
        self._uuid = GenerateUUID.generate_uuid()
        self.frmwrk_utils = FrameworkUtils()

    def pre_test(self, test_num=int) -> None:
        """
        This is only checks whether the target is available or not.
        :param test_num: The number of the test case.
        """
        super(ProtobufTarget, self).pre_test(test_num)
        retry_count = 0
        while self.socket is None and retry_count < self.max_retries:
            sock = self._get_socket()
            if self.timeout is not None:
                sock.settimeout(self.timeout)
            try:
                retry_count += 1
                sock.connect((self.host, self.port))
                self.socket = sock
            except Exception:
                sock.close()
                self.logger.error(f"PBTARGET - TCP Error: {traceback.format_exc()}")
                self.logger.error(f"PBTARGET - TCP Failed to connect to target server, retrying...")
                time.sleep(1)
        if self.socket is None:
            raise (KittyException('PBTARGET - TCPTarget: (pre_test) cannot connect to server (retries = %d' %
                                  retry_count))

    def _get_socket(self) -> socket:
        """
        Get a socket object
        """
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def post_test(self, test_num=int):
        """
        Called after a test is completed, perform cleanup etc.
        """
        super(ProtobufTarget, self).post_test(test_num)
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        if self.report.get('status') != Report.PASSED:
            if not os.path.exists(os.getcwd() + '/results/'):
                os.makedirs(os.getcwd() + '/results/')
            test_num = self.report.get('test_number')
            with open(os.getcwd() + '/results/{}-result-protobuf-{}.json'.format(test_num, str(self._uuid)), 'w',
                      encoding='utf-8') as file:
                json.dump(self.report.to_dict(), file, ensure_ascii=False, indent=4)

    def _construct_message(self, data, pb2_module):
        msg = None
        to_dict = json.loads(data.decode())

        counter = 0
        for key, val in to_dict.items():
            if counter == 0:
                module_to_put_into = getattr(pb2_module, key)
                msg = json_format.ParseDict(val, module_to_put_into())

            else:
                # TODO Should implement a mechanism to send together
                # TODO top level messages.
                # TODO Currently sending only one top level for.ie.: Request
                # TODO and all its nested messages.
                raise NotImplementedError
            counter += 1

        return msg

    def _send_to_target(self, data):
        """
        HTTP POST with protobuf binary payload:

            POST / HTTP/1.1
            Host: localhost:8000
            Content-Type: : 'application/octet-stream'

            "b'|\x00\x00\x00\n\x05fdbcd\x10{\x1a\x05fdbcd"\t\n\x05fdbcd\x10\x01:_\n\x05fdbcd\x10{\x18\x01""\n\x05fdbcd\x10{\x1a\x05fdbcd"\x10\n\x05fdbcd\x10{\x1a\x05fdbcd*\x10\n\x05fdbcd\x10{\x1a\x05fdbcd2\x10\n\x05fdbcd\x10{\x1a\x05fdbcdB\n\n\x06%u0000\x10{'"

        https://stackoverflow.com/questions/28670835/python-socket-client-post-parameters

        :param data:
        :return:
        """
        proto_payload = self._construct_message(data, self.pb2_module)

        host = None
        port = None
        headers = """\
        POST / HTTP/1.1\r
        \r\n\
        Content-Type: {content_type}\r
        Content-Length: {content_length}\r
        \r\n"""

        body_bytes = self.frmwrk_utils.encode_message(proto_payload)
        # Evaluation of the message.
        #self.frmwrk_utils.decode_message(body_bytes, lookup_pb2, 'Request')

        header_bytes = headers.format(
            content_type="application/octet-stream",
            content_length=len(body_bytes),
            host=str(host) + ":" + str(port)
        ).encode('iso-8859-1')

        payload = header_bytes + body_bytes
        self.socket.send(payload)

    def _receive_from_target(self):
        return self.socket.recv(10000)

    def transmit(self, payload):
        """
        This is the original transmit method from ServerTarget overwritten with
        special cases such as 40X or 50X according to the aim of the test.

        Accordin to https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500
        500 Internal Server Error
        501 Not Implemented
        502 Bad Gateway
        503 Service Unavailable
        504 Gateway Timeout
        505 HTTP Version Not Supported
        506 Variant Also Negotiates
        507 Insufficient Storage
        508 Loop Detected
        510 Not Extended
        511 Network Authentication Required

        Original method docstring:
        Transmit single payload, and receive response, if expected.
        The actual implementation of the send/receive should be in
        ``_send_to_target`` and ``_receive_from_target``.

        :type payload: str
        :param payload: payload to send
        :rtype: str
        :return: the response (if received)
        """

        SERVER_50x_CODES = [
            '500 Internal Server Error',
            '501 Not Implemented',
            '502 Bad Gateway',
            '503 Service Unavailable',
            '504 Gateway Timeout',
            '505 HTTP Version Not Supported',
            '506 Variant Also Negotiates',
            '507 Insufficient Storage',
            '508 Loop Detected',
            '510 Not Extended',
            '511 Network Authentication Required'
        ]

        SERVER_40xCODES = [
            '400 Bad Request',
            '401 Unauthorized',
            '402 Payment Required',
            '403 Forbidden',
            '404 Not Found',
            '405 Method Not Allowed',
            '406 Not Acceptable',
            '407 Proxy Authentication Required',
            '408 Request Timeout',
            '409 Conflict',
            '410 Gone',
            '411 Length Required',
            '412 Precondition Failed',
            '413 Payload Too Large',
            '414 URI Too Long',
            '415 Unsupported Media Type',
            '416 Range Not Satisfiable',
            '417 Expectation Failed',
            '422 Unprocessable Entity',
            '425 Too Early',
            '426 Upgrade Required',
            '428 Precondition Required',
            '429 Too Many Requests',
            '431 Request Header Fields Too Large',
            '451 Unavailable For Legal Reasons'
        ]

        response = None
        trans_report_name = 'transmission_0x%04x' % self.transmission_count
        trans_report = Report(trans_report_name)
        self.transmission_report = trans_report
        self.report.add(trans_report_name, trans_report)
        try:
            trans_report.add('request (hex)', hexlify(payload).decode())
            trans_report.add('request (raw)', '%s' % payload)
            trans_report.add('request length', len(payload))
            trans_report.add('request time', time.time())

            request = hexlify(payload).decode()
            request = request if len(request) < 100 else (request[:100] + ' ...')
            self.logger.info(f"request({len(payload)}): {request}")
            self.logger.debug(f"payload {payload}")
            self._send_to_target(payload)
            trans_report.success()

            if self.expect_response:
                try:
                    response = self._receive_from_target()
                    trans_report.add('response time', time.time())
                    trans_report.add('response (hex)', hexlify(response).decode())
                    trans_report.add('response (raw)', '%s' % response)
                    trans_report.add('response length', len(response))
                    trans_report.add('Session ID', str(self._uuid))
                    printed_response = hexlify(response).decode()
                    printed_response = printed_response if len(printed_response) < 100 else (
                                printed_response[:100] + ' ...')
                    self.logger.info(f"response({len(response)}): {printed_response}")

                    string_response = response.decode('utf-8')
                    response_code_string = string_response.splitlines()[0]
                    response_code = response_code_string.replace('HTTP/1.1 ', '')

                    if response_code in SERVER_40xCODES or response_code in SERVER_50x_CODES:
                        self.logger.info(f"response failure {response.decode('utf-8')}")
                        trans_report.failed('Failure in HTTP-PROTO response.')
                        trans_report.add('Response', response.decode('utf-8'))
                        self.report.set_status('failed')
                        self.receive_failure = True

                except Exception as ex2:
                    trans_report.failed('failed to receive response: %s' % ex2)
                    trans_report.add('traceback', traceback.format_exc())
                    self.logger.error(f"target.transmit - failure in receive (exception: {ex2})")
                    self.logger.error(traceback.format_exc())
                    self.receive_failure = True
            else:
                response = ''
        except Exception as ex1:
            #trans_report.failed('failed to send payload: %s' % ex1)
            #trans_report.add('traceback', traceback.format_exc())
            self.logger.error(f"target.transmit - failure in send (exception: {ex1})")
            self.logger.error(traceback.format_exc())
            #self.send_failure = True
        self.transmission_count += 1
        return response
