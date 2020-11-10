import os
import socket
import time
import traceback
import ssl
import json
from binascii import hexlify

from kitty.targets import ServerTarget
from kitty.core import KittyException
from kitty.data.report import Report

from framework.services.parse_config import ConfigParser
from framework.utils.generate_uuid import GenerateUUID


class HttpTarget(ServerTarget):
    """
    HttpTarget is implementation of a TCP target for the ServerFuzzer
    """

    def __init__(self, name, host, port, max_retries=10, timeout=None, logger=None) -> object:
        """
        :param name: name of the target
        :param host: host ip (to send data to) currently unused
        :param port: port to send to
        :param max_retries: maximum connection retries (default: 10)
        :param timeout: socket timeout (default: None)
        :param logger: logger for the object (default: None)
        """
        super(HttpTarget, self).__init__(name, logger)
        self.host = host
        self.port = port
        if (host is None) or (port is None):
            raise ValueError('host and port may not be None')
        self.timeout = timeout
        self.socket = None
        self.max_retries = max_retries
        self.config = ConfigParser()
        self.use_tls = self.config.get_tls()
        self.target_host = self.config.get_target_host_name()
        self.report = Report('report')
        self._uuid = GenerateUUID.generate_uuid()

    def pre_test(self, test_num=str) -> None:
        """Katnip original method."""
        super(HttpTarget, self).pre_test(test_num)
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
                self.logger.error(f"Error: {traceback.format_exc()}")
                self.logger.error(f"Failed to connect to target server, retrying...")
                time.sleep(1)
        if self.socket is None:
            raise(KittyException('TCPTarget: (pre_test) cannot connect to server (retries = %d' % retry_count))

    def _get_socket(self) -> socket:
        """
        Katnip original method. Get a Socket object.
        Extended with Python3.x TLS socket wrapper
        """

        if self.use_tls:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            socket_handler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_wraped = ssl.create_default_context().wrap_socket(socket_handler, server_hostname=self.target_host)
            return socket_wraped
        elif not self.use_tls:
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def post_test(self, test_num=str) -> None:
        """Katnip original method."""
        super(HttpTarget, self).post_test(test_num)
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        if self.report.get('status') != Report.PASSED:
            if not os.path.exists(os.getcwd() + '/results/'):
                os.makedirs(os.getcwd() + '/results/')
            test_num = self.report.get('test_number')
            with open(os.getcwd() + '/results/{}-result-http-{}.json'.format(test_num, str(self._uuid)), 'w',
                      encoding='utf-8') as file:
                json.dump(self.report.to_dict(), file, ensure_ascii=False, indent=4)
            file.close()

    def _raw_data(self, data=bytes) -> None:
        """Convert bytes data to UTF-8"""
        try:
            self.logger.info(f"Data sent: {data.decode('utf-8')}")
        except UnicodeDecodeError as err:
            """
            UnicodeDecodeError: 'utf-8' codec can't decode byte 0xfe in position 14: invalid start byte
            Fuzzer transform data so I have to log the bytes format.
            """
            self.logger.info(f"Data sent: {data}, error {err}")

    def _send_to_target(self, data=bytes) -> None:
        self._raw_data(data)
        self.socket.send(data)

    def _receive_from_target(self) -> bytes:
        return self.socket.recv(10000)

    def transmit(self, payload):
        """
        This is the original transmit method from ServerTarget overwritten with
        special cases such as 40X or 50X according to the aim of the test.

        According to https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500
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
            self.logger.info('request(%d): %s' % (len(payload), request))
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
                    printed_response = printed_response if len(printed_response) < 100 else (printed_response[:100] + ' ...')
                    self.logger.info(f"response{len(response)}: {printed_response}")
                    self.logger.debug(response.decode('utf-8'))
                    string_response = response.decode('utf-8')
                    response_code_string = string_response.splitlines()[0]
                    response_code = response_code_string.replace('HTTP/1.1 ', '')

                    if response_code in SERVER_40xCODES or response_code in SERVER_50x_CODES:
                        self.logger.info(f"response failure {response.decode('utf-8')}")
                        trans_report.failed('Failure in HTTP response.')
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
            trans_report.failed(f"failed to send payload: {ex1}")
            trans_report.add('traceback', traceback.format_exc())
            self.logger.error(f"target.transmit - failure in send (exception: {ex1})")
            self.logger.error(traceback.format_exc())
            self.send_failure = True
        self.transmission_count += 1
        return response
