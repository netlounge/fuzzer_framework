"""
Module to construct DNS message then send and receive.
Uses socket to establish and send DNS on UDP.
Receiving done by DNSLib.
"""
# https://github.com/tigerlyb/DNS-Lookup-Tool-in-Python
# https://routley.io/posts/hand-writing-dns-messages/
# https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf

import os
import socket
import struct
import time
import traceback
import codecs

import json
from binascii import hexlify, unhexlify

from dnslib.bimap import BimapError
from dnslib.buffer import BufferError
from dnslib.bit import get_bits
from dnslib import DNSHeader, DNSRecord, DNSBuffer, DNSLabel, DNSError, DNSQuestion, RR
from kitty.targets.server import ServerTarget
from kitty.data.report import Report

from framework.services.parse_config import ConfigParser
from framework.utils.generate_uuid import GenerateUUID


class DNSBufferExt(DNSBuffer):
    offset: object

    def __init__(self, data=b''):
        """
            Add 'names' dict to cache stored labels
        """
        super(DNSBufferExt, self).__init__(data)
        self.names = {}

    def decode_name(self, last=-1):
        """
            Orig docstring: Decode label at current offset in buffer (following pointers
            to cached elements where necessary)
            This method has overwritten because of Kitty. Sometimes it produces fuzzed data
            with iso-8859-1 encodings that the original DNS lib can not handle because that type
            of DNS domain label not exists in real world scenario but here it is.
        """
        label = []
        done = False
        while not done:
            (length,) = self.unpack("!B")
            if get_bits(length, 6, 2) == 3:
                # Pointer
                self.offset -= 1
                pointer = get_bits(self.unpack("!H")[0], 0, 14)
                save = self.offset
                if last == save:
                    raise BufferError(
                        f"Recursive pointer in DNSLabel [offset={self.offset:d},pointer={pointer:d},"
                        f"length={len(self.data):d}]")
                if pointer < self.offset:
                    self.offset = pointer
                else:
                    # Pointer can't point forwards
                    raise BufferError(
                        f"Invalid pointer in DNSLabel [offset={self.offset:d},pointer={pointer:d},"
                        f"length={len(self.data):d}]")
                label.extend(self.decode_name(save).label)
                self.offset = save
                done = True
            else:
                if length > 0:
                    l = self.get(length)
                    try:
                        l.decode()
                    except:
                        l.decode('iso-8859-1')
                    label.append(l)
                else:
                    done = True
        return DNSLabel(label)


class DNSRecordExt(DNSRecord):
    """
    Following the usage of DNSBuffer class to use the DNSBufferExt to inherit the behaviour.
    """

    @classmethod
    def parse(cls, packet):
        """
            Parse DNS packet data and return DNSRecord instance
            Recursively parses sections (calling appropriate parse method)
        """
        buffer = DNSBufferExt(packet)
        try:
            header = DNSHeader.parse(buffer)
            questions = []
            rr = []
            auth = []
            ar = []
            for i in range(header.q):
                questions.append(DNSQuestion.parse(buffer))
            for i in range(header.a):
                rr.append(RR.parse(buffer))
            for i in range(header.auth):
                auth.append(RR.parse(buffer))
            for i in range(header.ar):
                ar.append(RR.parse(buffer))
            return cls(header, questions, rr, auth=auth, ar=ar)
        except DNSError:
            raise
        except (BufferError, BimapError) as e:
            raise DNSError(f"Error unpacking DNSRecord [offset={buffer.offset:d}]: {e}")

    def pack(self):

        self.set_header_qa()
        buffer = DNSBufferExt()
        self.header.pack(buffer)
        for q in self.questions:
            q.pack(buffer)
        for rr in self.rr:
            rr.pack(buffer)
        for auth in self.auth:
            auth.pack(buffer)
        for ar in self.ar:
            ar.pack(buffer)
        return buffer.data


class DnsTarget(ServerTarget):
    """
    DnsTarget is implementation of a DNS target, which is inherited from ServerTarget and
    uses socket DGRAM to send DNS query over UDP.
    """

    def __init__(self, name, host, port, timeout=None, logger=None):
        """
        :param name: name of the target
        :param host: host ip (to send data to) currently unused
        :param port: port to send to
        :param timeout: socket timeout (default: None)
        :param logger: logger for the object (default: None)
        """
        super(DnsTarget, self).__init__(name, logger)
        self.host = host
        self.port = port
        if (host is None) or (port is None):
            raise ValueError('Host and port may not be None!')
        self.timeout = timeout
        self.socket = None
        self.bind_host = None
        self.bind_port = None
        self.expect_response = False
        self.config = ConfigParser()
        self.dns_a_record_status = self.config.get_dns_a_record_status()
        self.dns_ns_record_status = self.config.get_dns_ns_record_status()
        self.dns_txt_record_status = self.config.get_dns_txt_record_status()
        self.verbosity = self.config.get_generic_verbosity()
        self.logger.setLevel(self.verbosity)
        self._uuid = GenerateUUID.generate_uuid()
        self.question_length = None

    def set_binding(self, host=str, port=int, expect_response=False) -> None:
        """
        Enable binding of socket to given ip/address
        Katnip original method.
        """
        self.bind_host = host
        self.bind_port = port
        self.expect_response = expect_response
        self._do_bind()

    def _do_bind(self) -> None:
        """Katnip original method."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.bind((self.bind_host, self.bind_port))

    def _prepare_socket(self) -> None:
        """Katnip original method."""
        if self.bind_host is None:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self._do_bind()

    def pre_test(self, test_num=str) -> None:
        """Katnip original method."""
        super(DnsTarget, self).pre_test(test_num)
        if self.socket is None:
            self._prepare_socket()
            if self.timeout is not None:
                self.socket.settimeout(self.timeout)

    def post_test(self, test_num=str) -> None:
        """
        Katnip original method.
        Extended with report export.
        """

        super(DnsTarget, self).post_test(test_num)
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        if self.report.get('status') != Report.PASSED:
            if not os.path.exists(os.getcwd() + '/results/'):
                os.makedirs(os.getcwd() + '/results/')
            test_num = self.report.get('test_number')
            with open(os.getcwd() + '/results/{}-result-dns-{}.json'.format(test_num, str(self._uuid)), 'w',
                      encoding='utf-8') as file:
                json.dump(self.report.to_dict(), file, ensure_ascii=False, indent=4)
            file.close()

    def _construct_dns_query(self, data=bytes) -> bytes:
        """
        According to https://routley.io/posts/hand-writing-dns-messages/ and based on
        https://github.com/tigerlyb/DNS-Lookup-Tool-in-Python/blob/master/dnslookup.py
        :param data: the fuzzed data, in this case the DNS query foo.baz.bar.TLD
        :type data: bytes
        :return: the processed DNS query we will have been putting on wire.
        :rtype: bytes
        """

        global qtype
        domain = None

        try:
            domain = data.decode('utf-8')
        except:
            """UnicodeDecodeError: 'utf-8' codec can't decode byte 0xfe in position 1: invalid start byte"""
            self.logger.error(f"UnicodeDecodeError: {data.decode('iso-8859-1')}")
            domain = data.decode('iso-8859-1')

        qname = b''

        for label in domain.split('.'):
            # QNAME a domain name represented as a sequence of labels which consists
            # the length octet followed by the number of octets.
            # example.com consists two sections example and com
            # to construct the URL encode the section and producing series of bytes using struct in this case.
            # Section terminator is zero byte (00)

            qname = qname + struct.pack(b'!b' +
                                        str(len(label)).encode('utf-8') +
                                        b's', len(label),
                                        label.encode('utf-8'))

        """
        Header:

        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      ID                       | header_layer_1
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   | header_layer_2
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    QDCOUNT                    | header_layer_3
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ANCOUNT                    | header_layer_4
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    NSCOUNT                    | header_layer_5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ARCOUNT                    | header_layer_6
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        """
        header_layer_1 = b'\x41\x41'  # ID AA this is an ID assigned by the program that generates the query
        header_layer_2 = b'\x01\x00'  #  QR Query parameters, QR: 1 bit flag query or response, we set this flag to 0.
        #  Opcode A 4 bit field
        # 0: inverse query,
        # 1: standard query,
        # 2: server status request
        # 3: reserved for further usage
        # TC: 1 bit flag to truncat message
        # RD: 1 bit flag if recursion is desired
        #  QDCOUNT: 16 bit integer to specifying the number of entries in the question section.
        # 01 00 hexadecimal is 0000 0001 0000 0000 from QR to RCODE represents a standard
        # DNS query. Fields are not mentioned sets to 0.
        header_layer_3 = b'\x00\x01'  # Number of questions, we ask one question per query
        header_layer_4 = b'\x00\x00'  #  Number of answers
        header_layer_5 = b'\x00\x00'  #  Number of authority records
        header_layer_6 = b'\x00\x00'  # Number of additional records

        header = header_layer_1 + header_layer_2 + header_layer_3 + header_layer_4 + header_layer_5 + header_layer_6
        # print(header)
        # print(type(header))
        """
        0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                     QNAME                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QTYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QCLASS                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        """
        # QNAME holds by domain_labels variable, explained above.
        # QTYPE the DNS record type we looking for
        # QTYPE A: 1 NS: 2 TXT: 16
        #  QCLASS the class we are looking up, we using IN which has a value of 1, internet.
        # here again terminate x00\x00 is the zero byte terminator.
        terminate = b'\x00\x00'

        if self.dns_a_record_status:
            qtype = b'\x01\x00'  # 1 ask A record
        elif self.dns_ns_record_status:
            qtype = b'\x02\x00'  #  2 ask NS
        elif self.dns_txt_record_status:
            qtype = b'\x10\x00'  # 16 ask TXT record

        qclass = b'\x01'
        question = qname + terminate + qtype + qclass
        message = header + question
        self.question_length = len(question)

        # USE DNS LIB TO HELP DEBUGGING MALFORMED HEADER
        # debug_question_header = DNSBuffer(binascii.unhexlify(header))
        # print('Debugg header: ', DNSHeader.parse(debug_question_header))

        return message

    def _send_to_target(self, data):
        message = self._construct_dns_query(data)
        self.logger.debug(f"Sending data to host: {self.host}, {self.port}")
        try:
            self.logger.info(f"Sending data {data.decode('utf-8')}")
        except:
            self.logger.info(f"Sending data {data.decode('iso-8859-1')}")
        self.socket.sendto(message, (self.host, self.port))

    def _receive_from_target(self) -> bytes:
        """
        This function is in charge to process the DNS reply back on the road.
        According to the response:

         0   1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                                               /
        /                     NAME                      /
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     TYPE                      |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     CLASS                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TTL                      |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    RDLENGTH                   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        /                     RDATA                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


        :return: the response in bytes
        :rtype: bytes
        """

        response, addr = self.socket.recvfrom(1024)
        return response

    def transmit(self, payload):

        """
        This is the original transmit method from ServerTarget overwritten with
        DNS response code specific reporting

        Accordin to:
        https://support.umbrella.com/hc/en-us/articles/232254248-Common-DNS-return-codes-for-any-DNS-service-and-Umbrella-

        NOERROR     RCODE:0     DNS Query completed successfully
        FORMERR     RCODE:1     DNS Query Format Error
        SERVFAIL    RCODE:2     Server failed to complete the DNS request
        NXDOMAIN    RCODE:3     Domain name does not exist.
        NOTIMP      RCODE:4     Function not implemented
        REFUSED     RCODE:5     The server refused to answer for the query
        YXDOMAIN    RCODE:6     Name that should not exist, does exist
        XRRSET      RCODE:7     RRset that should not exist, does exist
        NOTAUTH     RCODE:8     Server not authoritative for the zone
        NOTZONE     RCODE:9     Name not in zone

        Original method docstring:
        Transmit single payload, and receive response, if expected.
        The actual implementation of the send/receive should be in
        ``_send_to_target`` and ``_receive_from_target``.

        :type payload: str
        :param payload: payload to send
        :rtype: str
        :return: the response (if received)
        """

        DNS_RETRUN_CODES = [
            'NOERROR',
            'FORMERR',
            'SERVFAIL',
            'NXDOMAIN',
            'NOTIMP',
            'REFUSED',
            'YXDOMAIN',
            'XRRSET',
            'NOTAUTH',
            'NOTZONE'
        ]

        DNS_EXCLUDE = [0, 3, 5]

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
                    printed_response = printed_response if len(printed_response) < 100 else (printed_response[:100]
                                                                                             + ' ...')
                    self.logger.info(f"response({len(response)}): {printed_response}")

                    server_message = response.split(b',', 0)
                    reply = codecs.encode(server_message[0], 'hex')

                    # USE DNS LIB TO HELP DEBUGGING MALFORMED HEADER
                    debug_response_header = DNSBufferExt(unhexlify(reply))
                    parsed_dns_response_header = DNSHeader.parse(debug_response_header)
                    dns_response_message = DNSRecordExt.parse(server_message[0])

                    if int(parsed_dns_response_header.rcode) not in DNS_EXCLUDE:
                        self.logger.error(f"DNS response code: "
                                          f"{DNS_RETRUN_CODES[int(parsed_dns_response_header.rcode)]}")
                        self.logger.error(f"Debug header: {str(parsed_dns_response_header)}")
                        trans_report.failed(f"Failure in response, code: "
                                            f"{DNS_RETRUN_CODES[int(parsed_dns_response_header.rcode)]}")
                        trans_report.add('Response', str(dns_response_message))
                        trans_report.add('traceback', traceback.format_exc())
                        self.receive_failure = True
                        self.report.set_status('failed')

                except Exception as ex2:
                    trans_report.failed('failed to receive response: %s' % ex2)
                    trans_report.add('traceback', traceback.format_exc())
                    self.logger.error(f"target.transmit - failure in receive (exception: {ex2})")
                    self.logger.error(traceback.format_exc())
                    self.receive_failure = True
            else:
                response = ''
        except Exception as ex1:
            trans_report.failed('failed to send payload: %s' % ex1)
            trans_report.add('traceback', traceback.format_exc())
            self.logger.error(f"target.transmit - failure in send (exception: {ex1})")
            self.logger.error(traceback.format_exc())
            self.send_failure = True
        self.transmission_count += 1
        return response
