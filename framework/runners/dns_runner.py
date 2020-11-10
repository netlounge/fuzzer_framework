"""
Module is charge for run the fuzz test.

Fuzzer  +--- Model *--- Template *--- Field
        |
        +--- Target  +--- Controller
        |            |
        |            *--- Monitor
        |
        +--- Interface


https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf


Domain Name System (query)
    [Response In: 1852]
    Transaction ID: 0x241a
    Flags: 0x0100 (Standard query)
        0... .... .... .... = Response: Message is a query
        .000 0... .... .... = Opcode: Standard query (0)
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... .0.. .... = Z: reserved (0)
        .... .... ...0 .... = Non-authenticated data OK: Non-authenticated data is unacceptable
    Questions: 1
    Answer RRs: 0
    Authority RRs: 0
    Additional RRs: 0
    Queries
        www.google.com: type A, class IN
            Name: www.google.com
            Type: A (Host address)
            Class: IN (0x0001)

Domain Name System (response)
    [Request In: 1851]
    [Time: 0.000125000 seconds]
    Transaction ID: 0x241a
    Flags: 0x8180 (Standard query response, No error)
        1... .... .... .... = Response: Message is a response
        .000 0... .... .... = Opcode: Standard query (0)
        .... .0.. .... .... = Authoritative: Server is not an authority for domain
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... 1... .... = Recursion available: Server can do recursive queries
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
        .... .... .... 0000 = Reply code: No error (0)
    Questions: 1
    Answer RRs: 3
    Authority RRs: 0
    Additional RRs: 0
    Queries
        www.google.com: type A, class IN
            Name: www.google.com
            Type: A (Host address)
            Class: IN (0x0001)
    Answers
        www.google.com: type CNAME, class IN, cname www.l.google.com
            Name: www.google.com
            Type: CNAME (Canonical name for an alias)
            Class: IN (0x0001)
            Time to live: 3 days, 21 hours, 52 minutes, 57 seconds
            Data length: 18
            Primary name: www.l.google.com
        www.l.google.com: type A, class IN, addr 66.249.89.99
            Name: www.l.google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 3 minutes, 47 seconds
            Data length: 4
            Addr: 66.249.89.99
        www.l.google.com: type A, class IN, addr 66.249.89.104
            Name: www.l.google.com
            Type: A (Host address)
            Class: IN (0x0001)
            Time to live: 3 minutes, 47 seconds
            Data length: 4
            Addr: 66.249.89.104

"""
import time
from kitty.model import Template, GraphModel
from kitty.fuzzers import ServerFuzzer
from kitty.interfaces import WebInterface
from kitty.model.low_level.field import Delimiter, String

from framework.core.fuzz_object import FuzzObject
from framework.services.parse_config import ConfigParser
from framework.controllers.dns.dns_controller import DnsController
from framework.targets.dns_target import DnsTarget


class DnsRunner(FuzzObject):

    def __init__(self, name='DnsRunner', logger=None):
        super(DnsRunner, self).__init__(name, logger)
        self.config = ConfigParser()
        self.target_host = self.config.get_target_host_name()
        self.target_port = self.config.get_target_port()
        self.timeout = self.config.get_dns_timout()
        self.tld = self.config.get_dns_tld()
        self.default_labels = self.config.get_dns_default_labels()

    def run_dns(self):
        """
        kitty low level field model
        https://kitty.readthedocs.io/en/latest/kitty.model.low_level.field.html
        """
        fields = []
        counter = 0
        dns_label_length = len(self.default_labels.split('.'))
        dns_label_list = self.default_labels.split('.')

        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Initiate template for DNS ...")
        while counter < dns_label_length:
            fields.append(String(dns_label_list[counter], name='sub_domain_' + str(counter), max_size=10))
            fields.append(Delimiter('.', name='delimiter_' + str(counter)))
            counter += 1

        fields.append(String(self.tld, name='tld', fuzzable=False))

        dns_query = Template(name='DNS_QUERY', fields=fields)

        """
        dns_query = Template(name='DNS_QUERY', fields=[
            String('r', name='sub_domain', max_size=10),
            Delimiter('.', name='space1"),
            String('rf', name='sub_domain2', max_size=10),
            Delimiter('.', name='space2"),
            String(self.tld, name='tld', fuzzable=False),
        ])
        """
        # define target, in this case this is SslTarget because of HTTPS
        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Prepare DnsTarget ...")
        target = DnsTarget(name='DnsTarget', host=self.target_host, port=self.target_port, timeout=self.timeout)
        target.set_expect_response('true')
        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Prepare DnsController ...")
        controller = DnsController('DnsController', host=self.target_host, port=self.target_port)
        target.set_controller(controller)

        # Define model
        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Defining GraphModel...")
        model = GraphModel()
        model.connect(dns_query)

        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Prepare Server Fuzzer ...")
        fuzzer = ServerFuzzer()
        fuzzer.set_interface(WebInterface(port=26001))
        fuzzer.set_model(model)
        fuzzer.set_target(target)
        fuzzer.set_delay_between_tests(1)
        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Start Fuzzer...")
        self.logger.info(f"[Further info are in the related Kitty log output!]")
        fuzzer.start()
        self.logger.info(f"[{time.strftime('%H:%M:%S')}] End Fuzzer Session")
        fuzzer.stop()
