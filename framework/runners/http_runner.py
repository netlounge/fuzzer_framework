"""
Module is charge for run the fuzz test.

Fuzzer  +--- Model *--- Template *--- Field
        |
        +--- Target  +--- Controller
        |            |
        |            *--- Monitor
        |
        +--- Interface

https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
https://buildmedia.readthedocs.org/media/pdf/kitty/latest/kitty.pdf
https://kitty.readthedocs.io/en/latest/data_model/writing_encoders.html#example-1-aligned-string

HTTP GET:
 ---------------------------------------------------------------------------------
 GET /tutorial/requesting?query_api=335c7ee2-0d93-11ea-b76a-7e46358fd919 HTTP/1.1
 Host: localhost:5000
 Content-Type: application/octet-stream


 ---------------------------------------------------------------------------------

 GET / HTTP/1.1
 Host: somehost.com
 Content-Type:  application/x-www-form-urlencoded



 # 1. Method - a string with the value "GET"
 # 1.a The space between Method and Path
 # 2. Path - a string with the value "/index.html"
 # 2.a. The space between Path and Protocol
 # 3.a Protocol Name - a string with the value "HTTP"
 # 3.b The '/' after "HTTP"
 # encode the major version as decimal number
 # 3.d The '.' between 1 and 1
 # encode the minor version as decimal number
 # 4. The double "new lines" ("\r\n\r\n") at the end of the request

HTTP POST (PUT):
 The rest of the header is equivalent with the GET request header.

 POST /foo/bar HTTP/1.1
 Host: somehost.com
 Content-Type:  text/plain
 Content-Length: str(len(self.http_payload))

    {"data_item": "foo"}


"""
import time

from kitty.model import Template, ENC_INT_DEC, GraphModel
from kitty.fuzzers import ServerFuzzer
from kitty.interfaces import WebInterface
from kitty.model.low_level.aliases import Dword
from kitty.model.low_level.field import String, Delimiter, Static

from framework.core.fuzz_object import FuzzObject
from framework.services.parse_config import ConfigParser
from framework.utils.generate_uuid import GenerateUUID
from framework.controllers.http.http_get_controller import HttpGetController
from framework.targets.http_target import HttpTarget


class HttpRunner(FuzzObject):
    """
       HttpRunner class created according to the Kitty/Katnip API documentations.
       The class is a part of the Fuzzer Framework.

    """

    def __init__(self, name='HttpRunner', logger=None) -> object:
        """
        HttpRunner constructor
        :param name: the name of the class
        :param logger: logger from the framework
        """
        super(HttpRunner, self).__init__(name, logger)
        self.config = ConfigParser()
        self.target_host = self.config.get_target_host_name()
        self.target_port = self.config.get_target_port()
        self.http_get = self.config.get_http_get_method()
        self.http_post_put = self.config.get_http_post_put_method()
        self.http_post_update = self.config.get_http_post_update_method()
        self.http_delete = self.config.get_http_delete_method()
        self.http_fuzz_protocol = self.config.get_http_fuzz_protocol()
        self.http_path = self.config.get_http_path()
        self.http_content_type = self.config.get_http_content_type()
        self.http_payload = self.config.get_http_payload()
        self.gen_uuid = GenerateUUID.generate_uuid()

    def run_http(self) -> None:
        """
        This method provides the HTTP GET, POST, ... , templating for the HTTP header
        as fields, data provided by the config, explained in the User Documentation.
        kitty low level field model
        https://kitty.readthedocs.io/en/latest/kitty.model.low_level.field.html

        :returns: None
        :rtype: None

        """
        http_template = None
        # HTTP GET TEMPLATE
        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Initiate template for HTTP GET ...")
        if self.http_get:
            http_template = Template(name='HTTP_GET', fields=[
                # GET / HTTP/1.1
                String('GET', name='method', fuzzable=False),
                Delimiter(' ', name='delimiter-1', fuzzable=False),
                String(self.http_path, name='path'),
                Delimiter(' ', name='delimiter-2', fuzzable=self.http_fuzz_protocol),
                String('HTTP', name='protocol name', fuzzable=self.http_fuzz_protocol),
                Delimiter('/', name='fws-1', fuzzable=self.http_fuzz_protocol),
                Dword(1, name='major version', encoder=ENC_INT_DEC, fuzzable=self.http_fuzz_protocol),
                Delimiter('.', name='dot-1', fuzzable=self.http_fuzz_protocol),
                Dword(1, name='minor version', encoder=ENC_INT_DEC, fuzzable=self.http_fuzz_protocol),
                Static('\r\n', name='EOL-1'),

                # User agent
                String('User-Agent:', name='user_agent_field', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-3', fuzzable=self.http_fuzz_protocol),
                String('Fuzzer', name='user-agent_name', fuzzable=self.http_fuzz_protocol),
                Static('\r\n', name='EOL-2'),

                # Token generated by framework to support following the session if necessary.
                String('Fuzzer-Token:', name='fuzzer_token', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-4', fuzzable=self.http_fuzz_protocol),
                String(str(self.gen_uuid), name='fuzzer_token_type', fuzzable=False),  # do not fuzz token
                Static('\r\n', name='EOL-3'),

                # Accept
                String('Accept:', name='accept', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-5', fuzzable=self.http_fuzz_protocol),
                String('*/*', name='accept_type_', fuzzable=self.http_fuzz_protocol),
                Static('\r\n', name='EOL-4'),

                # Cache-control no-cache by default
                String('Cache-Control:', name='cache-control', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-6', fuzzable=self.http_fuzz_protocol),
                String('no-cache', name='cache_control_type', fuzzable=self.http_fuzz_protocol),
                Static('\r\n', name='EOL-5'),

                # Host, the target host
                String('Host:', name='host_name', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-7', fuzzable=self.http_fuzz_protocol),
                String(self.target_host, name='target_host', fuzzable=False),  # do not fuzz target host address!
                Static('\r\n', name='EOL-6'),

                # Connection close, do not use keep-alive it results only one mutation, than the
                # fuzzer will hang.
                String('Connection:', name='accept_encoding', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-8', fuzzable=self.http_fuzz_protocol),
                String('close', name='accept_encoding_types', fuzzable=False),  # do not fuzz this field!
                Static('\r\n', name='EOM-7'),

                # Content-type from config.
                String('Content-Type:', name='Content-Type', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-9', fuzzable=self.http_fuzz_protocol),
                String(self.http_content_type, name='content_type_', fuzzable=self.http_fuzz_protocol),
                Static('\r\n\r\n', name='EOM-8')
            ])

        if self.http_post_put:
            self.logger.info(f"[{time.strftime('%H:%M:%S')}] Initiate template for HTTP POST ...")
            http_template = Template(name='HTTP_POST', fields=[
                # POST / HTTP/1.1
                String('POST', name='method', fuzzable=False),
                Delimiter(' ', name='delimiter-1', fuzzable=False),
                String(self.http_path, name='path'),
                Delimiter(' ', name='delimiter-2', fuzzable=self.http_fuzz_protocol),
                String('HTTP', name='protocol name', fuzzable=self.http_fuzz_protocol),
                Delimiter('/', name='fws-1', fuzzable=self.http_fuzz_protocol),
                Dword(1, name='major version', encoder=ENC_INT_DEC, fuzzable=self.http_fuzz_protocol),
                Delimiter('.', name='dot-1', fuzzable=self.http_fuzz_protocol),
                Dword(1, name='minor version', encoder=ENC_INT_DEC, fuzzable=self.http_fuzz_protocol),
                Static('\r\n', name='EOL-1'),

                # User agent
                String('User-Agent:', name='user_agent_field', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-3', fuzzable=self.http_fuzz_protocol),
                String('Fuzzer', name='user-agent_name', fuzzable=self.http_fuzz_protocol),
                Static('\r\n', name='EOL-2'),

                # Token generated by framework to support following the session if necessary.
                String('Fuzzer-Token:', name='fuzzer_token', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-4', fuzzable=self.http_fuzz_protocol),
                String(str(self.gen_uuid), name='fuzzer_token_type', fuzzable=self.http_fuzz_protocol),
                Static('\r\n', name='EOL-3'),

                # Accept
                String('Accept:', name='accept', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-5', fuzzable=self.http_fuzz_protocol),
                String('*/*', name='accept_type_', fuzzable=self.http_fuzz_protocol),
                Static('\r\n', name='EOL-4'),

                # Cache-control no-cache by default
                String('Cache-Control:', name='cache-control', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-6', fuzzable=self.http_fuzz_protocol),
                String('no-cache', name='cache_control_type', fuzzable=self.http_fuzz_protocol),
                Static('\r\n', name='EOL-5'),

                # Host, the target host
                String('Host:', name='host_name', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-7', fuzzable=self.http_fuzz_protocol),
                String(self.target_host, name='target_host', fuzzable=False),  # do not fuzz target host address!
                Static('\r\n', name='EOL-6'),

                # Content length: obvious payload lenght.
                String('Content-Length:', name='content_length', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-9', fuzzable=self.http_fuzz_protocol),
                String(str(len(self.http_payload)), name='content_length_len', fuzzable=False),
                Static('\r\n', name='EOM-8'),

                # Connection close, do not use keep-alive it results only one mutation, than the
                # fuzzer will hang.
                String('Connection:', name='accept_encoding', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-8', fuzzable=self.http_fuzz_protocol),
                String('close', name='accept_encoding_types', fuzzable=False),  # do not fuzz this field!
                Static('\r\n', name='EOM-7'),

                # Content type
                String('Content-Type:', name='Content-Type', fuzzable=self.http_fuzz_protocol),
                Delimiter(' ', name='delimiter-10', fuzzable=self.http_fuzz_protocol),
                String(self.http_content_type, name='content_type_', fuzzable=self.http_fuzz_protocol),
                Static('\n\r\n', name='EOM-9'),

                # Payload
                String(self.http_payload, name='payload'),
                Static('\r\n\r\n', name='EOM-10')
            ])

        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Prepare HttpTarget ...")
        target = HttpTarget(name='HttpTarget',
                            host=self.target_host,
                            port=self.target_port,
                            max_retries=10,
                            timeout=None)
        target.set_expect_response('true')
        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Prepare HttpController ...")
        controller = HttpGetController('HttpGetController',
                                       host=self.target_host,
                                       port=self.target_port)
        target.set_controller(controller)
        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Defining GraphModel...")
        model = GraphModel()
        model.connect(http_template)
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
