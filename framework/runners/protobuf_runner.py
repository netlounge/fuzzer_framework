"""
Files involved:

protobuf_file_generator - initial tester to fuzz into binary
    /Users/balazsattila/Env/fuzz_framework/framework/services/protobuf_generator.py

protobuf_target - extend and refactor file target to handle protobuf binary message file
    /Users/balazsattila/Env/fuzz_framework/third_party/katnip/katnip/targets/protobuf.py

protobuf_template - templating system which can handle protobuf message creation
    /Users/balazsattila/Env/fuzz_framework/third_party/katnip/katnip/templates/protobuf.py

protobuf_runner - this file which will run the protobuf over HTTP
    /Users/balazsattila/Env/fuzz_framework/framework/bin/protobuf_runner.py

protobuf_controller - this control and lego the fuzzer process via Kitty/Katnip API
    /Users/balazsattila/Env/fuzz_framework/framework/controllers/protobuf/protobuf_controller.py


Architecture of Fuzzing according to Kitty API.:

   Fuzzer  +--- Model *--- Template *--- Field
        |
        +--- Target  +--- Controller
        |            |
        |            *--- Monitor
        |
        +--- Interface (WebInterface)

"""
import time
import six

from kitty.model import Template, GraphModel
from kitty.fuzzers import ServerFuzzer
from kitty.interfaces import WebInterface

from framework.core.fuzz_object import FuzzObject
from framework.services.parse_config import ConfigParser
from framework.utils.utils import FrameworkUtils
from framework.utils import ext_json
from framework.controllers.protobuf.protobuf_controller import ProtobufController
from framework.targets.protobuf_target import ProtobufTarget


class ProtobufRunner(FuzzObject):

    def __init__(self, pb2_api, name='ProtobufRunner', logger=None):
        super(ProtobufRunner, self).__init__(name, logger)
        self.pb2_api = pb2_api
        self.config = ConfigParser()
        self.target_host = self.config.get_target_host_name()
        self.target_port = self.config.get_target_port()
        self.frmu = FrameworkUtils()

    def run_proto(self) -> None:
        """
        kitty low level field model
        https://kitty.readthedocs.io/en/latest/kitty.model.low_level.field.html
        """

        js = ext_json.dict_to_JsonObject(dict(self.pb2_api[0]['Messages']), 'api')

        template_a = Template(name='Api', fields=js)

        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Prepare ProtobufTarget ")
        target = ProtobufTarget('ProtobufTarget',
                                host=self.target_host,
                                port=self.target_port,
                                max_retries=10,
                                timeout=None,
                                pb2_module=self.pb2_api[1])

        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Prepare ProtobufController ")
        controller = ProtobufController('ProtobufController', host=self.target_host, port=self.target_port)
        target.set_controller(controller)
        #target.set_expect_response('true')
        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Defining GraphModel")
        model = GraphModel()
        model.connect(template_a)

        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Prepare Server Fuzzer ")
        fuzzer = ServerFuzzer()
        fuzzer.set_interface(WebInterface(port=26001))
        fuzzer.set_model(model)
        fuzzer.set_target(target)
        fuzzer.start()
        self.logger.info(f"[{time.strftime('%H:%M:%S')}] Start Fuzzer")
        self.logger.info(f"[Further info are in the related Kitty log output!]")
        six.moves.input('press enter to exit')
        self.logger.info(f"[{time.strftime('%H:%M:%S')}] End Fuzzer Session")
        fuzzer.stop()
