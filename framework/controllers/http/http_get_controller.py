"""
Module in charge of preparing the victim for the test.

Fuzzer  +--- Model *--- Template *--- Field
        |
        +--- Target  +--- Controller
        |            |
        |            *--- Monitor
        |
        +--- Interface
"""

import socket
from kitty.controllers.base import BaseController


class HttpGetController(BaseController):
    """
    This controller controls our HTTPS GET
    """

    def __init__(self, name, host, port, logger=None):
        '''
        :param name: name of the object
        :param host: Listen address for target
        :param port: Listen port for target
        :param logger: logger for the controller (default: None)
        :example:

            ::
                controller = ServerController(name='ServerController', host='target_ip', port=target_port)
        '''
        super(HttpGetController, self).__init__(name, logger)
        self._host = host
        self._port = port
        self._server = None
        self._active = False

    def setup(self):
        super(HttpGetController, self).setup()
        self.logger.info('Check the victim is alive!')
        #self._restart_target()
        if not self.is_victim_alive():
            msg = 'Controller cannot start target'
            raise Exception(msg)

    def teardown(self):
        # TODO
        """
        Check the server state after testing
        :return:
        """
        super(HttpGetController, self).teardown()
        if not self.is_victim_alive():
            msg = 'Target is already down'
            self.logger.error(msg)
        else:
            msg = 'Test Finish'
            self.logger.info(msg)

    def post_test(self):
        """
        Test server state after tests
        :return:
        """
        super(HttpGetController, self).post_test()
        if not self.is_victim_alive():
            if self._server:
                out, err = self._server.communicate()
                self.logger.error(err)
                self.report.failed("Target does not respond")
                self.report.add('Traceback', err)
            else:
                self.logger.error("Target does not respond")
                self.report.failed("Target does not respond")

    def pre_test(self, test_number):
        """
        Pre test test
        :param test_number:
        :return:
        """
        self._restart_target()
        super(HttpGetController, self).pre_test(test_number)

    def _restart_target(self):
        """
        Restart our Target.
        """
        self.is_victim_alive()

    def is_victim_alive(self):
        # TODO  Implement here a HTTPS GET and check the status code 200
        """
        Method check the server HTTPS response code
        :return:
        """
        self._active = False
        try:
            _sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _sock.settimeout(1)
            _sock.connect((self._host, self._port))
            _sock.close()
            self._active = True
        except socket.error:
            return self._active
        return self._active
