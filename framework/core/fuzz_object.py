"""
This class is the base object of the fuzzer wrapper framework.
Based on kittys kitty object but necessary to use independently
"""

import logging
import os
import time


from framework.utils.generate_uuid import GenerateUUID


class FuzzObject:
    """
    Basic class to define specific logging independently from Kitty
    for the fuzzer_framework
    """

    _logger = None
    _uuid = GenerateUUID.generate_uuid()
    log_file_name = './fuzzer_logs/%s-frmwrk_%s.log' % (str(_uuid), time.strftime("%Y%m%d-%H%M%S"),)

    @classmethod
    def get_logger(cls) -> object:
        """
        :return: the class logger
        """
        if FuzzObject._logger is None:
            logger = logging.getLogger('fuzzer')
            logger.setLevel(logging.INFO)
            consolehandler = logging.StreamHandler()
            console_format = logging.Formatter('[%(levelname)-1s] [%(asctime)s] [%(filename)s:%(lineno)s] '
                                               '[%(funcName)s] %(message)s')
            consolehandler.setFormatter(console_format)
            logger.addHandler(consolehandler)
            if not os.path.exists('./fuzzer_logs/'):
                os.mkdir('./fuzzer_logs')
            filehandler = logging.FileHandler(FuzzObject.log_file_name)
            file_format = console_format
            filehandler.setFormatter(file_format)
            logger.addHandler(filehandler)
            FuzzObject._logger = logger
        return FuzzObject._logger

    @classmethod
    def get_log_file_name(cls) -> object:
        """
        Get the logger file name.
        :return: object
        """
        return FuzzObject.get_log_file_name()

    @classmethod
    def set_verbosity(cls, verbosity):
        """

        :param verbosity: the level of the verbosity DEBUG, INFO
        :rtype: object
        """
        # TODO extend point 02: implement WARNING, CRITICAL
        if verbosity > 0:
            logger = FuzzObject.get_logger()
            levels = [logging.DEBUG]
            verbosity = min(verbosity, len(levels)) - 1
            logger.setLevel(levels[verbosity])

    def __init__(self, name, logger=None):
        """

        :type logger: object
        """
        self.name = name
        if logger:
            self.logger = logger
        else:
            self.logger = FuzzObject.get_logger()

    def get_description(self):
        """
        :rtype: str
        :return: the description of the object. by default only prints the object type.
        """
        return type(self).__name__

    def get_name(self):
        """
        :rtype: str
        :return: object's name
        """
        return self.name
