"""
This module is in charge of searching a given file type form a given
directory.
https://github.com/netlounge/thesis/wiki/Protobuf-module-design
"""
import os
from pathlib import Path

from framework.core.fuzz_object import FuzzObject


class SearchFile(FuzzObject):
    """Searching file in a given directory."""

    def __init__(self,
                 name='SearchFile',
                 logger=None,
                 file_type=str,
                 file_path=str,
                 ):
        """
        Constructor of file parser
        :type name of the object: object
        """
        super(SearchFile, self).__init__(name, logger)
        self.file_type = file_type
        self.file_path = file_path
        self.files_in_base_path = None
        self.ROOT_DIR = os.path.dirname(os.path.realpath('../'))

    @property
    def search_file(self):
        """
        This function is responsible to read files from a given folder.
        _:return The file name found
        :rtype: str
        """
        # TODO extend point 01: parse files from given folder, S3 or else
        self.file_path = Path(self.ROOT_DIR + self.file_path)
        self.logger.info(f"CONF - file dir: {self.file_path}")
        files = []
        for _, _directories, _files in os.walk(self.file_path):
            for _file in _files:
                if _file.endswith(self.file_type):
                    files.append(_file)
        return files
