"""
This could be a further function if no compiled pb.py found
This might be useful:
https://github.com/protocolbuffers/protobuf/blob/61301f01552dd84d744a05c88af95833c600a1a7/python/setup.py
"""

# TODO handle proto package relative / absolute import under python3
# TODO create a class which collects the proto-files into a working directory
# compile them, handle the module import inside if necessary, check each proto
# hash weather they modified or not.
# Maybe simulate the whole package structure somewhere

from framework.services.search_file import SearchFile


class CompileProto(SearchFile):

    def __init__(self, name='CompileProto', logger=None):
        """
        Constructor of file parser
        :type name of the object: object
        """
        super(CompileProto, self).__init__(name, logger)
