"""Generate uuid"""
import uuid
from framework.utils.decorators import singleton


class GenerateUUID:
    """Generate UUID for each session"""

    @staticmethod
    @singleton
    def generate_uuid() -> object:
        """Generates Universal Unique Identifier for the actual session
           I force this with a decorator to be a singleton because of UUID must
           be the same in each run and each file.
        :returns: Universal Unique Identifier
        :rtype: object
        """
        return uuid.uuid1()
