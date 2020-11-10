"""Protobuf API parser module"""

import json
from collections import OrderedDict

from framework.core.fuzz_object import FuzzObject
from framework.utils.utils import FrameworkUtils
from framework.services.parse_config import ConfigParser


class MessageCompareException(Exception):
    """Exception for compare msgs given from config and api."""


class ParseProtoApi(FuzzObject):
    """
    To parse/transform a Protobuf API into Dictionary.
    """
    def __init__(self, name='ParseProtoApi', logger=None, pb2_api_file=str, module_path=str):
        """
        :param name: name of the object
        :param logger: None
        :param pb2_api_file: the main protobuf api module
        :param module_path: the path of the module repr as dot delimited

        """
        super(ParseProtoApi, self).__init__(name, logger)
        self.pb2_api_file = pb2_api_file
        self.moule_path = module_path
        self.context = []

    def _message_types_by_name_keys(self, obj: object) -> list:
        """
        If a DESCRIPTOR tells that the message has more message types, it returns it
        if it has more it returns a list of messages.
        :rtype: list
        """
        try:
            message_types_by_name_keys = obj.DESCRIPTOR.message_types_by_name.keys()
            self.logger.info(f"PPROT MSG - Message_types_by_name: {message_types_by_name_keys}")
            return message_types_by_name_keys
        except:
            self.logger.info(f"PPROT MSG - Message has no message_types_by_name: {obj}")

    def _message_types_by_name_items(self, obj: object) -> list:
        """
        If a DESCRIPTOR tells that the message has more message types, it returns it
        if it has more it returns a list of messages.
        :rtype: list
        """
        try:
            message_types_by_items = obj.DESCRIPTOR.message_types_by_name.items()
            self.logger.info(f"PPROT MSG - message_types_by_items: {message_types_by_items}")
            return message_types_by_items
        except:
            self.logger.info(f"PPROT MSG - Message has no message_types_by_items: {obj}")

    def _get_message_by_config(self, pb_obj: object) -> list:
        """
        A compare and section creation depending on the provided class list in ['protobuf']['classes'] config
        object; If it is empty we rely on the protobuf descriptor information and we process every top
        level messages, if list is provided then the logic seeking for section amid messages and config provided
        messages, obviously logic process only the section of the two aggregation. For comparing the two lists
        the logic uses the string representation of messages via _message_types_by_names.
        The method will returns the list of message_types_by_items method which is a list of tuples including
        the string representation of the message and the object as well.

        :param pb_obj: protobuf object
        :return: list of top level messages
        :rtype: list
        """
        configuration = ConfigParser()
        messages_by_config: list = configuration.get_protobuf_classes_to_send()
        messages_by_name: list = self._message_types_by_name_keys(pb_obj)
        messages_by_item: list = self._message_types_by_name_items(pb_obj)

        if not messages_by_config:
            return list(messages_by_item)

        intersection = list(set(messages_by_name) & set(messages_by_config))
        if len(messages_by_config) == len(intersection) and \
           len(list(messages_by_name)) == len(intersection):
            self.logger.info(f"PPROT MSG - Messages provided by configuration: {messages_by_config} "
                             f"messages by pb object: {list(messages_by_name)} - section: {intersection} - OK!")
            return list(messages_by_item)
        if len(intersection) < len(list(messages_by_name)):
            for inter_item in intersection:
                for msg_str_item, _ in list(messages_by_item):
                    if inter_item not in msg_str_item:  # remove tuple from list
                        return list(filter(lambda x: str(x[0]) not in str(msg_str_item), list(messages_by_item)))
        else:
            self.logger.info(f"PPROT MSG - Config message {len(messages_by_name)} and section "
                             f"{intersection} mismatch!"
                             f"Maybe something wrong in the config ['protobuf']['classes'] field!")
            raise MessageCompareException

        return []

    @staticmethod
    def _gather_field(msg_obj: object) -> list:
        """
        This function list each fields of a message and can deal with both nested and imported types.

        :param msg_obj: protobuf object mainly from the actual level
        :return: list of tuples 0: str repr, 1: the object
        :rtype: list
        """
        if hasattr(msg_obj, 'DESCRIPTOR'):
            return msg_obj.DESCRIPTOR.fields_by_camelcase_name.items()
        if hasattr(msg_obj, 'message_type'):
            return msg_obj.message_type.fields_by_camelcase_name.items()
        return []
    
    @staticmethod
    def _gather_enum(msg_obj: object) -> list:
        """
        This function list enum of a message and can deal with both nested and imported types.

        :param msg_obj: protobuf object mainly from the actual level
        :return: list of enum values
        :rtype: list
      """
        if hasattr(msg_obj, 'DESCRIPTOR'):
            return msg_obj.DESCRIPTOR.enum_type.values_by_name.keys()
        if hasattr(msg_obj, 'enum_type'):
            return msg_obj.enum_type.values_by_name.keys()
        return []

    @staticmethod
    def _u_dict_list(tlist: list, key: str, value: int) -> tuple:
        """
        This tinny generator finds the tuple in the list of tuples by key
        and changes the value. This is useful to maintain the processed levels.
        :param tlist: the list of tuples
        :param key: key that has to be modify
        :param value: the value to change
        :return: list of tuples
        :rtype list
        """
        return [(k, v) if (k != key) else (key, value) for (k, v) in tlist]

    def _parse_proto(self, msg_obj: object, message_name: str) -> OrderedDict:  # pylint: disable=R0912,R0915
        """
        This method is to recursively parse a given protobuf api and produces an OrderedDict
        representation of it. It's supporters are:
            - _gather_field function;
            - _gather_enum function;
            - _u_dict_list function;

        :note
        Its supporter is a list of tuples that maintains an inventory about which level being
        under process by name and how many elements the actual level has. After an elem has been processed
        the counter will be decreased, after no more elem left on the actual level, it removes the level from the list.

        Each level depending on its role will put on to an OrderedDict.
        Field with label 1,2 will be a nested dict;
        Field with label 3 will be a list of nested dict;

        With the update_nested function under the utils class the logic able to append each value to the
        particular key that has been created before;

        :param msg_obj: the protobuf api instance
        :param message_name: the name of the top level message
        :return: the OrderedDict representation of the protobuf API
        """
        self.context.append((message_name, len(self._gather_field(msg_obj))))
        message_dict = OrderedDict()
        message_dict.update({})
        utl = FrameworkUtils()

        def _recurse(msg_obj: object, message_dict: OrderedDict) -> OrderedDict:  # pylint: disable=R0912,R0915
            # traverse the message fields
            # checking field if not 11, or 14
            for ms_na, ms_ob in self._gather_field(msg_obj):

                if ms_ob.type in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 16, 17, 18]:
                    self.logger.info(f"Checked for non msg non field: {ms_na}, "
                                     f"object: {ms_ob}, "
                                     f"containtin type {ms_ob.containing_type.name}")
                    if ms_ob.label in [1, 2]:  # optional, required field
                        if len(self.context) == 1:
                            message_dict[ms_na] = utl.field_randomizer(ms_ob.type, ms_ob.default_value, None)
                        else:
                            message_dict = utl.update_nested(message_dict,
                                                             self.context[-1][0],
                                                             {
                                                                 ms_na: utl.field_randomizer(ms_ob.type,
                                                                                             ms_ob.default_value,
                                                                                             None)
                                                             },
                                                             self.context)
                            self.context = self._u_dict_list(self.context, self.context[-1][0], self.context[-1][1] - 1)
                            self.logger.debug(f"CONCHECK 1 :{self.context}")
                    elif ms_ob.label == 3:  # repeated field
                        message_dict = utl.update_nested(message_dict,
                                                         self.context[-1][0],
                                                         {
                                                             ms_na: [utl.field_randomizer(ms_ob.type,
                                                                                          ms_ob.default_value,
                                                                                          None)]
                                                         },
                                                         self.context)
                        self.context = self._u_dict_list(self.context, self.context[-1][0], self.context[-1][1] - 1)
                        self.logger.debug(f"CONCHECK 1 repeated {ms_ob.label} :{self.context}")

                elif ms_ob.type == 14:
                    if ms_ob.label in [1, 2]:
                        if len(self.context) == 1:
                            message_dict[ms_na] = utl.field_randomizer(ms_ob.type, ms_ob.default_value, None)
                        else:
                            message_dict = utl.update_nested(message_dict,
                                                             self.context[-1][0],
                                                             {
                                                                 ms_na: utl.field_randomizer(ms_ob.type,
                                                                                             ms_ob.default_value,
                                                                                             self._gather_enum(ms_ob))
                                                             },
                                                             self.context)
                            self.context = self._u_dict_list(self.context, self.context[-1][0], self.context[-1][1] - 1)
                    elif ms_ob.label == 3:
                        if len(self.context) == 1:
                            message_dict[ms_na] = utl.field_randomizer(ms_ob.type, ms_ob.default_value, None)
                        else:
                            message_dict = utl.update_nested(message_dict,
                                                             self.context[-1][0],
                                                             {
                                                                 ms_na: [utl.field_randomizer(ms_ob.type,
                                                                                              ms_ob.default_value,
                                                                                              self._gather_enum(ms_ob))]
                                                             },
                                                             self.context)
                            self.context = self._u_dict_list(self.context, self.context[-1][0], self.context[-1][1] - 1)

                elif ms_ob.type == 11:
                    self.logger.info(f"Checked for msg field: {ms_na}, object: {ms_ob.message_type.name}")
                    if self.context[-1][1] != 0:  # Not at the end of the current level
                        self.logger.debug(f"CONCHECK 2 :{self.context}")
                        if ms_ob.label in [1, 2]:  # 1 optional or 2 required
                            if len(self.context) == 1:
                                message_dict[ms_na] = {}
                            else:
                                message_dict = utl.update_nested(message_dict,
                                                                 self.context[-1][0],
                                                                 {
                                                                     ms_na: {}
                                                                 },
                                                                 self.context)
                            self.context = self._u_dict_list(self.context,
                                                             self.context[-1][0],
                                                             self.context[-1][1] - 1)
                            self.context.append((ms_na, len(self._gather_field(ms_ob))))
                            _recurse(ms_ob, message_dict)
                        elif ms_ob.label == 3:  # 3 repeated should be list
                            if len(self.context) == 1:
                                message_dict[ms_na] = []  # put that list, AND TAKE CARE TO
                                # PLACE THE UPCOMING INCLUDES HERE OBJECTS
                            else:
                                message_dict = utl.update_nested(message_dict,
                                                                 self.context[-1][0],
                                                                 {
                                                                     ms_na: []
                                                                 },
                                                                 self.context)
                            self.context = self._u_dict_list(self.context,
                                                             self.context[-1][0],
                                                             self.context[-1][1] - 1)
                            self.context.append((ms_na, len(self._gather_field(ms_ob))))
                            _recurse(ms_ob, message_dict)
                    elif self.context[-1][1] == 0:  # At the end of the current level
                        if ms_ob.label in [1, 2]:
                            self.logger.debug(f"CONCHECK 3 :{self.context}")
                            self.context = self.context[:-1]
                            self.logger.debug(f"CONCHECK 4 :{self.context}")
                            if len(self.context) == 1:
                                message_dict[ms_na] = {}
                            else:
                                message_dict = utl.update_nested(message_dict,
                                                                 self.context[-1][0],
                                                                 {
                                                                     ms_na: {}
                                                                 },
                                                                 self.context)
                            self.context.append((ms_na, len(self._gather_field(ms_ob))))
                            _recurse(ms_ob, message_dict)
                        elif ms_ob.label == 3:
                            self.context = self.context[:-1]
                            self.logger.debug(f"CONCHECK 5 :{self.context}")
                            if len(self.context) == 1:
                                message_dict[ms_na] = []
                            else:
                                message_dict = utl.update_nested(message_dict,
                                                                 self.context[-1][0],
                                                                 {
                                                                     ms_na: []
                                                                 },
                                                                 self.context)
                                self.context.append((ms_na, len(self._gather_field(ms_ob))))
                            _recurse(ms_ob, message_dict)
                    self.logger.debug(f"CONTEXTHASNUM 2 :{len(self._gather_field(ms_ob)), self._gather_field(ms_ob)}")
                if self.context[-1][1] == 0:
                    self.context = self.context[:-1]
                    self.logger.debug(f"CONCHECK 6 :{self.context}")

            return message_dict

        result = _recurse(msg_obj, message_dict)

        return result

    def explore_pb2_api(self, pb_obj: object) -> object:
        """
        This method calls the _parse_proto function to traverse the api levels defined by the configuration.
        :return: the dictionary representation of the protbuf api
        :rtype: object
        """
        counter = 0
        message_processed = OrderedDict()
        package_dependency = []
        messages: list = self._get_message_by_config(pb_obj)

        for dep in pb_obj.DESCRIPTOR.dependencies:
            package_dependency.append(dep.name)

        message_processed.setdefault('Messages')
        message_processed['Messages'] = OrderedDict()
        while messages is not None:
            msg_obj = getattr(pb_obj, messages[0][0])
            message_name = messages[0][0]
            # despite that parse_proto produces OrderedDict then it should be converted to Dict during the
            # message_processed update because the Katnip json module deal only with Dict and at the time of
            # the type conversion it has already got the decent order.
            message_processed['Messages'].update({message_name: dict(self._parse_proto(msg_obj, message_name))})
            messages.remove(messages[0])
            counter += 1
            if len(messages) == 0:
                self.logger.info(f"PPROT MSG - API has no more message, message left: {len(messages)}, operation end")
                break
        js = json.dumps(message_processed, indent=4)
        print(js)

        return message_processed

    def execute_api_parse(self) -> tuple:
        """
        Will load the protobuf module and returns with the parsed protobuf api.
        :return: tuple key is the api dict value is the module
        """
        # Cut '.py' from the end of file)
        pb2_module_obj: object = FrameworkUtils.load_pb2_module(self.pb2_api_file[:-3], self.moule_path)
        return self.explore_pb2_api(pb2_module_obj), pb2_module_obj
