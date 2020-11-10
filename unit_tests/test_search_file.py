import os
import unittest

from framework.services.search_file import SearchFile


class TestFramework(unittest.TestCase):

    def __init__(self, name='TestFramework'):
        super(TestFramework, self).__init__(name)
        self.ROOT_DIR = os.path.dirname(os.path.realpath('../'))
        self.raw = '/framework/data/proto/example_v2/'
        self.pb = '/framework/models/pb2/example_v2/'
        self.pwd = '/'.join(os.getcwd().split('/')[len(self.ROOT_DIR.split('/')):])
        self.raw_proto_path = '/' + self.pwd + self.raw
        self.pb2_path = '/' + self.pwd + self.pb
        self.search_proto = SearchFile(file_type='proto', file_path=self.raw_proto_path)
        self.search_pb2 = SearchFile(file_type='_pb2.py', file_path=self.pb2_path)
        self.search_bad_pb2 = SearchFile(file_type='non_existent_extension', file_path=self.pb2_path)

    def test_01_file_search_proto(self) -> None:

        file_list = self.search_proto.search_file
        for file in file_list:
            if file == 'athlete.proto':
                self.assertEqual(file, 'athlete.proto')
            elif file == 'bike.proto':
                self.assertEqual(file, 'bike.proto')
            elif file == 'query.proto':
                self.assertEqual(file, 'query.proto')
            elif file == 'route.proto':
                self.assertEqual(file, 'route.proto')
            elif file == 'run.proto':
                self.assertEqual(file, 'run.proto')
            elif file == 'ski.proto':
                self.assertEqual(file, 'ski.proto')
            elif file == 'swim.proto':
                self.assertEqual(file, 'swim.proto')

    def test_02_file_search_pb2(self) -> None:

        file_list = self.search_pb2.search_file
        for file in file_list:
            if file == 'athlete_pb2.py':
                self.assertEqual(file, 'athlete_pb2.py')
            elif file == 'query_pb2.py':
                self.assertEqual(file, 'query_pb2.py')
            elif file == 'ski_pb2.py':
                self.assertEqual(file, 'ski_pb2.py')
            elif file == 'swim_pb2.py':
                self.assertEqual(file, 'swim_pb2.py')
            elif file == 'run_pb2.py':
                self.assertEqual(file, 'run_pb2.py')
            elif file == 'route_pb2.py':
                self.assertEqual(file, 'route_pb2.py')
            elif file == 'bike_pb2.py':
                self.assertEqual(file, 'bike_pb2.py')

    def test_03_file_search_not_found(self) -> None:

        file_list = self.search_bad_pb2.search_file
        for file in file_list:
            if file == 'athlete.proto':
                with self.assertRaises(FileNotFoundError):
                    self.search_bad_pb2.search_file()
