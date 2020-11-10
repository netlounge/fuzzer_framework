import os
import boto3
import time

from botocore.exceptions import ClientError
from framework.core.fuzz_object import FuzzObject
from framework.utils.generate_uuid import GenerateUUID


class PutArchiveToS3(FuzzObject):
    """
    This class is in charge of archiving artifacts into S3
    bucket if exists, if not it creates one.
    Based on https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3-examples.html
    """

    def __init__(self, name='PutArchiveToS3', logger=None):
        super(PutArchiveToS3, self).__init__(name, logger)
        self._uuid = GenerateUUID.generate_uuid()
        self.region = 'eu-central-1'
        self.s3_resource = boto3.resource('s3')
        self.s3_connection = self.s3_resource.meta.client

    @staticmethod
    def create_bucket_name(bucket_prefix=str) -> str:
        """
        This function creates the bucket name.
        <prefix>-fuzzer-framework-<Y:M:D>
        :param bucket_prefix: str
        :return: bucket name
        :rtype: str
        """
        # The generated bucket name must be between 3 and 63 chars long
        return ''.join([bucket_prefix, str('-fuzzer-framework-'), time.strftime("%Y-%m-%d")])

    def check_bucket_is_exists(self, bucket_name=str) -> bool:
        """
        Checks whether the bucket exists or not.
        :param bucket_name
        :return: True if bucket exists.
        :rtype: bool
        """
        s3_client = boto3.client('s3')
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            if bucket_name in bucket['Name']:
                self.logger.info('Bucket with name %s already exist' % bucket_name)
                return True

    def create_bucket(self, bucket_name=str) -> object:
        """
        Creates the S3 bucket.
        :param bucket_name
        :return: False if exception occurres, else the bucket name and the client
        response
        :rtype: object
        """
        if not self.check_bucket_is_exists(bucket_name):
            try:
                bucket_response = self.s3_connection.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={
                        'LocationConstraint': self.region})
                return bucket_name, bucket_response
            except ClientError as err:
                self.logger.error('Boto client error: %s' % err)
                return False

    def upload_file(self, files=list, bucket=str) -> bool:
        """
        Upload files to the given S3 bucket except if any of the files
        size greater than 5MB then it terminates the process.
        :param files: list
        :param bucket: str
        :return: True if succeed
        :rtype: bool
        """
        s3_client = boto3.client('s3')
        try:
            for file_name in files:
                if os.path.getsize(file_name) / 1000000 >= 5:
                    self.logger.error(f"File size limit! {os.path.getsize(file_name) / 1000000} >= 5!")
                    self.logger.error(f"COST!")
                    self.logger.error(f"DANGER THIS IS ONLY FOR ME")
                    exit(1)
                else:
                    object_name = file_name.replace(os.getcwd() + '/', '')
                    s3_client.upload_file(file_name, bucket, object_name)
                    self.logger.info(f"Archiving S3 object: {object_name}")
        except ClientError as err:
            self.logger.error(f"Boto client error: {err}")
            return False
        return True

    def do_upload(self, files=list) -> None:
        """
        Do the job.
        :param files: list
        """
        bucket_name = self.create_bucket_name('shrdcvxtct8191')  # dummy string do not care about
        if not self.check_bucket_is_exists(bucket_name):
            self.create_bucket(bucket_name)
        self.upload_file(files, bucket_name)
