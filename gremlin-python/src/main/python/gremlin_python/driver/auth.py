#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
import abc


class Auth(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def apply(self, request):
        """Applies the necessary authentication operations to the request and returns the modified request."""
        pass

    @staticmethod
    def basic(username, password):
        return BasicAuth(username, password)

    @staticmethod
    def sigv4(region_name, aws_access_key_id='', aws_secret_access_key='', session_token='', service_name=''):
        return SigV4Auth(region_name, aws_access_key_id, aws_secret_access_key, session_token, service_name)


class BasicAuth(Auth):

    def __init__(self, username, password):
        self._username = username
        self._password = password

    def apply(self, request):
        from aiohttp import BasicAuth as aiohttpBasicAuth

        return request['headers'].update({'authorization': aiohttpBasicAuth(self._username, self._password).encode()})


class SigV4Auth(Auth):

    def __init__(self, region_name, aws_access_key_id='', aws_secret_access_key='', session_token='',
                 service_name=''):
        import os

        self._region_name = region_name
        self._aws_access_key_id = aws_access_key_id if aws_access_key_id else os.environ.get('AWS_ACCESS_KEY_ID')
        self._aws_secret_access_key = aws_secret_access_key if aws_secret_access_key \
            else os.environ.get('AWS_SECRET_ACCESS_KEY')
        self._session_token = session_token if session_token else os.environ.get('AWS_SESSION_TOKEN')
        self._service_name = service_name if service_name else "neptune-db"

    def apply(self, request):
        from botocore.auth import SigV4Auth as botocoreSigV4Auth
        from botocore.awsrequest import AWSRequest
        from types import SimpleNamespace

        assert ((self._aws_access_key_id is not None and self._aws_secret_access_key is not None)
                or self._session_token is not None), \
            ('No credentials or session token found, please ensure access key and secret key or session tokens '
             'are provided or set as environment variables.')

        creds = SimpleNamespace(
            access_key=self._aws_access_key_id, secret_key=self._aws_secret_access_key, token=self._session_token,
            region=self._region_name,
        )
        aws_request = AWSRequest(method="POST", url=request['url'], data=request['payload'])
        botocoreSigV4Auth(creds, self._service_name, self._region_name).add_auth(aws_request)
        request['headers'].update(aws_request.headers)
        request['payload'] = aws_request.data
        return request
