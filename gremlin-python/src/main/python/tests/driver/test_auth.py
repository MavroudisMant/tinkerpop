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
from aiohttp import BasicAuth as aiohttpBasicAuth

from src.main.python.gremlin_python.driver.auth import Auth


def create_mock_request():
    return {'headers':
            {'content-type': 'application/vnd.graphbinary-v4.0',
             'accept': 'application/vnd.graphbinary-v4.0'},
            'payload': b'',
            'url': 'https://test_url:8182/gremlin'}


class TestAuth(object):

    def test_basic_auth_request(self):
        mock_request = create_mock_request()
        assert 'authorization' not in mock_request['headers']
        Auth.basic('username', 'password').apply(mock_request)
        assert 'authorization' in mock_request['headers']
        assert aiohttpBasicAuth('username', 'password').encode() == mock_request['headers']['authorization']

    def test_sigv4_auth_request(self):
        mock_request = create_mock_request()
        assert 'Authorization' not in mock_request['headers']
        assert 'X-Amz-Date' not in mock_request['headers']
        Auth.sigv4('us-west-2', 'MOCK_ID', 'MOCK_KEY').apply(mock_request)
        print(mock_request)
        assert mock_request['headers']['X-Amz-Date'] is not None
        assert mock_request['headers']['Authorization'].startswith('AWS4-HMAC-SHA256 Credential=MOCK_ID')
        assert 'us-west-2/neptune-db/aws4_request' in mock_request['headers']['Authorization']
        assert 'Signature=' in mock_request['headers']['Authorization']


