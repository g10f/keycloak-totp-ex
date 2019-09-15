#!/usr/bin/env python
import argparse
import logging
from urllib.parse import urljoin

import requests
import sys
from cachecontrol import CacheControl

logging.basicConfig(stream=sys.stdout, level='WARNING', format="%(levelname)s %(asctime)s: %(message)s")
logger = logging.getLogger(__name__)


class ApiClient(object):
    def __init__(self, base_uri, client_id, username, password, scope=None):
        self.base_uri = base_uri
        self.client_id = client_id
        self.username = username
        self.password = password
        self.scope = scope
        self.session = CacheControl(requests.session())

    @property
    def auth_header(self):
        """
        authorization header
        """
        token_response = self.get_token()
        return {
            'authorization': '%s %s' % (token_response.get('token_type', ''), token_response.get('access_token', ''))}

    def get_token(self):
        """
        get the token endpoint from the well-known uri and
        then authenticate with grant_type client_credentials
        """
        uri = urljoin(self.base_uri, '.well-known/openid-configuration')
        openid_configuration = self.session.get(uri).json()
        token_endpoint = openid_configuration['token_endpoint']

        body = {'grant_type': 'password', 'client_id': self.client_id, 'username': self.username,
                'password': self.password}
        if self.scope:
            body['scope'] = self.scope
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        json_response = self.session.post(token_endpoint, headers=headers, data=body).json()
        if 'error' in json_response:
            logger.error(json_response)
            raise Exception('authorization error', json_response)
        return json_response

    def get(self, uri):
        """
        make authorized request
        """
        uri = urljoin(self.base_uri, uri)
        headers = self.auth_header
        response = self.session.get(uri, headers=headers)
        return response

    def put(self, uri, data=None):
        uri = urljoin(self.base_uri, uri)
        headers = self.auth_header
        response = self.session.put(uri, headers=headers, json=data)
        return response


def main():
    parser = argparse.ArgumentParser(description='IAM API Request')
    parser.add_argument('client_id')
    parser.add_argument('username')
    parser.add_argument('password')
    parser.add_argument('-s', '--scope', default=None)
    parser.add_argument('-b', '--base_uri', help='The base_uri of the API ..',
                        default='http://localhost:8081/auth/realms/demo/')

    # uri template parameters
    parser.add_argument('--q', help='text search parameter for name, email, ..')

    # get a dictionary with the command line arguments
    args = vars(parser.parse_args())
    base_uri = args.pop('base_uri')
    client_id = args.pop('client_id')
    username = args.pop('username')
    password = args.pop('password')
    scope = args.pop('scope')

    client = ApiClient(base_uri, client_id, username, password, scope)
    try:
        update_totp(client)
        # test(client)
    except Exception as e:
        logger.exception(e)


def update_totp(client):
    # response = client.get('/auth/admin/realms/demo/users/ee2ef013-45fe-494f-b1e3-5ee66230f9ae')
    # print(response.text)
    data = {"type": "totp", "value": "KX2SI3KNXJF5MGY3", "device": "ex"}
    user = 'demo'
    data = {"type": "totp", "value": "firAvEGFyr5H9TgL4sAI"}
    response = client.put(f'/auth/realms/demo/user/{user}/totp-ex', data)
    #
    # response = client.put('/auth/realms/demo/user/test1/totp-ex', data)
    # response = client.put('/auth/realms/demo/user/test2/totp-ex', data)
    # response = client.put('/auth/realms/demo/user/ee2ef013-45fe-494f-b1e3-5ee66230f9ae', data)
    print(response)


def test(client):
    response = client.get('/auth/realms/master/realms')
    print(response)


if __name__ == "__main__":
    main()
    # test()
