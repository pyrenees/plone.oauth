import unittest
import asyncio
from collections import namedtuple

import pytest

from plone.oauth.tests.base import BaseHorusTest
from plone.oauth.tests.conftest import secret

from plone.oauth.endpoints import get_authorization_code, get_token
from plone.oauth.utils.request import payload
from plone.oauth.valid import valid_token
from plone.oauth.ldap import LDAPUserManager
import jwt


def test_endpoints(app):

    @asyncio.coroutine
    def _test_say_hello_service():
        dummy = app
        # We get the service token
        params = {}
        params['grant_type'] = 'service'
        params['client_id'] = 'plone'
        params['client_secret'] = 'plone'
        headers = {'User-Agent': 'DUMMY', 'Host': '127.0.0.1:8080'}
        dummy = dummy._replace(post=payload(params), headers=headers)

        view_callable = asyncio.coroutine(get_token)
        info = yield from view_callable(dummy)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        service_token = info_decoded['service_token']

        # We get the authorize code
        params = {}
        params['response_type'] = 'code'
        params['client_id'] = 'plone'
        params['service_token'] = service_token
        params['scopes'] = ['plone']
        dummy = app._replace(post=payload(params))

        view_callable = asyncio.coroutine(get_authorization_code)
        info = yield from view_callable(dummy)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)

        # We get the working token for the client app
        params = {}
        params['grant_type'] = 'user'
        params['code'] = info_decoded['auth_code']
        params['username'] = 'user@example.com'
        params['password'] = 'user'
        params['scopes'] = ['plone']
        params['client_id'] = 'plone'
        headers = {'User-Agent': 'DUMMY', 'Host': '127.0.0.1:8080'}
        dummy = app._replace(post=payload(params), headers=headers)

        view_callable = asyncio.coroutine(get_token)
        info = yield from view_callable(dummy)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        user_token = info_decoded['token']

        params = {'code': service_token, 'token': user_token}
        dummy = app._replace(post=payload(params))

        view_callable = asyncio.coroutine(valid_token)
        info = yield from view_callable(dummy)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['user'] == 'user@example.com'

    asyncio.get_event_loop().run_until_complete(_test_say_hello_service())
