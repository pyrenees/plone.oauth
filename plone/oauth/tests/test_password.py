import unittest
import asyncio
import pytest

from pyramid.httpexceptions import HTTPUnauthorized
from plone.oauth.tests.conftest import secret
from plone.oauth.endpoints import set_password
from plone.oauth.endpoints import get_authorization_code, get_token
from plone.oauth.valid import valid_token
import jwt


def test_endpoints(app):
    @asyncio.coroutine
    def _test_password_api():
        # We get the service token
        app.params['grant_type'] = 'service'
        app.params['client_id'] = 'plone'
        app.params['client_secret'] = 'plone'
        app.user_agent = 'DUMMY'
        app.client_addr = '127.0.0.1'
        view_callable = asyncio.coroutine(get_token)
        info = yield from view_callable(app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)
        service_token = info_decoded['service_token']

        # We get the authorize code
        app.params['response_type'] = 'code'
        app.params['client_id'] = 'plone'
        app.params['service_token'] = service_token
        app.params['scopes'] = ['plone']
        view_callable = asyncio.coroutine(get_authorization_code)
        info = yield from view_callable(app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)

        # We get the working token for the client app
        app.params['grant_type'] = 'user'
        app.params['code'] = info_decoded['auth_code']
        app.params['username'] = 'user@example.com'
        app.params['password'] = 'user'
        app.params['scopes'] = ['plone']
        app.user_agent = 'DUMMY'
        app.client_addr = '127.0.0.1'
        view_callable = asyncio.coroutine(get_token)
        info = yield from view_callable(app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)
        user_token = info_decoded['token']

        app.params['code'] = service_token
        app.params['token'] = user_token
        view_callable = asyncio.coroutine(valid_token)
        info = yield from view_callable(app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['user'] == 'user@example.com'

        # Change the password
        app.params['client_id'] = 'plone'
        app.params['token'] = user_token
        app.params['password'] = '12345678'
        app.user_agent = 'DUMMY'
        app.client_addr = '127.0.0.1'
        view_callable = asyncio.coroutine(set_password)
        info = yield from view_callable(app)
        assert info.status_code == 200

        # We get the authorize code
        app.params['response_type'] = 'code'
        app.params['client_id'] = 'plone'
        app.params['service_token'] = service_token
        app.params['scopes'] = ['plone']
        view_callable = asyncio.coroutine(get_authorization_code)
        info = yield from view_callable(app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)

        # Check again the auth with the old password
        app.params['grant_type'] = 'user'
        app.params['code'] = info_decoded['auth_code']
        app.params['username'] = 'user@example.com'
        app.params['password'] = 'user'
        app.user_agent = 'DUMMY'
        app.client_addr = '127.0.0.1'
        view_callable = asyncio.coroutine(get_token)
        try:
            info = yield from view_callable(app)
            assert info.status_code == 400
        except HTTPUnauthorized:
            pass

        # We get the authorize code
        app.params['response_type'] = 'code'
        app.params['client_id'] = 'plone'
        app.params['service_token'] = service_token
        app.params['scopes'] = ['plone']
        view_callable = asyncio.coroutine(get_authorization_code)
        info = yield from view_callable(app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)

        # Check again the auth with the new password
        app.params['grant_type'] = 'user'
        app.params['code'] = info_decoded['auth_code']
        app.params['username'] = 'user@example.com'
        app.params['password'] = '12345678'
        app.user_agent = 'DUMMY'
        app.client_addr = '127.0.0.1'
        view_callable = asyncio.coroutine(get_token)
        info = yield from view_callable(app)
        assert info.status_code == 200

        received_token = info.body
        info_decoded = jwt.decode(info.body, secret)
        user_token = info_decoded['token']
        app.params['code'] = service_token
        app.params['token'] = user_token
        view_callable = asyncio.coroutine(valid_token)
        info = yield from view_callable(app)
        assert info.status_code == 200

       # Change the password
        app.params['client_id'] = 'plone'
        app.params['code'] = service_token
        app.params['token'] = user_token
        app.params['password'] = 'user'
        app.user_agent = 'DUMMY'
        app.client_addr = '127.0.0.1'
        view_callable = asyncio.coroutine(set_password)
        info = yield from view_callable(app)
        assert info.status_code == 200

    asyncio.get_event_loop().run_until_complete(_test_password_api())
