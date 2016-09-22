import unittest
import asyncio
import pytest

from pyramid.httpexceptions import HTTPBadRequest
from plone.oauth.tests.conftest import secret
from plone.oauth.endpoints import refresh_token
from plone.oauth.endpoints import get_authorization_code, get_token
# from plone.oauth.tests.conftest import get_token_test
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

        # Refresh token
        app.params['client_id'] = 'plone'
        app.params['code'] = service_token
        app.params['token'] = user_token
        app.params['user'] = 'user@example.com'
        app.user_agent = 'DUMMY'
        app.client_addr = '127.0.0.1'
        view_callable = asyncio.coroutine(refresh_token)
        info = yield from view_callable(app)
        assert info.status_code == 200

        # Try again refresh token
        app.params['client_id'] = 'plone'
        app.params['code'] = service_token
        app.params['token'] = user_token
        app.params['user'] = 'user@example.com'
        app.user_agent = 'DUMMY'
        app.client_addr = '127.0.0.1'
        view_callable = asyncio.coroutine(refresh_token)
        try:
            info = yield from view_callable(app)
            assert info.status_code == 400
        except HTTPBadRequest:
            pass

    asyncio.get_event_loop().run_until_complete(_test_password_api())
