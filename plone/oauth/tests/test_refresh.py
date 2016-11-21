import unittest
import asyncio
import pytest
from aiohttp.web_exceptions import HTTPBadRequest
from plone.oauth.utils.request import payload
from plone.oauth.tests.conftest import secret
from plone.oauth.endpoints import refresh_token
from plone.oauth.endpoints import get_authorization_code, get_token
# from plone.oauth.tests.conftest import get_token_test
from plone.oauth.valid import valid_token
import jwt


def test_endpoints(app):
    async def _test_password_api():
        # We get the service token
        params = {}
        params['grant_type'] = 'service'
        params['client_id'] = 'plone'
        params['client_secret'] = 'plone'
        headers = {'User-Agent': 'DUMMY', 'Host': '127.0.0.1:8080'}
        dummy = app._replace(post=payload(params), headers=headers)
        view_callable = asyncio.coroutine(get_token)
        info = await view_callable(dummy)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        service_token = info_decoded['service_token']

        # We get the authorize code
        params['response_type'] = 'code'
        params['client_id'] = 'plone'
        params['service_token'] = service_token
        params['scopes'] = ['plone']
        dummy = dummy._replace(post=payload(params))
        view_callable = asyncio.coroutine(get_authorization_code)
        info = await view_callable(dummy)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)

        # We get the working token for the client app
        params['grant_type'] = 'user'
        params['code'] = info_decoded['auth_code']
        params['username'] = 'user@example.com'
        params['password'] = 'user'
        params['scopes'] = ['plone']
        dummy = dummy._replace(post=payload(params))

        view_callable = asyncio.coroutine(get_token)
        info = await view_callable(dummy)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        user_token = info_decoded['token']

        params['code'] = service_token
        params['token'] = user_token
        dummy = dummy._replace(post=payload(params))
        view_callable = asyncio.coroutine(valid_token)
        info = await view_callable(dummy)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['user'] == 'user@example.com'

        # Refresh token
        params['client_id'] = 'plone'
        params['code'] = service_token
        params['token'] = user_token
        params['user'] = 'user@example.com'
        dummy = dummy._replace(post=payload(params))
        view_callable = asyncio.coroutine(refresh_token)
        info = await view_callable(dummy)
        assert info.status == 200

        # Try again refresh token
        params['client_id'] = 'plone'
        params['code'] = service_token
        params['token'] = user_token
        params['user'] = 'user@example.com'
        dummy = dummy._replace(post=payload(params))
        view_callable = asyncio.coroutine(refresh_token)
        try:
            info = await view_callable(dummy)
            assert info.status == 400
        except HTTPBadRequest:
            pass

    asyncio.get_event_loop().run_until_complete(_test_password_api())
