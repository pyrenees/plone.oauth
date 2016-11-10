# content of conftest.py
from collections import namedtuple

import pytest
from unittest.mock import NonCallableMagicMock
from plone.oauth import main
import asyncio
from plone.oauth.endpoints import get_authorization_code, get_token
import jwt

def pytest_addoption(parser):
    parser.addoption("--ldap", action="store",
        help="ldap server")
    parser.addoption("--ldap-port", action="store",
        help="ldap port server")
    parser.addoption("--redis", action="store",
        help="redis server")
    parser.addoption("--redis-port", action="store",
        help="redis port server")

secret = 'secret'

# @asyncio.coroutine
# def get_token_test(app):
#     # We get the authorize code
#     app.params['response_type'] = 'code'
#     app.params['client_id'] = '11'
#     app.params['scope'] = 'plone'
#     view_callable = asyncio.coroutine(get_authorization_code)
#     info = yield from view_callable(app)
#     assert info.status_code == 200

#     info_decoded = jwt.decode(info.body, secret)

#     # We get the working token for the client app
#     app.params['grant_type'] = 'authorization_code'
#     app.params['code'] = info_decoded['auth_code']
#     app.params['client_id'] = 11
#     app.params['client_secret'] = '123456'
#     view_callable = asyncio.coroutine(get_token)
#     info = yield from view_callable(app)
#     assert info.status_code == 200

#     info_decoded = jwt.decode(info.body, secret)
#     token = info_decoded['access_token']

#     # We get the working token for the client app
#     app.params['grant_type'] = 'password'
#     app.params['code'] = token
#     app.user_agent = 'DUMMY'
#     app.client_addr = '127.0.0.1'
#     view_callable = asyncio.coroutine(get_token)
#     info = yield from view_callable(app)
#     assert info.status_code == 200

#     info_decoded = jwt.decode(info.body, secret)
#     token = info_decoded['token']
#     return token


@pytest.fixture(scope="module")
def app(request):
    settings = {
        'jwtsecret': secret,
        'ldap.base_dn': 'dc=plone,dc=com',
        'ldap.user_filter': 'mail={username},ou=users,dc=plone,dc=com',
        'ldap.root_dn': 'uid=admin,ou=system',
        'ldap.root_pw': 'secret',
        'ldap.server': request.config.getoption("--ldap") + ':' + request.config.getoption("--ldap-port"),
        'ldap.config_server': request.config.getoption("--ldap") + ':' + request.config.getoption("--ldap-port"),
        'ldap.config_dn': 'ou=config,dc=plone,dc=com',
        'ldap.config_root_pw': 'secret',
        'ldap.config_root_dn': 'uid=admin,ou=system',
        'ldap.user_profile': ["person","inetOrgPerson"],
        'valid_password': 'plone.oauth.password.valid_password',
        'password_policy': 'plone.oauth.password.password_policy',
        'debug': True,
        'manager': 'admin@example.com',
        'redis.host': request.config.getoption("--redis"),
        'redis.port': int(request.config.getoption("--redis-port")),
        'mail.host': 'localhost',
        'mail.port': 587,
        'mail.username': 'username',
        'mail.password': 'password',
        'mail.tls': True,
        'mail.ssl': False,
        'logging.config': 'development.ini',
        'backend': 'LDAPADMIN'
    }

    app = main(settings)

    # Init client db
    # db_clients = app.registry.settings['db_clients']
    # db_clients.set(21, 'holahola')
    # db_clients.set(22, 'holahola')

    # Add user
    user_manager = app['settings']['user_manager']
    user_manager.addUser('user@example.com', 'user')

    MockRequest = namedtuple('MockRequest', ['app', 'json', 'headers', 'post', 'get', 'transport'])
    ExtraInfo = namedtuple('ExtraInfo', ['get_extra_info'])
    extrainfo = ExtraInfo(lambda arg: ('127.0.0.1', '8080') if arg == 'peername' else None)
    return MockRequest(app, None, {}, None, None, extrainfo)
