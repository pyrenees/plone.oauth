import logging.config

import aioredis
import asyncio
import importlib
import json
from ldap3 import Server
from plone.oauth.ldap import LDAPUserManager
from plone.oauth.config import LDAPConfigManager

from plone.oauth import endpoints
from plone.oauth import search
from plone.oauth.valid import ping, say_hello
from plone.oauth import users
from plone.oauth import groups
from plone.oauth import views

from aiohttp_swagger import setup_swagger

from aiohttp import web
import aiohttp_cors

from pyramid_mailer import mailer_factory_from_settings

import logging

import jwt
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
from jwt.contrib.algorithms.py_ecdsa import ECAlgorithm

jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))
jwt.register_algorithm('ES256', ECAlgorithm(ECAlgorithm.SHA256))


log = logging.getLogger(__name__)

MANAGERS = []
CORS = []

def is_superuser(username):
    """
    True if `request` is solicited by a superuser
    """
    return username in MANAGERS


@asyncio.coroutine
def config_db(registry, settings):

    # DB 0 cauth
    # DB 1 tauth
    # DB 2 token

    # authorization_codes
    # TOKEN::scope : client_id
    db_pool_cauths = yield from aioredis.create_pool(
        (settings['redis.host'], settings['redis.port']),
        db=0,
        minsize=5,
        maxsize=10)

    # service_tokens
    # TOKEN : CLIENT_ID
    db_pool_tauth = yield from aioredis.create_pool(
        (settings['redis.host'], settings['redis.port']),
        db=1,
        minsize=5,
        maxsize=10)

    # User tokens
    # TOKEN : 
    db_pool_token = yield from aioredis.create_pool(
        (settings['redis.host'], settings['redis.port']),
        db=2,
        minsize=5,
        maxsize=10)

    # db_pool_cauths = redis.ConnectionPool(
    #     host=settings['redis.host'], port=settings['redis.port'], db=0)
    # db_pool_tauth = redis.ConnectionPool(
    #     host=settings['redis.host'], port=settings['redis.port'], db=1)
    # db_pool_token = redis.ConnectionPool(
    #     host=settings['redis.host'], port=settings['redis.port'], db=2)

    # db_conn_cauths = redis.Redis(connection_pool=db_pool_cauths)
    # db_conn_tauth = redis.Redis(connection_pool=db_pool_tauth)
    # db_conn_token = redis.Redis(connection_pool=db_pool_token)

    # db_conn_scopes = {}
    # db_conn_client_id = {}

    registry.settings['db_cauths'] = db_pool_cauths
    registry.settings['db_tauths'] = db_pool_tauth
    registry.settings['db_token'] = db_pool_token


@asyncio.coroutine
def config_ldap(registry, settings):

    db_pool_users = yield from aioredis.create_pool(
        (settings['redis.host'], settings['redis.port']),
        db=3,
        minsize=5,
        maxsize=10)

    db_pool_groups = yield from aioredis.create_pool(
        (settings['redis.host'], settings['redis.port']),
        db=4,
        minsize=5,
        maxsize=10)

    # db_pool_users = redis.ConnectionPool(
    #     host=settings['redis.host'], port=settings['redis.port'], db=3)
    # db_pool_groups = redis.ConnectionPool(
    #     host=settings['redis.host'], port=settings['redis.port'], db=4)

    # db_conn_users = redis.Redis(connection_pool=db_pool_users)
    # db_conn_groups = redis.Redis(connection_pool=db_pool_groups)

    db_conn_scopes = {}
    db_conn_client_id = {}

    server = Server(settings['ldap.server'])
    registry.settings['ldap_server'] = server

    if registry.settings['backend'] == 'LDAPADMIN':
        ldap_object = LDAPUserManager(
            ldap_server=server,
            user_filter=registry.settings['ldap.user_filter'],
            base_dn=registry.settings['ldap.base_dn'],
            root_dn=registry.settings['ldap.root_dn'],
            passwd_dn=registry.settings['ldap.root_pw'],
            user_profile=json.loads(registry.settings['ldap.user_profile']),
            read_only=False,
            cache_users=db_pool_users,
            cache_groups=db_pool_groups)

    elif registry.settings['backend'] == 'LDAP':
        ldap_object = LDAPUserManager(
            server,
            config.registry.settings['ldap.user_filter'])

    registry.settings['user_manager'] = ldap_object

    server = Server(settings['ldap.config_server'])
    registry.settings['ldap_config_server'] = server

    db_conn_config = LDAPConfigManager(
        ldap_server=server,
        base_dn=registry.settings['ldap.base_dn'],
        root_dn=registry.settings['ldap.config_root_dn'],
        passwd_dn=registry.settings['ldap.config_root_pw'],
        read_only=False,
        cache_scopes=db_conn_scopes,
        cache_client_id=db_conn_client_id)

    registry.settings['db_config'] = db_conn_config


@asyncio.coroutine
def config_mailer(registry, settings):
    registry['mailer'] = mailer_factory_from_settings(settings)


def main(config_file):
    """ This function returns a AioHTTP WSGI application.
    """

    app = web.Application()
    cors = aiohttp_cors.setup(app)

    resource_options = aiohttp_cors.ResourceOptions(
        allow_credentials=True,
        expose_headers=("X-Custom-Server-Header",),
        allow_headers=("X-Requested-With", "Content-Type"),
        max_age=3600,
    )

    cors_options = {
        "http://client.example.org": 
    }

    # support logging in python3
    logging.config.fileConfig(
        settings['logging.config'],
        disable_existing_loggers=False
    )

    if isinstance(global_config, Configurator):
        config = global_config
    else:
        config = Configurator(settings=settings)

    # DB 3 users cache
    # DB 4 groups cache
    # DB 5 clients

    manager_id = settings['manager']
    MANAGERS.append(manager_id)

    cors_config = settings.get('cors', '')
    CORS.extend(cors_config.split(','))
    log.info(' Enabled cors : ' + str(CORS))

    loop = asyncio.get_event_loop()

    loop.run_until_complete(config_db(config.registry, settings))
    loop.run_until_complete(config_ldap(config.registry, settings))
    # loop.run_until_complete(config_mailer(config.registry, settings))

    # Per fer un auth token amb un auth service
    config.add_settings(ttl_auth_code=120)

    # El token de l'usuari
    config.add_settings(ttl_auth=86400) #!24h fins que no tinguem renew!!

    # L'auth token del sistema
    config.add_settings(ttl_service_token=36600)

    # TTL search
    config.add_settings(ttl_search=360)
    config.add_settings(ttl_user_info=360)

    # Password policy modules
    valid_password_module = settings['valid_password'].rsplit('.', 1)
    password_policy_module = settings['password_policy'].rsplit('.', 1)

    m = importlib.import_module(valid_password_module[0])
    valid_password = getattr(m, valid_password_module[1])

    m = importlib.import_module(password_policy_module[0])
    password_policy = getattr(m, password_policy_module[1])

    config.registry.settings['valid_password'] = valid_password
    config.registry.settings['password_policy'] = password_policy

    config.add_settings(debug=settings['debug'] == 'True')

    app.router.add_get('/', say_hello)

    route_get_authorization_code = app.router.add_get(
        '/get_authorization_code', get_authorization_code)
    app.router.add_get('/get_auth_token', get_auth_token)
    app.router.add_get('/password', password)
    app.router.add_get('/refresh', refresh)
    app.router.add_get('/search_user', search_user)
    app.router.add_get('/valid_token', valid_token)
    app.router.add_get('/get_user', get_user)
    app.router.add_get('/get_users', get_users)
    app.router.add_get('/get_group', get_group)

    app.router.add_get('/ping', ping)
    app.router.add_get('/add_user', add_user)
    app.router.add_get('/add_group', add_group)
    app.router.add_get('/add_scope', add_scope)
    app.router.add_get('/get_scopes', get_scopes)
    app.router.add_get('/grant_scope_roles', grant_scope_roles)
    app.router.add_get('/deny_scope_roles', deny_scope_roles)

    app.router.add_static(
        '/static/',
        path=str(project_root / 'static'),
        name='static')

    route = cors.add(
        route_get_authorization_code, )

    setup_swagger(
        app,
        description="""OAuth Server to connecto to plone.server""",
        title="plone.oauth",
        api_version="1.0.0",
        contact="https://github.com/plone/plone.oauth")

    async def close_redis(app):
        app['db'].close()
        await app['db'].wait_closed()

    app.on_cleanup.append(close_redis)

    return app
