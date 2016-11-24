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
from plone.oauth.views import ping, say_hello
from plone.oauth import users
from plone.oauth import groups
from plone.oauth import valid

from aiohttp_swagger import setup_swagger

from aiohttp import web
import aiohttp_cors

from pyramid_mailer import mailer_factory_from_settings

import logging

log = logging.getLogger(__name__)

MANAGERS = []
# CORS = []


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

    registry['settings']['db_cauths'] = db_pool_cauths
    registry['settings']['db_tauths'] = db_pool_tauth
    registry['settings']['db_token'] = db_pool_token


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

    registry['settings']['db_pool_users'] = db_pool_users
    registry['settings']['db_pool_groups'] = db_pool_groups

    # db_pool_users = redis.ConnectionPool(
    #     host=settings['redis.host'], port=settings['redis.port'], db=3)
    # db_pool_groups = redis.ConnectionPool(
    #     host=settings['redis.host'], port=settings['redis.port'], db=4)

    # db_conn_users = redis.Redis(connection_pool=db_pool_users)
    # db_conn_groups = redis.Redis(connection_pool=db_pool_groups)

    db_conn_scopes = {}
    db_conn_client_id = {}

    server = Server(settings['ldap.server'])
    registry['settings']['ldap_server'] = server

    if registry['settings']['backend'] == 'LDAPADMIN':
        ldap_object = LDAPUserManager(
            ldap_server=server,
            user_filter=registry['settings']['ldap.user_filter'],
            base_dn=registry['settings']['ldap.base_dn'],
            root_dn=registry['settings']['ldap.root_dn'],
            passwd_dn=registry['settings']['ldap.root_pw'],
            user_profile=registry['settings']['ldap.user_profile'],
            read_only=False,
            cache_users=db_pool_users,
            cache_groups=db_pool_groups)

    # elif registry['settings']['backend'] == 'LDAP':
    #     ldap_object = LDAPUserManager(
    #         server,
    #         config.registry['settings']['ldap.user_filter'])

    registry['settings']['user_manager'] = ldap_object

    server = Server(settings['ldap.config_server'])
    registry['settings']['ldap_config_server'] = server

    db_conn_config = LDAPConfigManager(
        ldap_server=server,
        base_dn=registry['settings']['ldap.base_dn'],
        root_dn=registry['settings']['ldap.config_root_dn'],
        passwd_dn=registry['settings']['ldap.config_root_pw'],
        read_only=False,
        cache_scopes=db_conn_scopes,
        cache_client_id=db_conn_client_id)

    registry['settings']['db_config'] = db_conn_config


@asyncio.coroutine
def config_mailer(registry, settings):
    registry['mailer'] = mailer_factory_from_settings(settings)


def main(config):
    """ This function returns a AioHTTP WSGI application.
    """
    if type(config) == dict:
        settings = config
    else:
        with open(config, 'r') as config_fp:
            settings = json.load(config_fp)

    registry = {}
    registry['settings'] = settings

    app = web.Application()

    # Configure CORS
    resource_options = aiohttp_cors.ResourceOptions(
        allow_credentials=True,
        expose_headers=("X-Custom-Server-Header",),
        allow_headers=("X-Requested-With", "Content-Type"),
        max_age=3600,
    )
    cors_config = {address: resource_options for address in settings.get('cors', [])}
    cors = aiohttp_cors.setup(app, defaults=cors_config)
    # CORS.extend(cors_config)
    log.info(' Enabled cors: ' + ', '.join(cors_config))

    # support logging in python3
    logging.config.fileConfig(
        settings['logging.config'],
        disable_existing_loggers=False
    )

    # DB 3 users cache
    # DB 4 groups cache
    # DB 5 clients

    manager_id = settings['manager']
    MANAGERS.append(manager_id)

    loop = asyncio.get_event_loop()

    loop.run_until_complete(config_db(registry, settings))
    loop.run_until_complete(config_ldap(registry, settings))
    # loop.run_until_complete(config_mailer(config.registry, settings))

    # Per fer un auth token amb un auth service
    registry['settings']['ttl_auth_code'] = 120

    # El token de l'usuari
    registry['settings']['ttl_auth'] = 86400  # !24h fins que no tinguem renew

    # L'auth token del sistema
    registry['settings']['ttl_service_token'] = 36600

    # TTL search
    registry['settings']['ttl_search'] = 360
    registry['settings']['ttl_user_info'] = 360

    # Password policy modules
    valid_password_module = settings['valid_password'].rsplit('.', 1)
    password_policy_module = settings['password_policy'].rsplit('.', 1)

    m = importlib.import_module(valid_password_module[0])
    valid_password = getattr(m, valid_password_module[1])

    m = importlib.import_module(password_policy_module[0])
    password_policy = getattr(m, password_policy_module[1])

    registry['settings']['valid_password'] = valid_password
    registry['settings']['password_policy'] = password_policy

    # config.add_settings(debug=settings['debug'] == 'True')

    app.router.add_get('/', say_hello)
    app.router.add_post('/get_authorization_code', endpoints.get_authorization_code)
    cors.add(app.router.add_post('/get_auth_token', endpoints.get_token))
    cors.add(app.router.add_post('/password', endpoints.set_password))
    cors.add(app.router.add_post('/refresh', endpoints.refresh_token))

    app.router.add_post('/search_user', search.search_user)
    app.router.add_post('/valid_token', valid.valid_token)
    app.router.add_post('/get_user', users.get_user)
    app.router.add_post('/get_users', users.get_users)
    app.router.add_post('/get_group', groups.get_group)
    app.router.add_post('/add_user', users.add_user)
    app.router.add_post('/add_group', groups.add_group)
    app.router.add_post('/add_scope', users.add_scope)
    app.router.add_get('/get_scopes', users.get_scopes)
    app.router.add_post('/grant_scope_roles', users.grant_user_scope_roles)
    app.router.add_post('/deny_scope_roles', users.deny_user_scope_roles)
    app.router.add_get('/ping', ping)

    setup_swagger(
        app,
        description="""OAuth Server to connecto to plone.server""",
        title="plone.oauth",
        api_version="1.0.0",
        contact="https://github.com/plone/plone.oauth")

    async def close_redis(app):
        log.info('Closing REDIS pools connections ...')
        registry['settings']['db_cauths'].close()
        registry['settings']['db_tauths'].close()
        registry['settings']['db_token'].close()
        registry['settings']['db_pool_users'].close()
        registry['settings']['db_pool_groups'].close()
        await registry['settings']['db_cauths'].wait_closed()
        await registry['settings']['db_tauths'].wait_closed()
        await registry['settings']['db_token'].wait_closed()
        await registry['settings']['db_pool_users'].wait_closed()
        await registry['settings']['db_pool_groups'].wait_closed()
        log.info('Closed REDIS pools connections.')

    app.on_cleanup.append(close_redis)

    app['settings'] = registry['settings']
    return app
