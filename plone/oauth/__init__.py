import logging.config

from pyramid.config import Configurator
import aioredis
import asyncio
import sys
import importlib
import json
from ldap3 import Server
from plone.oauth.ldap import LDAPUserManager
from plone.oauth.config import LDAPConfigManager

from plone.oauth import endpoints
from plone.oauth import search
from plone.oauth import valid
from plone.oauth import users
from plone.oauth import groups
from plone.oauth import views

from pyramid_mailer import mailer_factory_from_settings


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
            user_filter=registry.settings['ldap.userfilter'],
            base_dn=registry.settings['ldap.base_dn'],
            root_dn=registry.settings['ldap.root_dn'],
            passwd_dn=registry.settings['ldap.root_pw'],
            user_profile=json.loads(registry.settings['ldap.userProfile']),
            read_only=False,
            cache_users=db_pool_users,
            cache_groups=db_pool_groups)

    elif registry.settings['backend'] == 'LDAP':
        ldap_object = LDAPUserManager(
            server,
            config.registry.settings['ldap.userfilter'])

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


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """

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

    config.add_route('say_hello', '/')

    config.add_route('get_authorization_code', '/get_authorization_code')
    config.add_route('get_auth_token', '/get_auth_token')
    config.add_route('password', '/password')
    config.add_route('refresh', '/refresh')
    config.add_route('search_user', '/search_user')
    config.add_route('valid_token', '/valid_token')
    config.add_route('get_user', '/get_user')
    config.add_route('get_users', '/get_users')
    config.add_route('get_group', '/get_group')

    config.add_route('add_user', '/add_user')
    config.add_route('add_group', '/add_group')
    config.add_route('add_scope', '/add_scope')
    config.add_route('get_scopes', '/get_scopes')
    config.add_route('grant_scope_roles', '/grant_scope_roles')
    config.add_route('deny_scope_roles', '/deny_scope_roles')

    config.scan(endpoints)
    config.scan(search)
    config.scan(valid)
    config.scan(users)
    config.scan(groups)
    config.scan(views)
    return config.make_wsgi_app()

def includeme(config):
    """
    Callable to allow extending this Pyramid application with
    `config.include('plone.oauth')`
    """
    return main(config, **config.registry.settings)
