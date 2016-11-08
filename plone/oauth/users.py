import asyncio
import uuid
import logging
import ujson
from ldap3 import Server
from ldap3 import Connection
from ldap3 import SUBTREE
from ldap3 import ASYNC
from ldap3 import SIMPLE
from ldap3 import ANONYMOUS
from ldap3 import SASL
import requests
import aiohttp
from pyramid_mailer.message import Message
from validate_email import validate_email
import ast
from aiohttp.web import HTTPBadRequest, Response

import plone.oauth
from plone.oauth.utils.password import generate_password
from plone.oauth.utils.request import check_superuser
from plone.oauth.utils.request import check_manager
from plone.oauth.utils.request import get_validate_request
from plone.oauth.utils.response import jwt_response


log = logging.getLogger(__name__)


welcome_message = """
Hello,

In order to access to your {scope} please login by using your email {user} and the following

password: {password}

"""


async def get_user(request):
    """Protected for the user or superuser

    Request: POST /get_user
        Body :
            - user_token
            - service_token (json)
            - scope
            - user

    Response HTTP 200 in JWT token:
        {
            'roles': {
                'Manager': 1
            },
            'groups': [
                'Group1'
            ],
            'name':
        }

    """
    request_data = await get_validate_request(request)
    scope = request_data.get('scope')
    username = request_data.get('username')

    user = request.params.get('user', None)
    if user is None:
        raise HTTPBadRequest('user is missing')
    if not validate_email(user):
        raise HTTPBadRequest("user isn't a valid email address")

    if username != user:
        await check_manager(username, scope, request)  # !!important

    ttl = request.app['settings']['ttl_user_info']
    db_token = request.app['settings']['db_token']
    user_scope = '{0}::{1}'.format(user, scope)
    # Search Redis
    with (await db_token) as redis:
        result = await redis.get(user_scope)

    result = None
    if result is not None:
        result = ujson.loads(result)
    else:
        # Search LDAP
        user_manager = request.app['settings']['user_manager']
        result = await user_manager.getUserInfo(user, scope)
        if plone.oauth.is_superuser(user):
            # Add superadmins roles to scope
            result['roles']['Manager'] = 1

        # Cache in redis
        with (await db_token) as redis:
            await redis.set(user_scope, ujson.dumps(result))
            await redis.expire(user_scope, ttl)

    token = jwt_response(request, result)
    return Response(body=token, content_type='text/plain')


async def get_users(request):
    """Protected for the user or superuser

    Request: POST /get_users
        Body :
            - user_token
            - service_token (json)
            - scope

    Response HTTP 200 in JWT token:

    """
    request_data = await get_validate_request(request)
    scope = request_data.get('scope')
    username = request_data.get('username')

    plone.oauth.is_superuser(username)  # !!important

    user_manager = request.app['settings']['user_manager']
    users = await user_manager.getScopeUsers(scope)

    token = jwt_response(request, users)
    return Response(body=token, content_type='text/plain')


async def add_user(request):
    """Request: POST /add_user

        Body :
            - user_token
            - service_token (json)
            - scope
            - user
            - password

    Response HTTP 200 in JWT token:
        success

    Response HTTP 400 in JWT token:
        entryAlreadyExists

    """
    request_data = await get_validate_request(request)
    scope = request_data.get('scope')
    username = request_data.get('username')

    check_superuser(username)  # !!important

    user = request.params.get('user', None)
    if user is None:
        raise HTTPBadRequest('user is missing')
    if not validate_email(user):
        raise HTTPBadRequest("user isn't a valid email address")

    password = request.params.get('password', None)
    if password is None:
        raise HTTPBadRequest('password is missing')

    # Add LDAP
    user_manager = request.app['settings']['user_manager']
    result = await user_manager.addUser(user, password)

    status = 500
    if result == 'success':
        status = 200
    elif result == 'entryAlreadyExists':
        status = 400

    token = jwt_response(request, result)
    return Response(status=status, body=token, content_type='text/plain')


async def add_scope(request):
    """Request: POST /add_scope

        Body :
            - user_token
            - service_token
            - scope
            - admin_user

    Response HTTP 200 in JWT token:
        success

    Response HTTP 400 in JWT token:
        entryAlreadyExists

    """
    request_data = await get_validate_request(request)
    scope = request_data.get('scope')
    username = request_data.get('username')

    check_superuser(username)  # !!important

    # Obtenim el correu del l'administrador(Manager) del site
    admin_user = request.params.get('admin_user', None)
    if admin_user is None:
        raise HTTPBadRequest('admin_user is missing')
    if not validate_email(admin_user):
        raise HTTPBadRequest("user isn't a valid email address")

    # Add LDAP Scope
    user_manager = request.app['settings']['user_manager']
    result = await user_manager.addScope(scope)

    if result == 'success':
        status = 200
    elif result == 'entryAlreadyExists':
        status = 400
        token = jwt_response(request, result)
        return Response(status=status, body=token, content_type='text/plain')
    else:
        raise HTTPBadRequest('scope creation')

    # Add user (only if user aren't exists)
    new_password = generate_password()
    result_user = await user_manager.addUser(admin_user, new_password)

    if result_user == 'success':
        pass
        # send mail
        # mailer = request.registry['mailer']
        # text_message = welcome_message.format(
        #     password=new_password,
        #     scope=scope,
        #     user=admin_user)
        # message = Message(
        #     subject="[Plone] Welcome manager user",
        #     sender="no-reply@plone.com",
        #     recipients=[admin_user],
        #     body=text_message)
        # mailer.send_immediately(message, fail_silently=False)
    elif result_user != 'entryAlreadyExists':
        raise HTTPBadRequest('user creation')

    # Assign the manager role to the user
    result_role = await user_manager.addScopeRoleUser(
        scope,
        admin_user,
        'manager')

    if result_role != 'success':
        raise HTTPBadRequest('role assignation')

    token = jwt_response(request, result)
    return Response(status=status, body=token, content_type='text/plain')


async def get_scopes(request):
    """Request: GET /get_scopes

        Body :
            - user_token
            - service_token

    Response HTTP 200 in JWT token:
        success

    Response HTTP 400 in JWT token:
        entryAlreadyExists

    """
    service_token = request.params.get('service_token', None)
    if service_token is None:
        raise HTTPBadRequest('service_token is missing')

    db_tauths = request.app['settings']['db_tauths']

    with (await db_tauths) as redis:
        client_id = await redis.get(service_token)

    if client_id is None:
        raise HTTPBadRequest('Invalid service_token')

    user_token = request.params.get('user_token', None)
    if user_token is None:
        raise HTTPBadRequest('user_token is missing')

    # We need the user info so we are going to get it from UserManager
    db_token = request.app['settings']['db_token']
    with (await db_token) as redis:
        username = await redis.get(user_token)

    if username is None:
        raise HTTPBadRequest('Invalid user_token')
    username = username.decode("utf-8")

    # La petició getUserScopes filtra els scopes segons l'username
    user_manager = request.app['settings']['user_manager']
    scopes = await user_manager.getUserScopes(username)

    token = jwt_response(request, scopes)
    return Response(body=token, content_type='text/plain')


async def grant_user_scope_roles(request):
    """Request: POST /grant_scope_roles

        Body :
            - user_token
            - service_token (json)
            - scope
            - user
            - roles

    Response HTTP 200 in JWT token:
        success

    Response HTTP 400 in JWT token:
        entryAlreadyExists

    """
    # Verifiquem que la petició tingui tots els parametres
    request_data = await get_validate_request(request)
    scope = request_data.get('scope')
    username = request_data.get('username')

    # Verifiquem que l'usuari que vol realitzar l'acció és manager
    await check_manager(username, scope, request)  # !!important

    # Obtenim les dades del nou usuari que volem crear
    user = request.params.get('user', None)
    if user is None:
        raise HTTPBadRequest('user is missing')
    if not validate_email(user):
        raise HTTPBadRequest("user isn't a valid email address")

    roles = request.params.get('roles', None)
    if roles is None:
        raise HTTPBadRequest('roles is missing')
    if not isinstance(roles, list):
        roles = ast.literal_eval(roles)

    user_manager = request.app['settings']['user_manager']

    # Creem l'usuari al LDAP
    # Add user (only if user aren't exists)
    new_password = generate_password()
    result_user = await user_manager.addUser(user, new_password)

    logging.info('Added user %s - %s' % (user, result_user))
    if result_user == 'success':
        pass
        # send mail
        # mailer = request.registry['mailer']
        # text_message = welcome_message.format(
        #     password=new_password,
        #     scope=scope,
        #     user=user)

        # logging.info('Sending mail to %s' % user)
        # message = Message(
        #     subject="[Intranetum] Welcome",
        #     sender="no-reply@intranetum.com",
        #     recipients=[user],
        #     body=text_message)
        # mailer.send_immediately(message, fail_silently=False)
    elif result_user != 'entryAlreadyExists':
        raise HTTPBadRequest('user creation')

    # Assign the role to the user
    for role in roles:
        result_role = await user_manager.addScopeRoleUser(scope, user, role)

        if result_role == 'success':
            # Deshabilitem la cache redis per aquest camp
            db_token = request.app['settings']['db_token']
            user_scope = '{0}::{1}'.format(user, scope)
            with (await db_token) as redis:
                result_cache = await redis.delete(user_scope)

            status = 200
        elif result_role == 'attributeOrValueExists':
            status = 400
        else:
            raise HTTPBadRequest('role assignation')

    token = jwt_response(request, result_role)
    return Response(status=status, body=token, content_type='text/plain')


async def deny_user_scope_roles(request):
    """Request: POST /deny_scope_roles

        Body :
            - user_token
            - service_token (json)
            - scope
            - user
            - roles

    Response HTTP 200 in JWT token:
        success

    Response HTTP 400 in JWT token:
        entryAlreadyExists

    """
    # Verifiquem que la petició tingui tots els parametres
    request_data = await get_validate_request(request)
    scope = request_data.get('scope')
    username = request_data.get('username')

    # Verifiquem que l'usuari que vol realitzar l'acció és manager
    await check_manager(username, scope, request)  # !!important

    # Obtenim les dades del nou usuari que volem eliminar els rols
    user = request.params.get('user', None)
    if user is None:
        raise HTTPBadRequest('user is missing')
    if not validate_email(user):
        raise HTTPBadRequest("user isn't a valid email address")

    roles = request.params.get('roles', None)
    if roles is None:
        raise HTTPBadRequest('roles is missing')
    if not isinstance(roles, list):
        roles = ast.literal_eval(roles)

    user_manager = request.app['settings']['user_manager']

    # Remove the role to the user
    for role in roles:
        result_role = await user_manager.delScopeRole(scope, user, role)

        if result_role == 'success':
            # Deshabilitem la cache redis per aquest camp
            db_token = request.app['settings']['db_token']
            user_scope = '{0}::{1}'.format(user, scope)
            with (await db_token) as redis:
                result_cache = await redis.delete(user_scope)

            status = 200
        elif result_role == 'noSuchAttribute':
            status = 400
        else:
            raise HTTPBadRequest('role deny')

    token = jwt_response(request, result_role)
    return Response(status=status, body=token, content_type='text/plain')
