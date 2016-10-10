from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.httpexceptions import HTTPNotImplemented
from pyramid.httpexceptions import HTTPFound
import asyncio
from pyramid.view import view_config
import uuid
import logging
import jwt
from datetime import datetime, timedelta
from pyramid.response import Response
from ldap3 import Server, Connection, SUBTREE, ASYNC, SIMPLE, ANONYMOUS, SASL
import plone.oauth
import os

log = logging.getLogger(__name__)


# get_authorization_code
@view_config(route_name='get_authorization_code',
             request_method='POST',
             http_cache=0)
@asyncio.coroutine
def get_authorization_code(request):
    """
    Request: POST /get_authorization_code
                    ?response_type=[code, url]
                    &client_id={CLIENT_ID}
                    &service_token={SERVICE_TOKEN}
                    &scopes={SCOPE}
                    [&redirect_uri={REDIRECT_URI}]
    Response: HTTP 302
                Location={REDIRECT_URI}
                    ?code={CODE}

    Error Response: HTTP 302
                Location={REDIRECT_URI}
                    ?error=access_denied

    """

    try:
        json_body = request.json_body
    except:
        json_body = {}

    response_type = request.params.get('response_type', None)
    response_type = json_body.get('response_type', response_type)
    if response_type is None:
        raise HTTPBadRequest('response_type is missing')

    if response_type not in ['code', 'url']:
        raise HTTPBadRequest('response_type needs to be code or url')

    client_id = request.params.get('client_id', None)
    client_id = json_body.get('client_id', client_id)
    if client_id is None:
        raise HTTPBadRequest('client_id is missing')

    scopes = request.params.get('scopes', None)
    if scopes is None:
        raise HTTPBadRequest('scopes is missing')

    if not isinstance(scopes, list):
        scopes = scopes.split(',')
    scopes = json_body.get('scopes', scopes)

    service_token = request.params.get('service_token', None)
    service_token = json_body.get('service_token', service_token)
    if service_token is None:
        raise HTTPBadRequest('service_token is missing')

    db = request.registry.settings['db_tauths']

    # We check the service token
    with (yield from db) as redis:
        service_client_id = yield from redis.get(service_token)

    if service_client_id is None:
        raise HTTPBadRequest('Invalid Service Token')

    # We need to check if the client is ok for the scope
    # Table of valid clients and scopes
    config = request.registry.settings['db_config']
    ttl = request.registry.settings['ttl_auth_code']
    secret = request.registry.settings['jwtsecret']
    debug = request.registry.settings['debug']

    for scope in scopes:
        if not config.hasScope(scope):
            log.error('Not valid scope ' + scope)
            return HTTPUnauthorized("Wrong scope")

    if not config.hasClient(client_id):
        # S'hauria de reenviar a authentificacio de l'usuari per acceptar-ho
        log.error('Not valid client_id ' + client_id)
        return HTTPUnauthorized("Wrong client id")

    # If its ok create a authorization code
    auth_code = uuid.uuid4().hex

    db = request.registry.settings['db_cauths']

    # We store the client
    for scope in scopes:
        client_scope = str(client_id)
        with (yield from db) as redis:
            yield from redis.set(auth_code + '::' + scope, client_scope)
            yield from redis.expire(auth_code, ttl)

    # We log it
    if debug:
        log.warn('Auth Code from Client : %s', client_id)

    # if its ok redirect to get_access_token
    token = jwt.encode(
        {
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=ttl),
            'auth_code': auth_code
        },
        secret,
        algorithm='HS256')

    if response_type == 'url':
        redirect_uri = request.params.get('redirect_uri', None)
        if redirect_uri is None:
            raise HTTPBadRequest('redirect_uri is missing')

        response = HTTPFound(location=redirect_uri + '?code=' + token)
    else:
        response = Response(body=token, content_type='text/plain')

    origin = request.headers.get('Origin', None)
    if origin and origin in plone.oauth.CORS:
        response.headers['Access-Control-Allow-Origin'] = origin
    elif origin:
        return HTTPUnauthorized("Wrong Origin")

    return response


def preflight(request):
    origin = request.headers.get('Origin', None)
    if not origin:
        try:
            origin = request.headers.__dict__['environ']['HTTP_Origin']
        except:
            raise HTTPBadRequest('Origin header is missing')
    if origin in plone.oauth.CORS:
        response = Response()
        response.headers['Access-Control-Allow-Headers'] = 'origin, content-type, accept'
        response.headers['Access-Control-Allow-Methods'] = 'POST'
        response.headers['Access-Control-Allow-Origin'] = origin
        return response
    else:
        raise HTTPBadRequest('Not valid origin : ' + origin)


@view_config(route_name='get_auth_token',
             request_method='OPTIONS',
             http_cache=0)
@asyncio.coroutine
def get_auth_token_options(request):
    return preflight(request)


# get_token
@view_config(route_name='get_auth_token',
             request_method='POST',
             http_cache=0)
@asyncio.coroutine
def get_token(request):
    """
    Request: POST /get_auth_token
                grant_type=[user, service]
                client_id={CLIENT_ID}
                username={USERNAME}   | client_secret={CLIENT_SECRET}
                password={PASSWORD}   |
                code={AUTHCODE}       |
                [scope={SCOPE}]
    Response: HTTP 302
                Location={REDIRECT_URI}
                    ?code={CODE}

    Error Response: HTTP 302
                Location={REDIRECT_URI}
                    ?error=access_denied

    """
    try:
        json_body = request.json_body
    except:
        json_body = {}

    grant_type = request.params.get('grant_type', None)
    grant_type = json_body.get('grant_type', grant_type)

    if grant_type is None:
        raise HTTPBadRequest('grant_type is missing')

    if grant_type not in ['user', 'service']:
        raise HTTPBadRequest('grant_type not valid')

    client_id = request.params.get('client_id', None)
    client_id = json_body.get('client_id', client_id)

    if client_id is None:
        raise HTTPBadRequest('client_id is missing')

    secret = request.registry.settings['jwtsecret']
    debug = request.registry.settings['debug']

    if grant_type == 'service':
        # Get client secret
        client_secret = request.params.get('client_secret', None)
        client_secret = json_body.get('client_secret', client_secret)
        if client_secret is None:
            raise HTTPBadRequest('client_secret is missing')

        # Get DB
        db_config = request.registry.settings['db_config']
        if not db_config.clientAuth(client_id, client_secret):
            raise HTTPBadRequest('BAD client secret')

        # If its ok create a service token
        token = uuid.uuid4().hex

        # We store the service_token
        ttl = request.registry.settings['ttl_service_token']
        db_tauths = request.registry.settings['db_tauths']
        with (yield from db_tauths) as redis:
            yield from redis.set(token, str(client_id))
            yield from redis.expire(token, ttl)

        # We log it
        if debug:
            log.warn('Service token for client : %s', client_id)

        # generate JWT
        token = jwt.encode(
            {
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(seconds=ttl),
                'service_token': token
            },
            secret,
            algorithm='HS256')

        response = Response(body=token, content_type='text/plain')

    if grant_type == 'user':
        scopes = request.params.get('scopes', None)
        if scopes and not isinstance(scopes, list):
            scopes = scopes.split(',')
        scopes = json_body.get('scopes', scopes)

        if scopes is None:
            raise HTTPBadRequest('scopes is missing')

        code = request.params.get('code', None)
        code = json_body.get('code', code)
        if code is None:
            raise HTTPBadRequest('code is missing')

        db_cauths = request.registry.settings['db_cauths']

        with (yield from db_cauths) as redis:
            for scope in scopes:
                db_client_id = yield from redis.get(code + '::' + scope)

                if db_client_id is None:
                    raise HTTPBadRequest('Invalid Auth code')

                if db_client_id != bytes(client_id, encoding='utf-8'):
                    raise HTTPBadRequest('Invalid Client ID')
                yield from redis.delete(code + '::' + scope)

        username = request.params.get('username', None)
        username = json_body.get('username', username)

        if username is None:
            raise HTTPBadRequest('username is missing')

        password = request.params.get('password', None)
        password = json_body.get('password', password)

        if password is None:
            raise HTTPBadRequest('Password is missing')

        # Validate user
        user_manager = request.registry.settings['user_manager']
        result = yield from user_manager.loginUser(username, password)

        if not result:
            raise HTTPUnauthorized('Password/Username is not valid')

        if type(result['mail']) is list and len(result['mail']):
            login = result['mail'][0]
        else:
            login = result['mail']
        userName = ' '.join(result['cn'])

        # Generate token
        token = uuid.uuid4().hex
        ttl = request.registry.settings['ttl_auth']

        db_token = request.registry.settings['db_token']

        with (yield from db_token) as redis:
            yield from redis.set(token, username)
            yield from redis.expire(token, ttl)

            # Notify auth
            yield from redis.publish_json('auth', {
                'username': username,
                'status': True,
                'domain': request.domain,
                'agent': request.user_agent,
                'ip': request.client_addr,
                'scope': scope
                })

        if debug:
            log.warn('Access Code from User : %s', client_id)

        # if its ok redirect to get_access_token
        token = jwt.encode(
            {
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(seconds=ttl),
                'token': token,
                'login': login,
                'name': userName,
                'superuser': plone.oauth.is_superuser(login)
            },
            secret,
            algorithm='HS256')

        response = Response(body=token, content_type='text/plain')

    origin = request.headers.get('Origin', None)
    if origin is None:
        try:
            origin = request.headers.__dict__['environ']['HTTP_Origin']
        except:
            origin = None
    if origin and origin in plone.oauth.CORS:
        response.headers['Access-Control-Allow-Origin'] = origin
    elif origin:
        return HTTPUnauthorized("Wrong Origin " + origin)

    return response


@view_config(route_name='password',
             request_method='OPTIONS',
             http_cache=0)
@asyncio.coroutine
def set_password_options(request):
    return preflight(request)


@view_config(route_name='password',
             request_method='POST',
             http_cache=0)
@asyncio.coroutine
def set_password(request):
    """
    Request: POST /password
                client_id={CLIENT_ID}
                token={TOKEN}
                password={NEW_PASSWORD}
    Response: HTTP 200
                JWT

    Error Response: HTTP 302
                ERROR

    """
    try:
        json_body = request.json_body
    except:
        json_body = {}

    db_tauths = request.registry.settings['db_tauths']

    client_id = request.params.get('client_id', None)
    client_id = json_body.get('client_id', client_id)
    if client_id is None:
        raise HTTPBadRequest('client_id is missing')

    token = request.params.get('token', None)
    token = json_body.get('token', token)
    if token is None:
        raise HTTPBadRequest('token is missing')

    db_token = request.registry.settings['db_token']

    with (yield from db_token) as redis:
        user = yield from redis.get(token)

    if user is None:
        raise HTTPBadRequest('user invalid')

    user = user.decode('utf-8')

    password = request.params.get('password', None)
    password = json_body.get('password', password)
    if password is None:
        raise HTTPBadRequest('password invalid')

    valid_password = request.registry.settings['valid_password']
    password_policy = request.registry.settings['password_policy']
    if not valid_password(password):
        password_policy = password_policy()
        raise HTTPBadRequest('Password not valid: %s', password_policy)

    config = request.registry.settings['db_config']

    if not config.hasClient(client_id):
        # S'hauria de reenviar a authentificacio de l'usuari per acceptar-ho
        log.error('Not valid client_id ' + client_id)
        return HTTPUnauthorized("Wrong client id")

    secret = request.registry.settings['jwtsecret']
    debug = request.registry.settings['debug']
    ttl = request.registry.settings['ttl_auth']

    # We can change the password
    user_manager = request.registry.settings['user_manager']
    try:
        result = yield from user_manager.setPassword(user, password)
    except:
        raise HTTPBadRequest('Password not valid: %s', password_policy())

    if not result:
        raise HTTPBadRequest('Failed policy LDAP')

    # Generate token
    newtoken = uuid.uuid4().hex
    ttl = request.registry.settings['ttl_auth']

    db_token = request.registry.settings['db_token']

    userName = yield from user_manager.getUserName(user)

    with (yield from db_token) as redis:
        yield from redis.delete(token, user)
        yield from redis.set(newtoken, user)
        yield from redis.expire(newtoken, ttl)

        # Notify auth
        yield from redis.publish_json('password', {
            'username': user,
            'status': True,
            'domain': request.domain,
            'agent': request.user_agent,
            'ip': request.client_addr,
            'scope': 'plone'
            })

    if debug:
        log.warn('Access Code from User : %s', client_id)

    # if its ok redirect to get_access_token
    newtoken = jwt.encode(
        {
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=ttl),
            'token': newtoken,
            'login': user,
            'name': userName,
            'superuser': plone.oauth.is_superuser(user)
        },
        secret,
        algorithm='HS256')

    response = Response(body=newtoken, content_type='text/plain')

    origin = request.headers.get('Origin', None)
    if origin is None:
        try:
            origin = request.headers.__dict__['environ']['HTTP_Origin']
        except:
            origin = None
    if origin and origin in plone.oauth.CORS:
        response.headers['Access-Control-Allow-Origin'] = origin
    elif origin:
        return HTTPUnauthorized("Wrong Origin " + origin)

    return response


@view_config(route_name='refresh',
             request_method='OPTIONS',
             http_cache=0)
@asyncio.coroutine
def refresh_token_options(request):
    return preflight(request)


@view_config(route_name='refresh',
             request_method='POST',
             http_cache=0)
@asyncio.coroutine
def refresh_token(request):
    """
    Request: POST /refresh
                client_id={CLIENT_ID}
                token={TOKEN}
                user={USER}
    Response: HTTP 200
                JWT

    Error Response: HTTP 302
                ERROR

    """
    try:
        json_body = request.json_body
    except:
        json_body = {}

    # access_token = request.params.get('code', None)
    # access_token = json_body.get('code', access_token)
    # if access_token is None:
    #     raise HTTPBadRequest('code is missing')

    db_tauths = request.registry.settings['db_tauths']

    client_id = request.params.get('client_id', None)
    client_id = json_body.get('client_id', client_id)
    if client_id is None:
        raise HTTPBadRequest('client_id is missing')

    token = request.params.get('token', None)
    token = json_body.get('token', token)
    if token is None:
        raise HTTPBadRequest('token is missing')

    request_user = request.params.get('user', None)
    request_user = json_body.get('user', request_user)
    if request_user is None:
        raise HTTPBadRequest('user is missing')

    # with (yield from db_tauths) as redis:
    #     db_client_id = yield from redis.get(access_token)

    # try:
    #     post_splited = db_client_id.split(b'::')
    # except:
    #     raise HTTPBadRequest('Bad scope stored for the client')
    # try:
    #     real_db_client_id = post_splited[0].decode()
    # except:
    #     raise HTTPBadRequest('Bad client_id stored for the client')
    # try:
    #     int_client_id = client_id
    # except:
    #     raise HTTPBadRequest('bad client_id')

    # if real_db_client_id is None or real_db_client_id != int_client_id:
    #     raise HTTPBadRequest('Invalid Auth code')

    db_token = request.registry.settings['db_token']

    with (yield from db_token) as redis:
        user = yield from redis.get(token)

    if user is None:
        raise HTTPBadRequest('user invalid')

    user = user.decode('utf-8')

    if user != request_user:
        raise HTTPBadRequest('valid user mismatch')

    config = request.registry.settings['db_config']

    if not config.hasClient(client_id):
        # S'hauria de reenviar a authentificacio de l'usuari per acceptar-ho
        log.error('Not valid client_id ' + client_id)
        return HTTPUnauthorized("Wrong client id")

    secret = request.registry.settings['jwtsecret']
    debug = request.registry.settings['debug']
    ttl = request.registry.settings['ttl_auth']

    # Generate token
    newtoken = uuid.uuid4().hex
    ttl = request.registry.settings['ttl_auth']

    user_manager = request.registry.settings['user_manager']

    userName = yield from user_manager.getUserName(user)

    db_token = request.registry.settings['db_token']

    with (yield from db_token) as redis:
        yield from redis.delete(token, user)
        yield from redis.set(newtoken, user)
        yield from redis.expire(newtoken, ttl)

        # Notify auth
        yield from redis.publish_json('refresh', {
            'username': user,
            'status': True,
            'domain': request.domain,
            'agent': request.user_agent,
            'ip': request.client_addr,
            'scope': 'plone'
            })

    if debug:
        log.warn('Access Code from User : %s', client_id)

    # if its ok redirect to get_access_token
    newtoken = jwt.encode(
        {
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=ttl),
            'token': newtoken,
            'login': user,
            'name': userName,
            'superuser': plone.oauth.is_superuser(user)
        },
        secret,
        algorithm='HS256')

    response = Response(body=newtoken, content_type='text/plain')

    origin = request.headers.get('Origin', None)
    if origin is None:
        try:
            origin = request.headers.__dict__['environ']['HTTP_Origin']
        except:
            origin = None
    if origin and origin in plone.oauth.CORS:
        response.headers['Access-Control-Allow-Origin'] = origin
    elif origin:
        return HTTPUnauthorized("Wrong Origin " + origin)

    return response