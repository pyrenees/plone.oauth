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
import logstash
import os

log = logging.getLogger(__name__)

logging.basicConfig(
    format='%(name)s - %(asctime)s - %(levelname)s - %(message)s',
    datefmt='%m/%d/%Y %H:%M:%S')
logger = logging.getLogger('classifier')
log.setLevel(logging.WARN)

logstash_addr = os.environ.get('LOGSTASH_PORT_5000_TCP_ADDR', None)
logstash_port = int(os.environ.get('LOGSTASH_PORT_5000_TCP_PORT', 0))

if logstash_addr:
    log.addHandler(logstash.LogstashHandler(
        logstash_addr,
        logstash_port,
        version=1))


# get_authorization_code
# In case is a trust service we don't need redirect_uri
@view_config(route_name='get_authorization_code',
             request_method='GET',
             http_cache=0)
@asyncio.coroutine
def get_authorization_code(request):
    """
    Request: GET /get_authorization_code
                    ?response_type=code
                    &client_id={CLIENT_ID}
                    &scope={SCOPE}
                    [&redirect_uri={REDIRECT_URI}]
    Response: HTTP 302
                Location={REDIRECT_URI}
                    ?code={CODE}

    Error Response: HTTP 302
                Location={REDIRECT_URI}
                    ?error=access_denied

    """
    response_type = request.params.get('response_type', None)
    if response_type is None:
        raise HTTPBadRequest('response_type is missing')

    if response_type != 'code':
        raise HTTPNotImplemented('response_type needs to be code')

    client_id = request.params.get('client_id', None)
    if client_id is None:
        raise HTTPBadRequest('client_id is missing')

    #try:
    #    client_id = int(client_id)
    #except:
    #    raise HTTPBadRequest('client_id is not number')

    redirect_uri = request.params.get('redirect_uri', None)

    scope = request.params.get('scope', None)
    if scope is None:
        raise HTTPBadRequest('scope is missing')

    # We need to check if the client is ok for the scope
    # Table of valid clients and scopes
    config = request.registry.settings['db_config']
    ttl = request.registry.settings['ttl_auth_service']
    secret = request.registry.settings['jwtsecret']
    debug = request.registry.settings['debug']

    if not config.hasScope(scope):
        return HTTPUnauthorized("Wrong scope")

    if not config.hasClient(client_id):
        # S'hauria de reenviar a authentificacio de l'usuari per acceptar-ho
        return HTTPUnauthorized("Wrong client id")

    # If its ok create a authorization code
    auth_code = uuid.uuid4().hex

    db = request.registry.settings['db_cauths']

    # We store the client
    client_scope = str(client_id) + '::' + scope
    with (yield from db) as redis:
        yield from redis.set(auth_code, client_scope)
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

    if redirect_uri is not None:
        # Redirect to url
        return HTTPFound(location=redirect_uri + '?code=' + token)
    else:
        return Response(body=token, content_type='text/plain')


# Protected on header with the X-Intranetum-AuthService
# get_token
@view_config(route_name='get_auth_token',
             request_method='POST',
             http_cache=0)
@asyncio.coroutine
def get_token(request):
    """
    Request: POST /get_token
                grant_type=[password, authorization_code]
                code={SERVICETOKEN}  | code={AUTHCODE}
                username={CLIENT_ID} | client_id={CLIENT_ID}
                password={CLIENT_ID} | client_secret={CLIENT_SECRET}
                [scope={SCOPE}]
    Response: HTTP 302
                Location={REDIRECT_URI}
                    ?code={CODE}

    Error Response: HTTP 302
                Location={REDIRECT_URI}
                    ?error=access_denied

    """
    scope = request.params.get('scope', None)
    if scope is None:
        raise HTTPBadRequest('scope is missing')

    grant_type = request.params.get('grant_type', None)
    if grant_type is None:
        raise HTTPBadRequest('response_type is missing')

    if grant_type not in ['password', 'authorization_code']:
        raise HTTPNotImplemented('grant_type not valid')

    secret = request.registry.settings['jwtsecret']
    debug = request.registry.settings['debug']

    if grant_type == 'authorization_code':
        client_id = request.params.get('client_id', None)
        if client_id is None:
            raise HTTPBadRequest('client_id is missing')

        client_secret = request.params.get('client_secret', None)
        if client_secret is None:
            raise HTTPBadRequest('client_secret is missing')

        code = request.params.get('code', None)
        if code is None:
            raise HTTPBadRequest('code is missing')

        # check auth code
        db_cauths = request.registry.settings['db_cauths']
        with (yield from db_cauths) as redis:
            db_client_id = yield from redis.get(code)
        try:
            post_splited = db_client_id.split(b'::')
        except:
            raise HTTPBadRequest('Bad scope stored for the client')
        try:
            real_db_client_id = post_splited[0].decode()
        except:
            raise HTTPBadRequest('Bad client_id stored for the client')
        try:
            real_client_id = client_id
            real_scope = post_splited[1]
        except:
            raise HTTPBadRequest('BAD client ID INT')

        if real_db_client_id != real_client_id:
            raise HTTPBadRequest('BAD client ID')

        if real_scope != bytes(scope, 'utf-8'):
            raise HTTPBadRequest('BAD scope')

        db_config = request.registry.settings['db_config']
        if not db_config.clientAuth(real_client_id, client_secret):
            raise HTTPBadRequest('BAD client secret')

        # If its ok create a authorization code
        token = uuid.uuid4().hex
        ttl = request.registry.settings['ttl_access_token']

        db_tauths = request.registry.settings['db_tauths']

        # We store the client
        client_scope = str(client_id) + '::' + scope
        with (yield from db_tauths) as redis:
            yield from redis.set(token, client_scope)
            yield from redis.expire(token, ttl)

        # We log it
        if debug:
            log.warn('Access Code from Client : %s', client_id)

        # if its ok redirect to get_access_token
        token = jwt.encode(
            {
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(seconds=ttl),
                'access_token': token
            },
            secret,
            algorithm='HS256')

        return Response(body=token, content_type='text/plain')

    if grant_type == 'password':

        access_token = request.params.get('code', None)
        if access_token is None:
            raise HTTPBadRequest('code is missing')

        db_tauths = request.registry.settings['db_tauths']

        with (yield from db_tauths) as redis:
            client_id = yield from redis.get(access_token)

        if client_id is None:
            raise HTTPBadRequest('Invalid Auth code')

        username = request.params.get('username', None)
        if username is None:
            raise HTTPBadRequest('username is missing')

        password = request.params.get('password', None)
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

        return Response(body=token, content_type='text/plain')


@view_config(route_name='password',
             request_method='POST',
             http_cache=0)
@asyncio.coroutine
def set_password(request):
    """
    Request: POST /password
                code={SERVICETOKEN}
                client_id={CLIENT_ID}
                token={TOKEN}
                password={CLIENT_ID}
    Response: HTTP 200
                JWT

    Error Response: HTTP 302
                ERROR

    """
    access_token = request.params.get('code', None)
    if access_token is None:
        raise HTTPBadRequest('code is missing')

    db_tauths = request.registry.settings['db_tauths']

    client_id = request.params.get('client_id', None)
    if client_id is None:
        raise HTTPBadRequest('client_id is missing')

    token = request.params.get('token', None)
    if token is None:
        raise HTTPBadRequest('token is missing')

    with (yield from db_tauths) as redis:
        db_client_id = yield from redis.get(access_token)

    try:
        post_splited = db_client_id.split(b'::')
    except:
        raise HTTPBadRequest('Bad scope stored for the client')
    try:
        real_db_client_id = post_splited[0].decode()
    except:
        raise HTTPBadRequest('Bad client_id stored for the client')
    try:
        int_client_id = client_id
    except:
        raise HTTPBadRequest('bad client_id')

    if real_db_client_id is None or real_db_client_id != int_client_id:
        raise HTTPBadRequest('Invalid Auth code')

    db_token = request.registry.settings['db_token']

    with (yield from db_token) as redis:
        user = yield from redis.get(token)

    if user is None:
        raise HTTPBadRequest('user invalid')

    user = user.decode('utf-8')

    password = request.params.get('password', None)
    if password is None:
        raise HTTPBadRequest('password invalid')

    valid_password = request.registry.settings['valid_password']
    password_policy = request.registry.settings['password_policy']
    if not valid_password(password):
        password_policy = password_policy()
        raise HTTPBadRequest('Password not valid: %s', password_policy)

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
            'token': newtoken
        },
        secret,
        algorithm='HS256')

    return Response(body=newtoken, content_type='text/plain')


@view_config(route_name='refresh',
             request_method='POST',
             http_cache=0)
@asyncio.coroutine
def refresh_token(request):
    """
    Request: POST /refresh
                code={SERVICETOKEN}
                client_id={CLIENT_ID}
                token={TOKEN}
                user={USER}
    Response: HTTP 200
                JWT

    Error Response: HTTP 302
                ERROR

    """
    access_token = request.params.get('code', None)
    if access_token is None:
        raise HTTPBadRequest('code is missing')

    db_tauths = request.registry.settings['db_tauths']

    client_id = request.params.get('client_id', None)
    if client_id is None:
        raise HTTPBadRequest('client_id is missing')

    token = request.params.get('token', None)
    if token is None:
        raise HTTPBadRequest('token is missing')

    request_user = request.params.get('user', None)
    if request_user is None:
        raise HTTPBadRequest('user is missing')

    with (yield from db_tauths) as redis:
        db_client_id = yield from redis.get(access_token)

    try:
        post_splited = db_client_id.split(b'::')
    except:
        raise HTTPBadRequest('Bad scope stored for the client')
    try:
        real_db_client_id = post_splited[0].decode()
    except:
        raise HTTPBadRequest('Bad client_id stored for the client')
    try:
        int_client_id = client_id
    except:
        raise HTTPBadRequest('bad client_id')

    if real_db_client_id is None or real_db_client_id != int_client_id:
        raise HTTPBadRequest('Invalid Auth code')

    db_token = request.registry.settings['db_token']

    with (yield from db_token) as redis:
        user = yield from redis.get(token)

    if user is None:
        raise HTTPBadRequest('user invalid')

    user = user.decode('utf-8')

    if user != request_user:
        raise HTTPBadRequest('valid user mismatch')

    secret = request.registry.settings['jwtsecret']
    debug = request.registry.settings['debug']
    ttl = request.registry.settings['ttl_auth']

    # Generate token
    newtoken = uuid.uuid4().hex
    ttl = request.registry.settings['ttl_auth']

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
            'token': newtoken
        },
        secret,
        algorithm='HS256')

    return Response(body=newtoken, content_type='text/plain')
