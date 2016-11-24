import uuid
import logging
import jwt
from datetime import datetime, timedelta

from aiohttp.web import Response
from aiohttp.web import HTTPBadRequest, HTTPUnauthorized, HTTPFound
import plone.oauth

from plone.oauth.utils.request import get_domain

log = logging.getLogger(__name__)


async def get_authorization_code(request):
    """Get the authorization code.

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
        json_body = await request.json()
    except:
        json_body = {}

    params = await request.post()
    response_type = params.get('response_type', None)
    response_type = json_body.get('response_type', response_type)
    if response_type is None:
        raise HTTPBadRequest(reason='response_type is missing')

    if response_type not in ['code', 'url']:
        raise HTTPBadRequest(reason='response_type needs to be code or url')

    client_id = params.get('client_id', None)
    client_id = json_body.get('client_id', client_id)
    if client_id is None:
        raise HTTPBadRequest(reason='client_id is missing')

    scopes = params.get('scopes', None)
    if scopes is None:
        raise HTTPBadRequest(reason='scopes is missing')

    if not isinstance(scopes, list):
        scopes = scopes.split(',')
    scopes = json_body.get('scopes', scopes)

    service_token = params.get('service_token', None)
    service_token = json_body.get('service_token', service_token)
    if service_token is None:
        raise HTTPBadRequest(reason='service_token is missing')

    db = request.app['settings']['db_tauths']

    # We check the service token
    with (await db) as redis:
        service_client_id = await redis.get(service_token)

    if service_client_id is None:
        raise HTTPBadRequest(reason='Invalid Service Token')

    # We need to check if the client is ok for the scope
    # Table of valid clients and scopes
    config = request.app['settings']['db_config']
    ttl = request.app['settings']['ttl_auth_code']
    secret = request.app['settings']['jwtsecret']
    debug = request.app['settings']['debug']

    for scope in scopes:
        if not config.hasScope(scope):
            log.error('Not valid scope ' + scope)
            return HTTPUnauthorized(reason="Wrong scope")

    if not config.hasClient(client_id):
        # S'hauria de reenviar a authentificacio de l'usuari per acceptar-ho
        log.error('Not valid client_id ' + client_id)
        return HTTPUnauthorized(reason="Wrong client id")

    # If its ok create a authorization code
    auth_code = uuid.uuid4().hex

    db = request.app['settings']['db_cauths']

    # We store the client
    for scope in scopes:
        client_scope = str(client_id)
        with (await db) as redis:
            await redis.set(auth_code + '::' + scope, client_scope)
            await redis.expire(auth_code, ttl)

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
        redirect_uri = params.get('redirect_uri', None)
        if redirect_uri is None:
            raise HTTPBadRequest(reason='redirect_uri is missing')

        response = HTTPFound(location=redirect_uri + '?code=' + token)
    else:
        response = Response(body=token, content_type='text/plain')

    # origin = request.headers.get('Origin', None)
    # if origin and origin in plone.oauth.CORS:
    #     response.headers['Access-Control-Allow-Origin'] = origin
    # elif origin:
    #     return HTTPUnauthorized("Wrong Origin")

    return response


# def preflight(request):
#     origin = request.headers.get('Origin', None)
#     if not origin:
#         try:
#             origin = request.headers.__dict__['environ']['HTTP_Origin']
#         except:
#             raise HTTPBadRequest(reason='Origin header is missing')
#     if origin in plone.oauth.CORS:
#         response = Response()
#         response.headers['Access-Control-Allow-Headers'] = 'origin, content-type, accept'  # noqa
#         response.headers['Access-Control-Allow-Methods'] = 'POST'
#         response.headers['Access-Control-Allow-Origin'] = origin
#         return response
#     else:
#         raise HTTPBadRequest(reason='Not valid origin : ' + origin)

# async def get_auth_token_options(request):
#     return preflight(request)


async def get_token(request):
    """Get the access token.

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
        json_body = await request.json()
    except:
        json_body = {}

    params = await request.post()
    grant_type = params.get('grant_type', None)
    grant_type = json_body.get('grant_type', grant_type)

    if grant_type is None:
        raise HTTPBadRequest(reason='grant_type is missing')

    if grant_type not in ['user', 'service']:
        raise HTTPBadRequest(reason='grant_type not valid')

    client_id = params.get('client_id', None)
    client_id = json_body.get('client_id', client_id)

    if client_id is None:
        raise HTTPBadRequest(reason='client_id is missing')

    secret = request.app['settings']['jwtsecret']
    debug = request.app['settings']['debug']

    if grant_type == 'service':
        # Get client secret
        client_secret = params.get('client_secret', None)
        client_secret = json_body.get('client_secret', client_secret)
        if client_secret is None:
            raise HTTPBadRequest(reason='client_secret is missing')

        # Get DB
        db_config = request.app['settings']['db_config']
        if not db_config.clientAuth(client_id, client_secret):
            raise HTTPBadRequest(reason='BAD client secret')

        # If its ok create a service token
        token = uuid.uuid4().hex

        # We store the service_token
        ttl = request.app['settings']['ttl_service_token']
        db_tauths = request.app['settings']['db_tauths']
        with (await db_tauths) as redis:
            await redis.set(token, str(client_id))
            await redis.expire(token, ttl)

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
        scopes = params.get('scopes', None)
        if scopes and not isinstance(scopes, list):
            scopes = scopes.split(',')
        scopes = json_body.get('scopes', scopes)

        if scopes is None:
            raise HTTPBadRequest(reason='scopes is missing')

        code = params.get('code', None)
        code = json_body.get('code', code)
        if code is None:
            raise HTTPBadRequest(reason='code is missing')

        db_cauths = request.app['settings']['db_cauths']

        with (await db_cauths) as redis:
            for scope in scopes:
                db_client_id = await redis.get(code + '::' + scope)

                if db_client_id is None:
                    raise HTTPBadRequest(reason='Invalid Auth code')

                if db_client_id != bytes(client_id, encoding='utf-8'):
                    raise HTTPBadRequest(reason='Invalid Client ID')
                await redis.delete(code + '::' + scope)

        username = params.get('username', None)
        username = json_body.get('username', username)

        if username is None:
            raise HTTPBadRequest(reason='username is missing')

        password = params.get('password', None)
        password = json_body.get('password', password)

        if password is None:
            raise HTTPBadRequest(reason='Password is missing')

        # Validate user
        user_manager = request.app['settings']['user_manager']
        result = await user_manager.loginUser(username, password)

        if not result:
            raise HTTPUnauthorized(reason='Password/Username is not valid')

        if type(result['mail']) is list and len(result['mail']):
            login = result['mail'][0]
        else:
            login = result['mail']
        userName = ' '.join(result['cn'])

        # Generate token
        token = uuid.uuid4().hex
        ttl = request.app['settings']['ttl_auth']

        db_token = request.app['settings']['db_token']

        with (await db_token) as redis:
            await redis.set(token, username)
            await redis.expire(token, ttl)

            # Notify auth
            await redis.publish_json('auth', {
                'username': username,
                'status': True,
                'domain': get_domain(request),
                'agent': request.headers.get('User-Agent', 'Unknown'),
                'ip': request.transport.get_extra_info('peername')[0],
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

    # origin = request.headers.get('Origin', None)

    # if origin and origin in plone.oauth.CORS:
    #     response.headers['Access-Control-Allow-Origin'] = origin
    # elif origin:
    #     return HTTPUnauthorized(reason="Wrong Origin " + origin)

    return response

# async def set_password_options(request):
#     return preflight(request)

async def set_password(request):
    """Set password.

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
        json_body = await request.json()
    except:
        json_body = {}

    # db_tauths = request.app['settings']['db_tauths']

    params = await request.post()
    client_id = params.get('client_id', None)
    client_id = json_body.get('client_id', client_id)
    if client_id is None:
        raise HTTPBadRequest(reason='client_id is missing')

    token = params.get('token', None)
    token = json_body.get('token', token)
    if token is None:
        raise HTTPBadRequest(reason='token is missing')

    db_token = request.app['settings']['db_token']

    with (await db_token) as redis:
        user = await redis.get(token)

    if user is None:
        raise HTTPBadRequest(reason='user invalid')

    user = user.decode('utf-8')

    password = params.get('password', None)
    password = json_body.get('password', password)
    if password is None:
        raise HTTPBadRequest(reason='password invalid')

    valid_password = request.app['settings']['valid_password']
    password_policy = request.app['settings']['password_policy']
    if not valid_password(password):
        password_policy = password_policy()
        raise HTTPBadRequest(
            reason='Password not valid: {}'.format(password_policy))

    config = request.app['settings']['db_config']

    if not config.hasClient(client_id):
        # S'hauria de reenviar a authentificacio de l'usuari per acceptar-ho
        log.error('Not valid client_id ' + client_id)
        return HTTPUnauthorized(reason="Wrong client id")

    secret = request.app['settings']['jwtsecret']
    debug = request.app['settings']['debug']
    ttl = request.app['settings']['ttl_auth']

    # We can change the password
    user_manager = request.app['settings']['user_manager']
    try:
        result = await user_manager.setPassword(user, password)
    except:
        raise HTTPBadRequest(
            reason='Password not valid: {}'.format(password_policy()))

    if not result:
        raise HTTPBadRequest(reason='Failed policy LDAP')

    # Generate token
    newtoken = uuid.uuid4().hex
    ttl = request.app['settings']['ttl_auth']

    db_token = request.app['settings']['db_token']

    userName = await user_manager.getUserName(user)

    with (await db_token) as redis:
        await redis.delete(token, user)
        await redis.set(newtoken, user)
        await redis.expire(newtoken, ttl)

        # Notify auth
        await redis.publish_json('password', {
            'username': user,
            'status': True,
            'domain': get_domain(request),
            'agent': request.headers.get('User-Agent', 'Unknown'),
            'ip': request.transport.get_extra_info('peername')[0],
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

    # origin = request.headers.get('Origin', None)

    # if origin and origin in plone.oauth.CORS:
    #     response.headers['Access-Control-Allow-Origin'] = origin
    # elif origin:
    #     return HTTPUnauthorized(reason="Wrong Origin " + origin)

    return response


# async def refresh_token_options(request):
#     return preflight(request)


async def refresh_token(request):
    """Refresh token.

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
        json_body = await request.json()
    except:
        json_body = {}

    # access_token = params.get('code', None)
    # access_token = json_body.get('code', access_token)
    # if access_token is None:
    #     raise HTTPBadRequest(reason='code is missing')

    # db_tauths = request.app['settings']['db_tauths']
    params = await request.post()
    client_id = params.get('client_id', None)
    client_id = json_body.get('client_id', client_id)
    if client_id is None:
        raise HTTPBadRequest(reason='client_id is missing')

    token = params.get('token', None)
    token = json_body.get('token', token)
    if token is None:
        raise HTTPBadRequest(reason='token is missing')

    request_user = params.get('user', None)
    request_user = json_body.get('user', request_user)
    if request_user is None:
        raise HTTPBadRequest(reason='user is missing')

    # with (yield from db_tauths) as redis:
    #     db_client_id = yield from redis.get(access_token)

    # try:
    #     post_splited = db_client_id.split(b'::')
    # except:
    #     raise HTTPBadRequest(reason='Bad scope stored for the client')
    # try:
    #     real_db_client_id = post_splited[0].decode()
    # except:
    #     raise HTTPBadRequest(reason='Bad client_id stored for the client')
    # try:
    #     int_client_id = client_id
    # except:
    #     raise HTTPBadRequest(reason='bad client_id')

    # if real_db_client_id is None or real_db_client_id != int_client_id:
    #     raise HTTPBadRequest(reason='Invalid Auth code')

    db_token = request.app['settings']['db_token']

    with (await db_token) as redis:
        user = await redis.get(token)

    if user is None:
        raise HTTPBadRequest(reason='user invalid')

    user = user.decode('utf-8')

    if user != request_user:
        raise HTTPBadRequest(reason='valid user mismatch')

    config = request.app['settings']['db_config']

    if not config.hasClient(client_id):
        # S'hauria de reenviar a authentificacio de l'usuari per acceptar-ho
        log.error('Not valid client_id ' + client_id)
        return HTTPUnauthorized(reason="Wrong client id")

    secret = request.app['settings']['jwtsecret']
    debug = request.app['settings']['debug']
    ttl = request.app['settings']['ttl_auth']

    # Generate token
    newtoken = uuid.uuid4().hex
    ttl = request.app['settings']['ttl_auth']

    user_manager = request.app['settings']['user_manager']

    userName = await user_manager.getUserName(user)

    db_token = request.app['settings']['db_token']

    with (await db_token) as redis:
        await redis.delete(token, user)
        await redis.set(newtoken, user)
        await redis.expire(newtoken, ttl)

        # Notify auth
        await redis.publish_json('refresh', {
            'username': user,
            'status': True,
            'domain': get_domain(request),
            'agent': request.headers.get('User-Agent', 'Unknown'),
            'ip': request.transport.get_extra_info('peername')[0],
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

    # origin = request.headers.get('Origin', None)

    # if origin and origin in plone.oauth.CORS:
    #     response.headers['Access-Control-Allow-Origin'] = origin
    # elif origin:
    #     return HTTPUnauthorized(reason="Wrong Origin " + origin)

    return response
