from aiohttp.web import HTTPBadRequest, HTTPFound, HTTPUnauthorized, HTTPNotImplemented, Response
import asyncio
import uuid
import logging
import jwt
import ujson
from datetime import datetime, timedelta
from ldap3 import Server, Connection, SUBTREE, ASYNC, SIMPLE, ANONYMOUS, SASL


log = logging.getLogger(__name__)


async def valid_token(request):
    """
    Validate token!

    Request: POST /valid_token
        Body :
            - service_code
            - token

    Response HTTP 200 in JWT token:
        {
            'user': 'user'
        }

    """
    params = await request.post()
    service_token = params.get('code', None)
    if service_token is None:
        raise HTTPBadRequest(reason='code is missing')

    db_tauths = request.app['settings']['db_tauths']
    with (await db_tauths) as redis:
        client_id = await redis.get(service_token)

    if client_id is None:
        raise HTTPBadRequest(reason='Invalid Service Token')

    token = params.get('token', None)
    if token is None:
        raise HTTPBadRequest(reason='token is missing')

    db_token = request.app['settings']['db_token']

    with (await db_token) as redis:
        user = await redis.get(token)

    if user is None:
        raise HTTPBadRequest(reason='user invalid')

    secret = request.app['settings']['jwtsecret']

    # if its ok redirect to get_access_token
    token = jwt.encode(
        {
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=60),
            'user': user.decode('utf-8')
        },
        secret,
        algorithm='HS256')

    return Response(body=token, content_type='text/plain')
