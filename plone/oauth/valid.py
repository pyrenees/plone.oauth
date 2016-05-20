from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.httpexceptions import HTTPNotImplemented
from pyramid.httpexceptions import HTTPFound
import asyncio
from pyramid.view import view_config
import uuid
import logging
import jwt
import ujson
from datetime import datetime, timedelta
from pyramid.response import Response
from ldap3 import Server, Connection, SUBTREE, ASYNC, SIMPLE, ANONYMOUS, SASL


log = logging.getLogger(__name__)

@view_config(route_name='valid_token',
             request_method='POST',
             http_cache=0)
@asyncio.coroutine
def valid_token(request):
    """
    Validate token!

    Request: POST /valid_token
        Body :
            - code
            - token

    Response HTTP 200 in JWT token:
        {
            'user': 'user'
        }

    """

    access_token = request.params.get('code', None)
    if access_token is None:
        raise HTTPBadRequest('code is missing')

    db_tauths = request.registry.settings['db_tauths']

    with (yield from db_tauths) as redis:
        client_id = yield from redis.get(access_token)

    if client_id is None:
        raise HTTPBadRequest('Invalid Auth code')

    token = request.params.get('token', None)
    if token is None:
        raise HTTPBadRequest('token is missing')

    db_token = request.registry.settings['db_token']

    with (yield from db_token) as redis:
        user = yield from redis.get(token)

    if user is None:
        raise HTTPBadRequest('user invalid')

    secret = request.registry.settings['jwtsecret']

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
