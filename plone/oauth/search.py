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

@view_config(route_name='search_user',
             request_method='POST',
             http_cache=0)
@asyncio.coroutine
def search_user(request):
    """
    Its superadmin, take care!

    Request: POST /search_user
        Body :
            - code
            - criteria (json)
            - exact_match
            - attrs
            - scope
            - page (op)
            - num_x_page (op)

    Response HTTP 200 in JWT token:
        {
            'total': 0,
            'page': 0,
            'num_x_page': 20,
            'result':
                {
                    'login': '',
                    'attr1': '',
                    'attr2': ''
                }
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

    scope = request.params.get('scope', None)
    if scope is None:
        raise HTTPBadRequest('scope is missing')

    criteria = request.params.get('criteria', None)
    if criteria is None:
        raise HTTPBadRequest('criteria is missing')
    else:
        criteria = ujson.loads(criteria)

    exact_match = request.params.get('exact_match', None)
    if exact_match is None:
        exact_match = False
    else:
        exact_match = True


    attrs = ujson.loads(request.params.get('attrs', '[]'))

    page = request.params.get('page', '0')
    try:
        page = int(page)
    except ValueError:
        page = 0

    num_x_page = request.params.get('num_x_page', '20')
    try:
        num_x_page = int(num_x_page)
    except ValueError:
        num_x_page = 0

    ttl = request.registry.settings['ttl_search']
    secret = request.registry.settings['jwtsecret']

    user_manager = request.registry.settings['user_manager']
    result = yield from user_manager.searchUser(
        scope,
        criteria,
        exact_match,
        attrs,
        page=page,
        num_x_page=num_x_page)

    result, total = result
    # if its ok redirect to get_access_token
    token = jwt.encode(
        {
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=ttl),
            'total': total,
            'page': page,
            'num_x_page': num_x_page,
            'result': result
        },
        secret,
        algorithm='HS256')

    return Response(body=token, content_type='text/plain')
