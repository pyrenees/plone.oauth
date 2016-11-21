import asyncio
import uuid
import logging
import jwt
import ujson
from datetime import datetime, timedelta

from aiohttp.web import Response
from aiohttp.web import HTTPBadRequest
from ldap3 import Server, Connection, SUBTREE, ASYNC, SIMPLE, ANONYMOUS, SASL


log = logging.getLogger(__name__)


async def search_user(request):
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
    params = await request.post()
    access_token = params.get('code', None)
    if access_token is None:
        raise HTTPBadRequest(reason='code is missing')

    db_tauths = request.app['settings']['db_tauths']

    with (await db_tauths) as redis:
        client_id = await redis.get(access_token)

    if client_id is None:
        raise HTTPBadRequest(reason='Invalid Auth code')

    scope = params.get('scope', None)
    if scope is None:
        raise HTTPBadRequest(reason='scope is missing')

    criteria = params.get('criteria', None)
    if criteria is None:
        raise HTTPBadRequest(reason='criteria is missing')
    else:
        criteria = ujson.loads(criteria)

    exact_match = params.get('exact_match', None)
    if exact_match is None:
        exact_match = False
    else:
        exact_match = True


    attrs = ujson.loads(params.get('attrs', '[]'))

    page = params.get('page', '0')
    try:
        page = int(page)
    except ValueError:
        page = 0

    num_x_page = params.get('num_x_page', '20')
    try:
        num_x_page = int(num_x_page)
    except ValueError:
        num_x_page = 0

    ttl = request.app['settings']['ttl_search']
    secret = request.app['settings']['jwtsecret']

    user_manager = request.app['settings']['user_manager']
    result = await user_manager.searchUser(
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
