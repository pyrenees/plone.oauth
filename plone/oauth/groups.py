import asyncio
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.response import Response
from pyramid.view import view_config

from plone.oauth import redis
from plone.oauth.utils.request import check_manager
from plone.oauth.utils.request import get_validate_request
from plone.oauth.utils.response import jwt_response


@view_config(route_name='get_group',
             request_method='POST',
             http_cache=0)
@asyncio.coroutine
def get_group(request):
    """Protected for manager

    Request: POST /get_group
        Body :
            - user_token
            - service_token
            - scope
            - group (optional)

    Response HTTP 200 in JWT token:
        {
            'name': username,
            'members': [],
        }
        or [{'name'...}, ...]

    Response HTTP 400 in JWT token:
    Group not found

    """
    # Request params
    request_data = yield from get_validate_request(request)
    scope = request_data.get('scope')
    username = request_data.get('username')
    group = request.params.get('group', None)

    # Security
    yield from check_manager(username, scope, request)  # !!important

    # Compute result
    group_scope = redis.key_group(group, scope)
    try:
        # Search Cache Redis
        result = yield from redis.get(request, group_scope)
    except KeyError:
        # Search LDAP
        user_manager = request.registry.settings['user_manager']
        result = yield from user_manager.getGroupInfo(scope=scope, group=group)
        # Cache in redis
        yield from redis.cache(request, group_scope, result)

    # Response
    if result is None:
        token =  jwt_response(request, 'Group not found')
        return Response(status_code=400, body=token, content_type='text/plain')

    token = jwt_response(request, result)
    return Response(body=token, content_type='text/plain')


@view_config(route_name='add_group',
             request_method='POST',
             http_cache=0)
@asyncio.coroutine
def add_group(request):
    """Request: POST /add_group

        Body :
            - user_token
            - service_token (json)
            - scope
            - group

    Response HTTP 200 in JWT token:
        success

    Response HTTP 400 in JWT token:
        entryAlreadyExists

    """
    # Request params
    request_data = yield from get_validate_request(request)
    scope = request_data.get('scope')
    username = request_data.get('username')
    group = request.params.get('group', None)

    if group is None:
        raise HTTPBadRequest('group is missing')

    # Security
    yield from check_manager(username, scope, request)  # !!important

    # Add LDAP
    user_manager = request.registry.settings['user_manager']
    result = yield from user_manager.addGroup(scope, group)

    status = 500
    if result == 'success':
        status = 200
    elif result == 'entryAlreadyExists':
        status = 400

    token = jwt_response(request, result)
    return Response(status_code=status, body=token, content_type='text/plain')

