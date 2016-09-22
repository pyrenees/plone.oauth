import asyncio
from pyramid.httpexceptions import HTTPBadRequest
import ujson

import plone.oauth


def check_superuser(username):
    if plone.oauth.is_superuser(username):
        return True
    raise HTTPBadRequest('NOT VALID token: must be superuser')


@asyncio.coroutine
def check_manager(username, scope, request):
    """Check user is superuser or manager in scope"""
    # Check superuser
    if plone.oauth.is_superuser(username):
        return True

    # Or check manager in scope
    ttl = request.registry.settings['ttl_user_info']
    db_token = request.registry.settings['db_token']
    user_scope = '{0}::{1}'.format(username, scope)
    # Search Redis
    with (yield from db_token) as redis:
        result = yield from redis.get(user_scope)

    if result is not None:
        result = ujson.loads(result)
    else:
        # Search LDAP
        user_manager = request.registry.settings['user_manager']
        result = yield from user_manager.getUserInfo(username, scope)
        # Cache in redis
        with (yield from db_token) as redis:
            yield from redis.set(user_scope, ujson.dumps(result))
            yield from redis.expire(user_scope, ttl)

    roles = result.get('roles', {})
    # XXX: TODO not hardcoded
    if 'manager' in roles or 'site administrator' in roles:
        return True

    # Is not a manager
    raise HTTPBadRequest('NOT VALID token: must be manager')


@asyncio.coroutine
def get_validate_request(request):
    """Return data from `request`:

    - scope
    - username

    Validate:

    - service_token
    - scope
    - user_token

    :return: dict [scope, username]

    """
    service_token = request.params.get('service_token', None)
    if service_token is None:
        raise HTTPBadRequest('service_token is missing')

    db_tauths = request.registry.settings['db_tauths']

    with (yield from db_tauths) as redis:
        client_id = yield from redis.get(service_token)

    if client_id is None:
        raise HTTPBadRequest('Invalid service_token')

    scope = request.params.get('scope', None)
    if scope is None:
        raise HTTPBadRequest('scope is missing')

    user_token = request.params.get('user_token', None)
    if user_token is None:
        raise HTTPBadRequest('user_token is missing')

    # We need the user info so we are going to get it from UserManager
    db_token = request.registry.settings['db_token']
    with (yield from db_token) as redis:
        username = yield from redis.get(user_token)

    if username is None:
        raise HTTPBadRequest('bad token')
    username = username.decode("utf-8")

    return {
        'scope': scope,
        'username': username,
    }

