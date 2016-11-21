import asyncio
from aiohttp.web import HTTPBadRequest
import ujson

import plone.oauth


def check_superuser(username):
    if plone.oauth.is_superuser(username):
        return True
    raise HTTPBadRequest(reason='NOT VALID token: must be superuser')


async def check_manager(username, scope, request):
    """Check user is superuser or manager in scope"""
    # Check superuser
    if plone.oauth.is_superuser(username):
        return True

    # Or check manager in scope
    ttl = request.app['settings']['ttl_user_info']
    db_token = request.app['settings']['db_token']
    user_scope = '{0}::{1}'.format(username, scope)
    # Search Redis
    with (await db_token) as redis:
        result = await redis.get(user_scope)

    if result is not None:
        result = ujson.loads(result)
    else:
        # Search LDAP
        user_manager = request.app['settings']['user_manager']
        result = await user_manager.getUserInfo(username, scope)
        # Cache in redis
        with (await db_token) as redis:
            await redis.set(user_scope, ujson.dumps(result))
            await redis.expire(user_scope, ttl)

    roles = result.get('roles', {})
    # XXX: TODO not hardcoded
    if 'manager' in roles or 'site administrator' in roles:
        return True

    # Is not a manager
    raise HTTPBadRequest(reason='NOT VALID token: must be manager')


async def get_validate_request(request):
    """Return data from `request`:

    - scope
    - username

    Validate:

    - service_token
    - scope
    - user_token

    :return: dict [scope, username]

    """
    params = await request.post()
    service_token = params.get('service_token', None)
    if service_token is None:
        raise HTTPBadRequest(reason='service_token is missing')

    db_tauths = request.app['settings']['db_tauths']

    with (await db_tauths) as redis:
        client_id = await redis.get(service_token)

    if client_id is None:
        raise HTTPBadRequest(reason='Invalid service_token')

    scope = params.get('scope', None)
    if scope is None:
        raise HTTPBadRequest(reason='scope is missing')

    user_token = params.get('user_token', None)
    if user_token is None:
        raise HTTPBadRequest(reason='user_token is missing')

    # We need the user info so we are going to get it from UserManager
    db_token = request.app['settings']['db_token']
    with (await db_token) as redis:
        username = await redis.get(user_token)

    if username is None:
        raise HTTPBadRequest(reason='bad token')
    username = username.decode("utf-8")

    return {
        'scope': scope,
        'username': username,
    }


def get_domain(request):
    domain = request.headers['Host']
    if ':' in domain:
        domain = domain.split(':', 1)[0]
    return domain


def payload(payload):
    async def async_payload():
        return payload
    return async_payload
