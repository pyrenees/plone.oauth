import asyncio
import ujson


def key_group(group, scope):
    """
    Redis identifier for groups
    """
    return '{0}::{1}'.format(group, scope)

async def cache(request, key, value):
    """
    Cache in redis the `value` for `key`.
    Obtain redis parameters from `request`.

    :type key: str
    """
    ttl = request.app['settings']['ttl_user_info']
    db_token = request.app['settings']['db_token']

    with (await db_token) as redis:
        await redis.set(key, ujson.dumps(value))
        await redis.expire(key, ttl)

async def get(request, key):
    """
    Return the cached value in redis for `key`.
    If it is not found raise `KeyError`.

    :type key: str
    :returns: cached valued
    :raises: KeyError
    """
    db_token = request.app['settings']['db_token']

    with (await db_token) as redis:
        result = await redis.get(key)
    if result is not None:
        return ujson.loads(result)
        
    raise KeyError()