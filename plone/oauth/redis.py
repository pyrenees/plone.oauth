import asyncio
import ujson


def key_group(group, scope):
    """
    Redis identifier for groups
    """
    return '{0}::{1}'.format(group, scope)

@asyncio.coroutine
def cache(request, key, value):
    """
    Cache in redis the `value` for `key`.
    Obtain redis parameters from `request`.

    :type key: str
    """
    ttl = request.registry.settings['ttl_user_info']    
    db_token = request.registry.settings['db_token']

    with (yield from db_token) as redis:
        yield from redis.set(key, ujson.dumps(value))
        yield from redis.expire(key, ttl)

@asyncio.coroutine
def get(request, key):
    """
    Return the cached value in redis for `key`.
    If it is not found raise `KeyError`.

    :type key: str
    :returns: cached valued
    :raises: KeyError
    """
    db_token = request.registry.settings['db_token']

    with (yield from db_token) as redis:
        result = yield from redis.get(key)
    if result is not None:
        return ujson.loads(result)
        
    raise KeyError()