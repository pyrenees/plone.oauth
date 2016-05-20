from datetime import datetime
from datetime import timedelta
import jwt


def jwt_response(request, result, name='result'):
    """Return a JWT encode response"""
    # Check if the user is administrator for the scope so can get the info
    secret = request.registry.settings['jwtsecret']
    ttl = request.registry.settings['ttl_user_info']
    token = jwt.encode(
        {
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=ttl),
            name: result
        },
        secret,
        algorithm='HS256')

    return token