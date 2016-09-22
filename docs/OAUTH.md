# Server side

## Get Service Token:

 * Server side sends client_id/client_secret and gets a service_token

    POST http://OAUTH/get_auth_token
        {
            'grant_type': 'service',
            'client_id': 'SERVER_CLIENT_ID',
            'client_secret': 'SERVER_CLIENT_SECRET'
        }

## Validate Token:

 * Server sends service_token with user_token


# Client side without redirect URL (front can know the user/pass)

## Authenticate

 * Client sends to server to get auth_code

	GET http://SERVER/@get_auth_code?client_id=10

 * Server sends to oauth to get auth_code with the service_token

    POST http://OAUTH/get_authorization_code
        {
            response_type: 'code',
            client_id: 'WEB_CLIENT_ID',
            service_token: 'SERVICE_TOKEN_FROM_THE_SERVER',
            scopes: ['SCOPE', 'LOGIN'] 
        }

 * Client sends to oauth with username and password

    POST http://OAUTH/get_auth_token
        {
            grant_type: 'user',
            client_id: 'WEB_CLIENT_ID',
            username: 'username',
            password: 'password',
            code: 'AUTH_CODE_FROM_SERVER'
            scopes: ['LOGIN']
        }

# Client side with Server redirect URL (front can NOT know the user/pass)

## Authenticate

 * Client sends to server to get auth_code

    GET http://SERVER/@get_auth_code?client_id=10&redirect_url=http://CLIENT_URL/

 * Server sends to oauth to get auth_code with the service_token

    POST http://OAUTH/get_authorization_code
        {
            response_type: 'url',
            client_id: 'WEB_CLIENT_ID',
            service_token: 'SERVICE_TOKEN_FROM_THE_SERVER',
            redirect_url=http://CLIENT_URL/,
            scopes: ['SCOPE', 'LOGIN'] 
        }

 * Client redirect browser to url from Server that comes back to client url ?code=user_token
