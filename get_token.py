#!/usr/bin/python
import sys
import requests
import jwt
import time

NON_IAT_VERIFY = {
    'verify_iat': False,
}


def main():
    payload = {'response_type': 'code', 'client_id': 'plone', 'scope': 'plone'}
    r = requests.get(sys.argv[1] + '/get_authorization_code', params=payload)
    access_token = r.text
    access_token = jwt.decode(
        access_token,
        'secret',
        algorithms=['HS256'],
        options=NON_IAT_VERIFY)['auth_code']
    print("ACCESS TOKEN " + access_token)

    payload = {
        'grant_type': 'authorization_code',
        'client_id': 'plone',
        'client_secret': 'secret',
        'code': access_token,
        'scope': 'plone'}
    r = requests.post(sys.argv[1] + '/get_auth_token', params=payload)
    service_token = r.text
    service_token = jwt.decode(
        service_token,
        'secret',
        algorithms=['HS256'],
        options=NON_IAT_VERIFY)['access_token']
    print("SERVICE TOKEN " + service_token)

    payload = {
        'grant_type': 'password',
        'username': 'user@example.com',
        'password': 'user',
        'client_id': 'plone',
        'code': service_token,
        'scope': 'plone'}
    r = requests.post(sys.argv[1] + '/get_auth_token', params=payload)
    raw_token = r.text
    user_token = jwt.decode(
        r.text,
        'secret',
        algorithms=['HS256'],
        options=NON_IAT_VERIFY)

    print("EDITOR USER : user@example.com " + user_token['token'])
    print("RAW " + raw_token)
    expiration_date = time.gmtime(user_token['exp'])
    print("  valid until : " +
          time.strftime('%Y-%m-%dT%H:%M:%SZ', expiration_date))

    payload = {
        'grant_type': 'password',
        'username': 'admin@example.com',
        'password': 'admin',
        'client_id': 'plone',
        'code': service_token,
        'scope': 'plone'}
    r = requests.post(sys.argv[1] + '/get_auth_token', params=payload)
    raw_token = r.text
    user_token = jwt.decode(
        r.text,
        'secret',
        algorithms=['HS256'],
        options=NON_IAT_VERIFY)
    print("MANAGER USER : admin@example.com " + user_token['token'])
    print("RAW " + raw_token)
    expiration_date = time.gmtime(user_token['exp'])
    print("  valid until : " +
          time.strftime('%Y-%m-%dT%H:%M:%SZ', expiration_date))

if __name__ == "__main__":
    main()
