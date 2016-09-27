# -*- encoding: utf-8 -*-
"""Config oauth.

VARS:

REDIS_HOST = 'redis'
REDIS_PORT = 6379
JWT_SECRET = 'secret'
LDAP = 'ldap:10389'
ROOT_PW = 'secret'
ROOT_DN = 'uid=admin,ou=system'
DOMAIN = 'dc=example,dc=com'
USERFILTER = 'mail={username},ou=users,dc=example,dc=com'
MANAGER = 'admin@tickdi.com'

CORS = 'http://localhost:4200,https://example.com'
DEBUG = True
SMTP_SERVER = '---''
SMTP_PORT = 587
SMTP_USER = '---'
SMTP_PW = '---'
SMTP_TLS = True
SMTP_SSL = False

"""

import os
import configparser

REDISHOST = os.environ.get('REDIS_HOST', 'serviceredis')
REDISPORT = int(os.environ.get('REDIS_PORT', 6379))
JWTSECRET = os.environ.get('JWT_SECRET', 'secret')
LDAP = os.environ.get('LDAP', 'ldap:10389')
ROOTPW = os.environ.get('ROOT_PW', 'secret')
ROOTDN = os.environ.get('ROOT_DN', 'uid=admin,ou=system')
DOMAIN = os.environ.get('DOMAIN', 'dc=example,dc=com')
USERFILTER = os.environ.get(
    'USER_FILTER', 'mail={username},ou=users,dc=example,dc=com')
MANAGER = os.environ.get('MANAGER', 'admin@example.com')
CORS = os.environ.get('CORS', 'http://localhost:4200,https://example.com')
DEBUG = os.environ.get('DEBUG', True)
SMTPSERVER = os.environ.get(
    'SMTP_SERVER', 'smtp.gmail.com')
SMTPPORT = int(os.environ.get('SMTP_PORT', 587))
SMTPUSER = os.environ.get('SMTP_USER', '---')
SMTPPW = os.environ.get(
    'SMTP_PW', '---')
SMTPTLS = bool(os.environ.get('SMTP_TLS', 'True').upper() == 'TRUE')
SMTPSSL = bool(os.environ.get('SMTP_SSL', 'False').upper() == 'FALSE')


config = configparser.ConfigParser()
config.read("production.ini")

config['app:main']['jwtsecret'] = JWTSECRET
config['app:main']['redis.host'] = REDISHOST
config['app:main']['redis.port'] = str(REDISPORT)
config['app:main']['ldap.server'] = LDAP
config['app:main']['ldap.config_server'] = LDAP
config['app:main']['ldap.config_root_pw'] = ROOTPW
config['app:main']['ldap.root_pw'] = ROOTPW

config['app:main']['ldap.root_dn'] = ROOTDN
config['app:main']['ldap.config_root_dn'] = ROOTDN

config['app:main']['ldap.user_filter'] = USERFILTER
config['app:main']['ldap.base_dn'] = DOMAIN
config['app:main']['ldap.config_dn'] = 'ou=config,%s' % DOMAIN

config['app:main']['manager'] = MANAGER

config['app:main']['cors'] = CORS
config['app:main']['debug'] = 'True' if DEBUG else 'False'

config['app:main']['mail.host'] = SMTPSERVER
config['app:main']['mail.port'] = str(SMTPPORT)
config['app:main']['mail.username'] = SMTPUSER
config['app:main']['mail.password'] = SMTPPW
config['app:main']['mail.tls'] = 'True' if SMTPTLS else 'False'
config['app:main']['mail.ssl'] = 'True' if SMTPSSL else 'False'

with open('production.ini', 'w') as configfile:
    config.write(configfile)
