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
import json

REDISHOST = os.environ.get('REDIS_HOST', 'redis')
REDISPORT = int(os.environ.get('REDIS_PORT', "tcp://172.17.0.2:6379").split(":")[-1])
JWTSECRET = os.environ.get('JWT_SECRET', 'secret')
LDAP = os.environ.get('LDAP', 'ldap:10389')
ROOTPW = os.environ.get('ROOT_PW', 'secret')
ROOTDN = os.environ.get('ROOT_DN', 'uid=admin,ou=system')
DOMAIN = os.environ.get('DOMAIN', 'dc=example,dc=com')
USERFILTER = os.environ.get(
    'USER_FILTER', 'mail={username},ou=users,dc=example,dc=com')
MANAGER = os.environ.get('MANAGER', 'admin@example.com')
CORS = os.environ.get('CORS', ['http://localhost:4200','https://example.com'])
DEBUG = os.environ.get('DEBUG', True)
SMTPSERVER = os.environ.get(
    'SMTP_SERVER', 'smtp.gmail.com')
SMTPPORT = int(os.environ.get('SMTP_PORT', 587))
SMTPUSER = os.environ.get('SMTP_USER', '---')
SMTPPW = os.environ.get(
    'SMTP_PW', '---')
SMTPTLS = bool(os.environ.get('SMTP_TLS', 'True').upper() == 'TRUE')
SMTPSSL = bool(os.environ.get('SMTP_SSL', 'False').upper() == 'FALSE')

with open("config.json") as fp:
    config = json.load(fp)

config['jwtsecret'] = JWTSECRET
config['redis.host'] = REDISHOST
config['redis.port'] = str(REDISPORT)
config['ldap.server'] = LDAP
config['ldap.config_server'] = LDAP
config['ldap.config_root_pw'] = ROOTPW
config['ldap.root_pw'] = ROOTPW

config['ldap.root_dn'] = ROOTDN
config['ldap.config_root_dn'] = ROOTDN

config['ldap.user_filter'] = USERFILTER
config['ldap.base_dn'] = DOMAIN
config['ldap.config_dn'] = 'ou=config,%s' % DOMAIN

config['manager'] = MANAGER

config['cors'] = CORS
config['debug'] = 'True' if DEBUG else 'False'

config['mail.host'] = SMTPSERVER
config['mail.port'] = str(SMTPPORT)
config['mail.username'] = SMTPUSER
config['mail.password'] = SMTPPW
config['mail.tls'] = 'True' if SMTPTLS else 'False'
config['mail.ssl'] = 'True' if SMTPSSL else 'False'

with open('config.json', 'w') as configfile:
    json.dump(config, configfile, sort_keys=True, indent=4, separators=(',', ': '))
