import asyncio

from aiohttp.web_exceptions import HTTPBadRequest
from ldap3 import Connection
import jwt
import logging
import pytest
from unittest.mock import MagicMock, Mock

from plone.oauth import main
from plone.oauth import redis
from plone.oauth.endpoints import get_authorization_code, get_token
from plone.oauth.utils.request import payload

SUPERUSER_HARDCODED = 'admin@example.com'


class TestUtils:

    def call_horus(self, caller):
        """
        Call horus route `caller` and return the response with the decoded body.
        """
        dummy = self.app._replace(post=payload(self.params), get=payload(self.params),headers=self.headers)
        resp = asyncio.get_event_loop().run_until_complete(caller(dummy))
        secret = self.app.app['settings']['jwtsecret']
        decoded = jwt.decode(resp.body, secret)  # insert decoded body
        return resp, decoded

    def set_app_superuser(self):
        """
        Set request params for a superuser call
        """
        self.params = {}
        self.params['service_token'] = self.service_token
        self.params['scope'] = self.scope
        self.params['user_token'] = self.superuser_token

    def set_app_user(self):
        """
        Set request params for a user call
        """
        self.params = {}
        self.params['service_token'] = self.service_token
        self.params['scope'] = self.scope
        self.params['user_token'] = self.user_token
        self.params['user'] = self.user_id

    def set_app_manager(self):
        """
        Set request params for a user call
        """
        self.params = {}
        self.params['service_token'] = self.service_token
        self.params['scope'] = self.scope
        self.params['user_token'] = self.manager_token
        self.params['user'] = self.manager_id


class TestUtilsSecurity:

    def security_check_base_params(self, view):
        """
        Check that base request parameters are checked in `view`
        """
        #  No service token
        self.set_app_user()
        self.params['service_token'] = None
        with pytest.raises(HTTPBadRequest) as excinfo:
            self.call_horus(view)
        assert str(excinfo.value) == 'service_token is missing'

        #  Invalid service token
        self.set_app_user()
        self.params['service_token'] = 'invented'
        with pytest.raises(HTTPBadRequest) as excinfo:
            self.call_horus(view)
        assert str(excinfo.value) == 'Invalid service_token'

        #  No scope
        self.set_app_user()
        self.params['scope'] = None
        with pytest.raises(HTTPBadRequest) as excinfo:
            self.call_horus(view)
        assert str(excinfo.value) == 'scope is missing'

        #  No user token
        self.set_app_user()
        self.params['user_token'] = None
        with pytest.raises(HTTPBadRequest) as excinfo:
            self.call_horus(view)
        assert str(excinfo.value) == 'user_token is missing'

        #  Invalid token
        self.set_app_user()
        self.params['user_token'] = 'invented'
        with pytest.raises(HTTPBadRequest) as excinfo:
            self.call_horus(view)
        assert str(excinfo.value) == 'bad token'


class BaseHorusTest(TestUtils, TestUtilsSecurity):
    """
    Create base data:

    * config

    * scopes

      * plonetest

        * groups

          * group1 (user@example.com, group3)
          * group2 (user@example.com, superuser@plone.com)
          * group3 (user3)

        * roles

          * site administrator (manager@example.com)
          * reader (group1)

    * users

      * admin@example.com
      * manager@example.com
      * user@example.com
      * user3@example.com


    and set basic tokens:

    * auth_code
    * service_token
    * superuser_token
    * manager_token
    * user_token

    """
    DISABLE_CACHE_REDIS = True

    base_dn = 'dc=example,dc=com'
    client_id = '111'
    client_secret = '123456test'
    scope = 'plonetest'
    superuser_id = SUPERUSER_HARDCODED
    superuser_pwd = '123456test'

    manager_id = 'manager@example.com'
    manager_pwd = '123456test'
    user_id = 'user@example.com'
    user_pwd = '123456test'
    user3_id = 'user3@example.com'
    user3_pwd = '123456test'
    group_id = 'group1'
    group2_id = 'group2'
    group3_id = 'group3'

    def _recursively_delete(self, entry):
        self.conn.search(entry, '(objectclass=top)', 'LEVEL')

        for subentry in self.conn.entries:
            self._recursively_delete(subentry.entry_get_dn())

        self.conn.delete(entry)

    def set_teardown(self):
        self._recursively_delete('ou=scopes,'+self.base_dn)
        self._recursively_delete('ou=users,'+self.base_dn)
        self._recursively_delete('ou=config,'+self.base_dn)
        # close connections
        self.conn.unbind()
        self.ldap.unbind()
        # pending tasks from redis??
        tasks = asyncio.Task.all_tasks()
        for task in tasks:
            task.cancel()
        # unmock
        if self.DISABLE_CACHE_REDIS:
            redis.cache = self.original_redis_cache
            redis.get = self.original_redis_get
        # fix bug too many open files
        # pu = psutil.Process(os.getpid())
        # open_files = pu.open_files()
        # for of in open_files:
        #     os.close(of.fd)

    @pytest.fixture(autouse=True)
    def set_init(self, app, request):

        asyncio.get_event_loop().set_debug(True)
        logging.basicConfig(level=logging.DEBUG)

        ldap_server = app.app['settings']['ldap.server']
        conn = Connection(ldap_server, auto_bind=True)
        self.conn = conn

        # test entry is empty
        conn.search(self.base_dn,'(objectclass=top)')
        assert len(conn.entries) == 1, 'Refusing test: ldap entry is not empty'

        # set app testing
        settings = app.app['settings'].copy()
        config_dn = 'ou=config,' + self.base_dn
        userFilter = 'mail={username},ou=users,' + self.base_dn
        settings['ldap.base_dn'] = self.base_dn
        settings['ldap.config_dn'] = config_dn
        settings['ldap.user_filter'] = userFilter
        settings['valid_password'] = 'plone.oauth.password.valid_password'
        settings['password_policy'] = 'plone.oauth.password.password_policy'
        new_app = main(settings)
        self.app = app
        self.params = {}
        self.headers = {}
        self.app.app['settings'] = new_app['settings']

        # mock redis
        if self.DISABLE_CACHE_REDIS:

            async def coroutine_wrap(any):
                if callable(any):
                    return any()
                else:
                    return any

            self.original_redis_cache = redis.cache
            self.original_redis_get = redis.get
            self.mock_redis_cache = MagicMock()
            self.mock_redis_cache.return_value = coroutine_wrap(iter([None]))
            self.mock_redis_get = MagicMock(side_effect=KeyError)
            redis.cache = self.mock_redis_cache
            redis.get = self.mock_redis_get

        # pre add
        conn.add('ou=scopes,'+self.base_dn, 'organizationalUnit')
        conn.add('ou=users,'+self.base_dn, 'organizationalUnit')
        conn.add('ou=config,'+self.base_dn, 'organizationalUnit')
        conn.add('ou=clients,ou=config,'+self.base_dn, 'organizationalUnit')

        # post delete
        if request is not None:
            request.addfinalizer(self.set_teardown)

        # load data
        self.ldap = self.app.app['settings']['user_manager']

        self.create_scope()
        self.create_client()
        self.create_superuser()
        # load extra data
        self.create_manager()
        self.create_user()
        self.create_group()

    @property
    def cauth_code(self):
        self.params['response_type'] = 'code'
        self.params['client_id'] = self.client_id
        self.params['service_token'] = self.service_token
        self.params['scopes'] = [self.scope]
        r, decoded = self.call_horus(get_authorization_code)
        assert r.status == 200
        return decoded['auth_code']

    def create_superuser(self):
        self.conn.add(
            self.ldap.user_filter.format(username=self.superuser_id),
            ['person', 'inetOrgPerson'],
            {
                'cn': self.superuser_id,
                'sn': 'admin',
                'mail': self.superuser_id,
                'userPassword': self.superuser_pwd
            }
            )

        # We get the working token for the superuser
        self.params['grant_type'] = 'user'
        self.params['code'] = self.cauth_code
        self.params['client_id'] = self.client_id
        self.params['username'] = self.superuser_id
        self.params['password'] = self.superuser_pwd
        self.params['scopes'] = [self.scope]
        self.headers = {'User-Agent': 'DUMMY', 'Host': '127.0.0.1:8080'}
        r, decoded = self.call_horus(get_token)
        assert r.status == 200
        self.superuser_token = decoded['token']

    def create_scope(self):
        self.conn.add(
            self.ldap.scope_filter(self.scope),
            'organizationalUnit',
            )
        self.conn.add(
            self.ldap.groups_filter(self.scope),
            'organizationalUnit',
            )
        self.conn.add(
            self.ldap.roles_filter(self.scope),
            'organizationalUnit',
            )

    def create_client(self):
        client_dn = 'cn={0},ou=clients,ou=config,'+self.base_dn
        self.conn.add(
            client_dn.format(self.client_id),
            'person',
            {
            'cn': self.client_id,
            'sn': 'Plone',
            'userPassword': self.client_secret
            }
            )

        # We get the working token for the client app
        self.params['grant_type'] = 'service'
        self.params['client_id'] = self.client_id
        self.params['client_secret'] = self.client_secret
        r, decoded = self.call_horus(get_token)
        assert r.status == 200
        self.service_token = decoded['service_token']

    def create_manager(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.ldap.addUser(
            self.manager_id, self.manager_pwd))
        loop.run_until_complete(
            self.ldap.addScopeRoleUser(
                self.scope,
                self.manager_id,
                'site administrator'
                )
            )

        # We get the working token for the manager
        self.params['grant_type'] = 'user'
        self.params['code'] = self.cauth_code
        self.params['client_id'] = self.client_id
        self.params['username'] = self.manager_id
        self.params['password'] = self.manager_pwd
        self.params['scopes'] = [self.scope]
        self.headers = {'User-Agent': 'DUMMY', 'Host': '127.0.0.1:8080'}
        r, decoded = self.call_horus(get_token)
        assert r.status == 200
        self.manager_token = decoded['token']

    def create_user(self):
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(self.ldap.addUser(self.user_id, self.user_pwd))

        # We get the working token for the user
        self.params['grant_type'] = 'user'
        self.params['code'] = self.cauth_code
        self.params['client_id'] = self.client_id
        self.params['username'] = self.user_id
        self.params['password'] = self.user_pwd
        self.params['scopes'] = [self.scope]
        self.headers = {'User-Agent': 'DUMMY', 'Host': '127.0.0.1:8080'}
        r, decoded = self.call_horus(get_token)
        assert r.status == 200
        self.user_token = decoded['token']

        #user3
        result = loop.run_until_complete(self.ldap.addUser(self.user3_id, self.user3_pwd))

        # We get the working token for the user
        self.params['grant_type'] = 'user'
        self.params['code'] = self.cauth_code
        self.params['username'] = self.user3_id
        self.params['password'] = self.user3_pwd
        self.params['scopes'] = [self.scope]
        self.headers = {'User-Agent': 'DUMMY', 'Host': '127.0.0.1:8080'}

        r, decoded = self.call_horus(get_token)
        assert r.status == 200
        self.user3_token = decoded['token']

    def create_group(self):
        loop = asyncio.get_event_loop()
        ldap = self.app.app['settings']['user_manager']
        group_dn = ldap.group_filter(scope=self.scope, group=self.group_id)
        member_dn = ldap.user_filter.format(username=self.user_id)
        member2_dn = ldap.user_filter.format(username=self.superuser_id)
        member3_dn = ldap.user_filter.format(username=self.user3_id)

        group3_dn = ldap.group_filter(scope=self.scope, group=self.group3_id)
        self.conn.add(
            group3_dn,
            'groupOfUniqueNames',
            {'uniqueMember': [member3_dn]}
            )

        self.conn.add(
            group_dn,
            'groupOfUniqueNames',
            {'uniqueMember': [member_dn, group3_dn]}
            )
        loop.run_until_complete(ldap.addScopeRoleGroup(
            self.scope,
            self.group_id,
            'reader'
            ))
        group2_dn = ldap.group_filter(scope=self.scope, group=self.group2_id)
        self.conn.add(
            group2_dn,
            'groupOfUniqueNames',
            {'uniqueMember': [member_dn, member2_dn]}
            )
