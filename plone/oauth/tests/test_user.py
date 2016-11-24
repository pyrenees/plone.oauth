import asyncio

from aiohttp.web_exceptions import HTTPBadRequest
from plone.oauth.utils.request import payload
from plone.oauth.endpoints import get_authorization_code, get_token
from plone.oauth.search import search_user
from plone.oauth.tests.conftest import secret
from plone.oauth.users import get_user, add_scope, add_user
from plone.oauth.users import grant_user_scope_roles, deny_user_scope_roles
import jwt
import unittest

SUPERUSER_HARDCODED = 'admin@example.com'


class MockClient():
    def __init__(self, app):
        self.app = app
        self.params = {}
        self.headers = {}
        self.client = 'plone'
        self.client_secret = 'plone'
        self.user = 'user@example.com'
        self.user_password = 'user'
        self.user_roles = {'Contributor': 1, 'Member':1, 'Editor': 1}
        self.user_groups = {'group1': 1}
        self.new_user ='hola@example.com'
        self.manager = 'manager@example.com'
        self.manager_password = '123456'
        self.superuser = SUPERUSER_HARDCODED
        self.superuser_password = 'admin'
        self.scope = 'plone'
        self.auth_code = None
        self.service_token = None
        self.user_token = None
        self.superuser_token = None
        asyncio.get_event_loop().run_until_complete(self.setup())

    async def setup_service_token(self):
        # We get the authorize code
        self.params['grant_type'] = 'service'
        self.params['client_id'] = self.client
        self.params['client_secret'] = self.client_secret
        self.app = self.app._replace(post=payload(self.params), headers=self.headers)
        view_callable = asyncio.coroutine(get_token)
        info = await view_callable(self.app)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        self.service_token = info_decoded['service_token']

    async def setup_authorize_code(self):
        # We get the authorize code
        self.params['response_type'] = 'code'
        self.params['client_id'] = self.client
        self.params['service_token'] = self.service_token
        self.params['scopes'] = [self.scope]
        self.app = self.app._replace(post=payload(self.params), headers=self.headers)
        view_callable = asyncio.coroutine(get_authorization_code)
        info = await view_callable(self.app)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        self.auth_code = info_decoded['auth_code']


    async def setup_user_token(self):
        # We get the working token for the user
        self.params['grant_type'] = 'user'
        self.params['code'] = self.auth_code
        self.params['username'] = self.user
        self.params['password'] = self.user_password
        self.params['scopes'] = [self.scope]
        self.headers = {'User-Agent': 'DUMMY', 'Host': '127.0.0.1:8080'}
        self.app = self.app._replace(
            post=payload(self.params), headers=self.headers)
        view_callable = asyncio.coroutine(get_token)
        info = await view_callable(self.app)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        self.user_token = info_decoded['token']

    async def setup_manager_token(self):
        #add user by superadmin
        self.setup_app_superuser()
        self.params['scope'] = self.scope
        self.params['user'] = self.manager
        self.params['password'] = self.manager_password
        self.app = self.app._replace(post=payload(self.params), headers=self.headers)
        view_callable = asyncio.coroutine(add_user)
        info = await view_callable(self.app)
        assert info.status in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'entryAlreadyExists')

        #grant user Manager
        self.setup_app_superuser()
        self.params['scope'] = self.scope
        self.params['roles'] = ['site administrator']
        self.app = self.app._replace(post=payload(self.params), headers=self.headers)
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        info = await view_callable(self.app)
        assert info.status in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'attributeOrValueExists')

        # We get the working token for the manager
        self.params['grant_type'] = 'user'
        self.params['code'] = self.auth_code
        self.params['username'] = self.manager
        self.params['password'] = self.manager_password
        self.params['scopes'] = [self.scope]
        self.app = self.app._replace(post=payload(self.params), headers=self.headers)
        view_callable = asyncio.coroutine(get_token)
        info = await view_callable(self.app)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        self.manager_token = info_decoded['token']


    async def setup_superuser_token(self):
        # We get the working token for the superuser
        self.params['grant_type'] = 'user'
        self.params['code'] = self.auth_code
        self.params['username'] = self.superuser
        self.params['password'] = self.superuser_password
        self.params['scopes'] = [self.scope]
        self.app = self.app._replace(post=payload(self.params), headers=self.headers)
        view_callable = asyncio.coroutine(get_token)
        info = await view_callable(self.app)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        self.superuser_token = info_decoded['token']

    async def setup(self):
        await self.setup_service_token()
        await self.setup_authorize_code()
        await self.setup_user_token()
        await self.setup_authorize_code()
        await self.setup_superuser_token()
        await self.setup_authorize_code()
        await self.setup_manager_token()

    def setup_app_user(self):
        self.params['service_token'] = self.service_token
        self.params['scope'] = self.scope
        self.params['user_token'] = self.user_token
        self.params['user'] = self.user

    def setup_app_manager(self):
        self.params['service_token'] = self.service_token
        self.params['scope'] = self.scope
        self.params['user_token'] = self.manager_token
        self.params['user'] = self.manager

    def setup_app_superuser(self):
        self.params['service_token'] = self.service_token
        self.params['scope'] = self.scope
        self.params['user_token'] = self.superuser_token

    def setup_app_client(self):
        self.params['code'] = self.service_token
        self.params['scope'] = self.scope


def test_endpoints(app):

    mock = MockClient(app)

    async def _test_user_info():
        mock.setup_app_user()
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(get_user)
        info = await view_callable(mock.app)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == mock.user_roles
        assert info_decoded['result']['groups'] == mock.user_groups

    asyncio.get_event_loop().run_until_complete(_test_user_info())

    async def _test_user_info_by_admin():
        #get info for the user by superadmin
        mock.setup_app_superuser()
        mock.params['user'] = mock.user
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(get_user)
        info = await view_callable(mock.app)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == mock.user_roles
        assert info_decoded['result']['groups'] == mock.user_groups

    asyncio.get_event_loop().run_until_complete(_test_user_info_by_admin())

    async def _test_superadmin_info():
        #get info for superadmin
        mock.setup_app_superuser()
        mock.params['user'] = mock.superuser
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(get_user)
        info = await view_callable(mock.app)
        assert info.status == 200

        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {'plone.Manager': 1}
        assert info_decoded['result']['groups'] == {}

    asyncio.get_event_loop().run_until_complete(_test_superadmin_info())

    async def _test_search_user():
        mock.setup_app_client()
        mock.params['criteria'] = '{"mail": "'+mock.user+'"}'
        mock.params['exact_match'] = 'True'
        mock.params['attrs'] = '["mail"]'
        mock.params['page'] = '0'
        mock.params['num_x_page'] = '30'
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(search_user)
        info = await view_callable(mock.app)
        assert info.status == 200

        #search user empty criteria without exact_match
        mock.params['criteria'] = '{"displayName": ""}'
        mock.params['exact_match'] = None
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(search_user)
        info = await view_callable(mock.app)
        assert info.status == 200

        #search all users in scope
        mock.params['criteria'] = '{}'
        mock.params['exact_match'] = None
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(search_user)
        info = await view_callable(mock.app)
        assert info.status == 200
        info_decoded = jwt.decode(info.body, secret)

    asyncio.get_event_loop().run_until_complete(_test_search_user())

    async def _test_add_scope():
        #add scope by superadmin
        mock.setup_app_superuser()
        mock.params['scope'] = 'nou_test'
        mock.params['admin_user'] = 'a@example.com'
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(add_scope)
        info = await view_callable(mock.app)
        assert info.status in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'entryAlreadyExists')

        #add already added scope
        mock.params['scope'] = 'nou_test'
        mock.params['admin_user'] = 'a@example.com'
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(add_scope)
        info = await view_callable(mock.app)
        assert info.status == 400
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == 'entryAlreadyExists'

        #add scope by not superadmin
        mock.setup_app_user()
        mock.params['scope'] = 'nou_test_2'
        mock.params['admin_user'] = 'a@example.com'
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(add_scope)
        with unittest.TestCase().assertRaises(
            HTTPBadRequest, msg = 'NOT VALID token: must be superuser'):
            info = await view_callable(mock.app)

    asyncio.get_event_loop().run_until_complete(_test_add_scope())

    async def _test_add_user():
        #add user by superadmin
        mock.setup_app_superuser()
        mock.params['scope'] = 'nou_test'
        mock.params['user'] = mock.new_user
        mock.params['password'] = 'password'
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(add_user)
        info = await view_callable(mock.app)
        assert info.status in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'entryAlreadyExists')

        #add already added user
        mock.params['user'] = mock.new_user
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(add_user)
        info = await view_callable(mock.app)
        assert info.status == 400
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == 'entryAlreadyExists'

        await mock.setup_authorize_code()

        #login added user
        mock.params['grant_type'] = 'user'
        mock.params['code'] = mock.auth_code
        mock.params['username'] = mock.new_user
        mock.params['password'] = 'password'
        mock.params['scopes'] = [mock.scope]
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(get_token)
        info = await view_callable(mock.app)
        assert info.status == 200
        decoded_info = jwt.decode(info.text, 'secret', algorithms=['HS256'])
        assert decoded_info['login'] == mock.new_user

    asyncio.get_event_loop().run_until_complete(_test_add_user())

    async def _test_grant_globaleditor():
        #grant role by superadmin
        mock.setup_app_superuser()
        mock.params['scope'] = 'nou_test'
        mock.params['user'] = mock.new_user
        mock.params['roles'] = "['Editor']"
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        info = await view_callable(mock.app)
        assert info.status in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'attributeOrValueExists')

        #add already added role
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        info = await view_callable(mock.app)
        assert info.status == 400
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == 'attributeOrValueExists'

        mock.params['user'] = mock.new_user
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(get_user)
        info = await view_callable(mock.app)
        assert info.status == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {'Editor': 1}

        #grant role to other user
        mock.params['user'] = mock.user
        mock.params['roles'] = ['Editor', 'Contributor']
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        info = await view_callable(mock.app)
        assert info.status in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'attributeOrValueExists')

        #check added roles
        mock.params['user'] = mock.user
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(get_user)
        info = await view_callable(mock.app)
        assert info.status == 200
        info_decoded = jwt.decode(info.body, secret)
        assert sorted(info_decoded['result']['roles'].keys()) == ['Contributor', 'Editor']

        #deny role by superadmin
        mock.params['user'] = mock.user
        mock.params['roles'] = "['Editor']"
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(deny_user_scope_roles)
        info = await view_callable(mock.app)
        assert info.status == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == 'success'

        #remove already removed role
        mock.params['user'] = mock.user
        mock.params['roles'] = ['Editor']
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(deny_user_scope_roles)
        info = await view_callable(mock.app)
        assert info.status == 400
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == "noSuchAttribute"

        #check added and deny roles
        mock.params['user'] = mock.user
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(get_user)
        info = await view_callable(mock.app)
        assert info.status == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {'Contributor': 1}

        #check delete all roles
        mock.params['user'] = mock.user
        mock.params['roles'] = list(info_decoded['result']['roles'].keys())
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(deny_user_scope_roles)
        info = await view_callable(mock.app)
        assert info.status == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == "success"

        #check no roles
        mock.params['user'] = mock.user
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(get_user)
        info = await view_callable(mock.app)
        assert info.status == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {}


    asyncio.get_event_loop().run_until_complete(_test_grant_globaleditor())

    async def _test_manager():
        mock.setup_app_manager()
        # check manager role
        view_callable = asyncio.coroutine(get_user)
        info = await view_callable(mock.app)
        assert info.status == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {'site administrator': 1}

        # check manager can assign roles
        mock.params['scope'] = mock.scope
        mock.params['user'] = mock.new_user
        mock.params['roles'] = ['Editor']
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        info = await view_callable(mock.app)
        assert info.status in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'attributeOrValueExists')

        # check manager can get user and check added roles
        mock.params['user'] = mock.new_user
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(get_user)
        info = await view_callable(mock.app)
        assert info.status == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {'Editor': 1}

    asyncio.get_event_loop().run_until_complete(_test_manager())

    async def _test_no_manager():
        mock.setup_app_user()

        # check not manager can not assign roles
        mock.params['scope'] = mock.scope
        mock.params['user'] = mock.new_user
        mock.params['roles'] = ['plone.Manager']
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        with unittest.TestCase().assertRaises(
            HTTPBadRequest, msg = 'NOT VALID token: must be manager'):
            info = await view_callable(mock.app)

        # check not manager can not get user
        mock.params['user'] = mock.new_user
        mock.app = mock.app._replace(post=payload(mock.params), headers=mock.headers)
        view_callable = asyncio.coroutine(get_user)
        with unittest.TestCase().assertRaises(
            HTTPBadRequest, msg = 'NOT VALID token: must be manager'):
            info = await view_callable(mock.app)

    asyncio.get_event_loop().run_until_complete(_test_no_manager())
