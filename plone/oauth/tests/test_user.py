import asyncio

from aiohttp.web_exceptions import HTTPBadRequest

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

    @asyncio.coroutine
    def setup_service_token(self):
        # We get the authorize code
        self.app.params['grant_type'] = 'service'
        self.app.params['client_id'] = self.client
        self.app.params['client_secret'] = self.client_secret
        view_callable = asyncio.coroutine(get_token)
        info = yield from view_callable(self.app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)
        self.service_token = info_decoded['service_token']

    @asyncio.coroutine
    def setup_authorize_code(self):
        # We get the authorize code
        self.app.params['response_type'] = 'code'
        self.app.params['client_id'] = self.client
        self.app.params['service_token'] = self.service_token
        self.app.params['scopes'] = [self.scope]
        view_callable = asyncio.coroutine(get_authorization_code)
        info = yield from view_callable(self.app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)
        self.auth_code = info_decoded['auth_code']


    @asyncio.coroutine
    def setup_user_token(self):
        # We get the working token for the user
        self.app.params['grant_type'] = 'user'
        self.app.params['code'] = self.auth_code
        self.app.params['username'] = self.user
        self.app.params['password'] = self.user_password
        self.app.params['scopes'] = [self.scope]
        self.app.user_agent = 'DUMMY'
        self.app.client_addr = '127.0.0.1'
        view_callable = asyncio.coroutine(get_token)
        info = yield from view_callable(self.app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)
        self.user_token = info_decoded['token']

    @asyncio.coroutine
    def setup_manager_token(self):
        #add user by superadmin
        self.setup_app_superuser()
        self.app.params['scope'] = self.scope
        self.app.params['user'] = self.manager
        self.app.params['password'] = self.manager_password
        view_callable = asyncio.coroutine(add_user)
        info = yield from view_callable(self.app)
        assert info.status_code in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'entryAlreadyExists')

        #grant user Manager
        self.setup_app_superuser()
        self.app.params['scope'] = self.scope
        self.app.params['roles'] = ['site administrator']
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        info = yield from view_callable(self.app)
        assert info.status_code in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'attributeOrValueExists')

        # We get the working token for the manager
        self.app.params['grant_type'] = 'user'
        self.app.params['code'] = self.auth_code
        self.app.params['username'] = self.manager
        self.app.params['password'] = self.manager_password
        self.app.params['scopes'] = [self.scope]
        self.app.user_agent = 'DUMMY'
        self.app.client_addr = '127.0.0.1'
        view_callable = asyncio.coroutine(get_token)
        info = yield from view_callable(self.app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)
        self.manager_token = info_decoded['token']


    @asyncio.coroutine
    def setup_superuser_token(self):
        # We get the working token for the superuser
        self.app.params['grant_type'] = 'user'
        self.app.params['code'] = self.auth_code
        self.app.params['username'] = self.superuser
        self.app.params['password'] = self.superuser_password
        self.app.params['scopes'] = [self.scope]
        self.app.user_agent = 'DUMMY'
        self.app.client_addr = '127.0.0.1'
        view_callable = asyncio.coroutine(get_token)
        info = yield from view_callable(self.app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)
        self.superuser_token = info_decoded['token']

    @asyncio.coroutine
    def setup(self):
        yield from self.setup_service_token()
        yield from self.setup_authorize_code()
        yield from self.setup_user_token()
        yield from self.setup_authorize_code()
        yield from self.setup_superuser_token()
        yield from self.setup_authorize_code()
        yield from self.setup_manager_token()

    def setup_app_user(self):
        self.app.params['service_token'] = self.service_token
        self.app.params['scope'] = self.scope
        self.app.params['user_token'] = self.user_token
        self.app.params['user'] = self.user

    def setup_app_manager(self):
        self.app.params['service_token'] = self.service_token
        self.app.params['scope'] = self.scope
        self.app.params['user_token'] = self.manager_token
        self.app.params['user'] = self.manager

    def setup_app_superuser(self):
        self.app.params['service_token'] = self.service_token
        self.app.params['scope'] = self.scope
        self.app.params['user_token'] = self.superuser_token

    def setup_app_client(self):
        self.app.params['code'] = self.service_token
        self.app.params['scope'] = self.scope


def test_endpoints(app):

    mock = MockClient(app)

    @asyncio.coroutine
    def _test_user_info():
        mock.setup_app_user()
        view_callable = asyncio.coroutine(get_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == mock.user_roles
        assert info_decoded['result']['groups'] == mock.user_groups

    asyncio.get_event_loop().run_until_complete(_test_user_info())

    @asyncio.coroutine
    def _test_user_info_by_admin():
        #get info for the user by superadmin
        mock.setup_app_superuser()
        mock.app.params['user'] = mock.user
        view_callable = asyncio.coroutine(get_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == mock.user_roles
        assert info_decoded['result']['groups'] == mock.user_groups

    asyncio.get_event_loop().run_until_complete(_test_user_info_by_admin())

    @asyncio.coroutine
    def _test_superadmin_info():
        #get info for superadmin
        mock.setup_app_superuser()
        mock.app.params['user'] = mock.superuser
        view_callable = asyncio.coroutine(get_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200

        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {'Manager': 1}
        assert info_decoded['result']['groups'] == {}

    asyncio.get_event_loop().run_until_complete(_test_superadmin_info())

    @asyncio.coroutine
    def _test_search_user():
        mock.setup_app_client()
        mock.app.params['criteria'] = '{"mail": "'+mock.user+'"}'
        mock.app.params['exact_match'] = 'True'
        mock.app.params['attrs'] = '["mail"]'
        mock.app.params['page'] = '0'
        mock.app.params['num_x_page'] = '30'
        view_callable = asyncio.coroutine(search_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200

        #search user empty criteria without exact_match
        mock.app.params['criteria'] = '{"fullname": ""}'
        mock.app.params['exact_match'] = None
        view_callable = asyncio.coroutine(search_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200

        #search all users in scope
        mock.app.params['criteria'] = '{}'
        mock.app.params['exact_match'] = None
        view_callable = asyncio.coroutine(search_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200
        info_decoded = jwt.decode(info.body, secret)

    asyncio.get_event_loop().run_until_complete(_test_search_user())

    @asyncio.coroutine
    def _test_add_scope():
        #add scope by superadmin
        mock.setup_app_superuser()
        mock.app.params['scope'] = 'nou_test'
        mock.app.params['admin_user'] = 'a@example.com'
        view_callable = asyncio.coroutine(add_scope)
        info = yield from view_callable(mock.app)
        assert info.status_code in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'entryAlreadyExists')

        #add already added scope
        mock.app.params['scope'] = 'nou_test'
        mock.app.params['admin_user'] = 'a@example.com'
        view_callable = asyncio.coroutine(add_scope)
        info = yield from view_callable(mock.app)
        assert info.status_code == 400
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == 'entryAlreadyExists'

        #add scope by not superadmin
        mock.setup_app_user()
        mock.app.params['scope'] = 'nou_test_2'
        mock.app.params['admin_user'] = 'a@example.com'
        view_callable = asyncio.coroutine(add_scope)
        with unittest.TestCase().assertRaises(
            HTTPBadRequest, msg = 'NOT VALID token: must be superuser'):
            info = yield from view_callable(mock.app)

    asyncio.get_event_loop().run_until_complete(_test_add_scope())

    @asyncio.coroutine
    def _test_add_user():
        #add user by superadmin
        mock.setup_app_superuser()
        mock.app.params['scope'] = 'nou_test'
        mock.app.params['user'] = mock.new_user
        mock.app.params['password'] = 'password'
        view_callable = asyncio.coroutine(add_user)
        info = yield from view_callable(mock.app)
        assert info.status_code in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'entryAlreadyExists')

        #add already added user
        mock.app.params['user'] = mock.new_user
        view_callable = asyncio.coroutine(add_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 400
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == 'entryAlreadyExists'

        yield from mock.setup_authorize_code()

        #login added user
        mock.app.params['grant_type'] = 'user'
        mock.app.params['code'] = mock.auth_code
        mock.app.params['username'] = mock.new_user
        mock.app.params['password'] = 'password'
        mock.app.params['scopes'] = [mock.scope]
        view_callable = asyncio.coroutine(get_token)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200
        decoded_info = jwt.decode(info.text, 'secret', algorithms=['HS256'])
        assert decoded_info['login'] == mock.new_user

    asyncio.get_event_loop().run_until_complete(_test_add_user())

    @asyncio.coroutine
    def _test_grant_globaleditor():
        #grant role by superadmin
        mock.setup_app_superuser()
        mock.app.params['scope'] = 'nou_test'
        mock.app.params['user'] = mock.new_user
        mock.app.params['roles'] = "['Editor']"
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        info = yield from view_callable(mock.app)
        assert info.status_code in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'attributeOrValueExists')

        #add already added role
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        info = yield from view_callable(mock.app)
        assert info.status_code == 400
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == 'attributeOrValueExists'

        mock.app.params['user'] = mock.new_user
        view_callable = asyncio.coroutine(get_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {'Editor': 1}

        #grant role to other user
        mock.app.params['user'] = mock.user
        mock.app.params['roles'] = ['Editor', 'Contributor']
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        info = yield from view_callable(mock.app)
        assert info.status_code in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'attributeOrValueExists')

        #check added roles
        mock.app.params['user'] = mock.user
        view_callable = asyncio.coroutine(get_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200
        info_decoded = jwt.decode(info.body, secret)
        assert sorted(info_decoded['result']['roles'].keys()) == ['Contributor', 'Editor']

        #deny role by superadmin
        mock.app.params['user'] = mock.user
        mock.app.params['roles'] = "['Editor']"
        view_callable = asyncio.coroutine(deny_user_scope_roles)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == 'success'

        #remove already removed role
        mock.app.params['user'] = mock.user
        mock.app.params['roles'] = ['Editor']
        view_callable = asyncio.coroutine(deny_user_scope_roles)
        info = yield from view_callable(mock.app)
        assert info.status_code == 400
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == "noSuchAttribute"

        #check added and deny roles
        mock.app.params['user'] = mock.user
        view_callable = asyncio.coroutine(get_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {'Contributor': 1}

        #check delete all roles
        mock.app.params['user'] = mock.user
        mock.app.params['roles'] = list(info_decoded['result']['roles'].keys())
        view_callable = asyncio.coroutine(deny_user_scope_roles)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] == "success"

        #check no roles
        mock.app.params['user'] = mock.user
        view_callable = asyncio.coroutine(get_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {}


    asyncio.get_event_loop().run_until_complete(_test_grant_globaleditor())

    @asyncio.coroutine
    def _test_manager():
        mock.setup_app_manager()
        # check manager role
        view_callable = asyncio.coroutine(get_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {'site administrator': 1}

        # check manager can assign roles
        mock.app.params['scope'] = mock.scope
        mock.app.params['user'] = mock.new_user
        mock.app.params['roles'] = ['Editor']
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        info = yield from view_callable(mock.app)
        assert info.status_code in (200, 400)
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result'] in ('success', 'attributeOrValueExists')

        # check manager can get user and check added roles
        mock.app.params['user'] = mock.new_user
        view_callable = asyncio.coroutine(get_user)
        info = yield from view_callable(mock.app)
        assert info.status_code == 200
        info_decoded = jwt.decode(info.body, secret)
        assert info_decoded['result']['roles'] == {'Editor': 1}

    asyncio.get_event_loop().run_until_complete(_test_manager())

    def _test_no_manager():
        mock.setup_app_user()

        # check not manager can not assign roles
        mock.app.params['scope'] = mock.scope
        mock.app.params['user'] = mock.new_user
        mock.app.params['roles'] = ['Manager']
        view_callable = asyncio.coroutine(grant_user_scope_roles)
        with unittest.TestCase().assertRaises(
            HTTPBadRequest, msg = 'NOT VALID token: must be manager'):
            info = yield from view_callable(mock.app)

        # check not manager can not get user
        mock.app.params['user'] = mock.new_user
        view_callable = asyncio.coroutine(get_user)
        with unittest.TestCase().assertRaises(
            HTTPBadRequest, msg = 'NOT VALID token: must be manager'):
            info = yield from view_callable(mock.app)

    asyncio.get_event_loop().run_until_complete(_test_no_manager())
