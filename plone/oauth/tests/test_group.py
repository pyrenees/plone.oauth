import pytest
from aiohttp.web_exceptions import HTTPBadRequest

from plone.oauth.groups import get_group, add_group
from plone.oauth.tests.base import BaseHorusTest


class TestGroups(BaseHorusTest):

    DISABLE_CACHE_REDIS = True

    def test_security_check_base_params_get(self):
        self.security_check_base_params(get_group)

    def test_security_check_base_params_add(self):
        self.security_check_base_params(add_group)

        # add empty group
        self.set_app_manager()
        self.app.params['group'] = None
        with pytest.raises(HTTPBadRequest) as excinfo:
            self.call_horus(add_group)
        assert str(excinfo.value) == 'group is missing'

    def test_get_all_scope_groups_superuser(self):
        self.set_app_superuser()

        res, decoded = self.call_horus(get_group)
        assert res.status_code == 200
        assert isinstance(res.decoded['result'], list)
        assert len(res.decoded['result']) == 3
        names = map(lambda x: x['name'], res.decoded['result'])
        assert self.group_id in names

    def test_get_scope_group_superuser(self):
        self.set_app_superuser()
        self.app.params['group'] = self.group_id

        res, decoded = self.call_horus(get_group)
        assert res.status_code == 200
        assert res.decoded['result']['name'] == self.group_id
        assert self.user_id in res.decoded['result']['members']
        assert res.decoded['result']['groups'] == {}

    def test_get_scope_group_inexistent_superuser(self):
        self.set_app_superuser()
        self.app.params['group'] = 'inexistent'

        res, decoded = self.call_horus(get_group)
        assert res.status_code == 400
        assert res.decoded['result'] == 'Group not found'

    def test_get_all_scope_group_manager(self):
        self.set_app_manager()
        self.app.params['group'] = self.group_id

        res, decoded = self.call_horus(get_group)
        assert res.status_code == 200
        assert decoded['result']['name'] == self.group_id
        assert self.user_id in res.decoded['result']['members']

    def test_get_all_scope_groups_user_forbidden(self):
        self.set_app_user()

        with pytest.raises(HTTPBadRequest) as excinfo:
            self.call_horus(get_group)
        assert str(excinfo.value) == 'NOT VALID token: must be manager'

    def test_get_group_of_groups(self):
        self.set_app_superuser()

        self.app.params['group'] = self.group_id
        res, decoded = self.call_horus(get_group)
        assert res.status_code == 200
        assert res.decoded['result']['name'] == self.group_id
        assert self.group3_id in res.decoded['result']['members']
        assert res.decoded['result']['groups'] == {}

        self.app.params['group'] = self.group3_id
        res, decoded = self.call_horus(get_group)
        assert res.status_code == 200
        assert res.decoded['result']['name'] == self.group3_id
        assert self.user3_id in res.decoded['result']['members']
        assert self.group_id in res.decoded['result']['groups']

    def test_add_group(self):
        nou_grup = 'nou_grup'
        self.set_app_manager()
        self.app.params['group'] = nou_grup

        # add group
        res, decoded = self.call_horus(add_group)
        assert res.status_code == 200
        assert decoded['result'] == 'success'

        # check added
        res, decoded = self.call_horus(get_group)
        assert res.status_code == 200
        assert decoded['result']['name'] == nou_grup
        assert len(decoded['result']['members']) == 0
        assert len(decoded['result']['groups']) == 0

        # error if readd group
        res, decoded = self.call_horus(add_group)
        assert res.status_code == 400
        assert decoded['result'] == 'entryAlreadyExists'


class TestGroupsWithRedis(TestGroups):
    DISABLE_CACHE_REDIS = False

