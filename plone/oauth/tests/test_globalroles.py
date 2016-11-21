from plone.oauth.groups import get_group
from plone.oauth.tests.base import BaseHorusTest


class TestGroupsRoles(BaseHorusTest):

    DISABLE_CACHE_REDIS = True

    def test_get_globalroles_group(self):
        self.set_app_superuser()
        self.params['group'] = self.group_id

        res, decoded = self.call_horus(get_group)
        assert res.status == 200
        assert decoded['result']['name'] == self.group_id
        assert 'reader' in decoded['result']['roles']


class TestGroupsRolesRedis(TestGroupsRoles):
    DISABLE_CACHE_REDIS = False
