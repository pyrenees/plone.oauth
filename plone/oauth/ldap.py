
from ldap3 import Server, Connection, SUBTREE, ASYNC, SYNC, BASE, LEVEL, SIMPLE, REUSABLE, ANONYMOUS, SASL, ALL_ATTRIBUTES, DEREF_ALWAYS
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException
from ldap3.utils.hashed import hashed
from ldap3 import HASHED_SHA512
import sys
import asyncio
import ujson
import plone.oauth

USER_ATTRIBUTES = ['sn', 'cn', 'mail']

class LDAPUserManager(object):

    def __init__(
            self,
            ldap_server,
            user_filter,
            base_dn=None,
            root_dn=None,
            passwd_dn=None,
            user_profile=[],
            read_only=True,
            cache_users=None,
            cache_groups=None):
        self.ldap_server = ldap_server
        self.root_dn = root_dn
        self.passwd_dn = passwd_dn
        self.base_dn = base_dn
        self.user_filter = user_filter
        self.user_profile = user_profile
        self.read_only = read_only
        self.cache_users = cache_users
        self.cache_groups = cache_groups
        self.ttl_users = 3660
        self.bind()


    def scopes_filter(self):
        f = 'ou=scopes,' + self.base_dn
        return f

    def scope_filter(self, scope):
        f = 'ou={scope},' + self.scopes_filter()
        return f.format(scope=scope)

    def groups_filter(self, scope):
        return 'ou=groups,' + self.scope_filter(scope=scope)

    def group_filter(self, scope, group):
        f = 'cn={group},' + self.groups_filter(scope=scope)
        return f.format(group=group)

    def roles_filter(self, scope):
        return 'ou=roles,' + self.scope_filter(scope=scope)

    def role_filter(self, scope, role):
        f = 'cn={role},' + self.roles_filter(scope)
        return f.format(role=role)

    def users_filter(self):
        f = 'ou=users,' + self.base_dn
        return f

    def userdn2id(self, user_dn):
        """
        :param user_dn: can be a user or a group dn
        :type user_dn: str
        """
        parse_dn = None
        if user_dn.startswith('mail='):
            parse_dn = 'mail='
        elif user_dn.startswith('cn='):
            parse_dn = 'cn='

        if parse_dn:
            return user_dn[len(parse_dn):user_dn.find(',')]

    def bind(self):
        if self.root_dn is None:
            raise Exception('No LDAP Admin Configuration')

        authentication_method = SIMPLE
        bind_type = ASYNC

        self.ldap_conn_mng = Connection(
            self.ldap_server,
            authentication=authentication_method,
            client_strategy=bind_type,
            user=self.root_dn,
            password=self.passwd_dn,
            read_only=self.read_only)
        self.ldap_conn_mng.bind()

    def bind_root_readonly(self):
        """
        A root connection to LDAP server only read_only
        """
        if self.root_dn is None:
            raise Exception('No LDAP Admin Configuration')

        authentication_method = SIMPLE
        bind_type = ASYNC

        ldap_conn_mng = Connection(
            self.ldap_server,
            authentication=authentication_method,
            client_strategy=bind_type,
            user=self.root_dn,
            password=self.passwd_dn,
            read_only=True)

        ldap_conn_mng.bind()
        return ldap_conn_mng

    def unbind(self):
        self.ldap_conn_mng.unbind()

    def checkUserName(self, username):
        if ',' in username:
            raise TypeError('No , in username')

    def parse_async_add(self, return_code):
        """
        Parser the response for an LDAP async ADD
        """
        result = 'Not done'
        if return_code:
            result = self.ldap_conn_mng.get_response(return_code)
            result = result[1].get('description', 'Error no description')
        return result

    @asyncio.coroutine
    def addScope(self, scope):
        """
        !!!Admin add: must be protected when calling
        """
        # Needs admin
        if self.read_only:
            raise Exception('LDAP in Read only mode')

        self.bind()

        scope_dn = self.scope_filter(scope=scope)
        done = self.ldap_conn_mng.add(scope_dn, 'organizationalUnit')

        result = self.parse_async_add(done)

        if result == 'success':
            #add subelements for scope
            roles_dn = self.roles_filter(scope=scope)
            done = self.ldap_conn_mng.add(roles_dn, 'organizationalUnit')
            if self.parse_async_add(done) != 'success':
                result = 'Failed creating roles'

            groups_dn = self.groups_filter(scope=scope)
            done = self.ldap_conn_mng.add(groups_dn, 'organizationalUnit')
            if self.parse_async_add(done) != 'success':
                result = 'Failed creating groups'

        self.unbind()
        return result

    @asyncio.coroutine
    def addUser(self, username, password):
        """
        !!!Admin add: must be protected when calling
        """
        # Needs admin
        if self.read_only:
            raise Exception('LDAP in Read only mode')

        self.bind()

        self.checkUserName(username)
        user_dn = self.user_filter.format(username=username)
        if '@' in username:
            sn = username.split('@')[0]
        else:
            sn = username

        done = self.ldap_conn_mng.add(
            user_dn,
            self.user_profile,
            {
            'cn': username,
            'sn': sn,
            'mail': username,
            'userPassword': password,
            })

        result = self.parse_async_add(done)
        self.unbind()
        return result

    @asyncio.coroutine
    def addGroup(self, scope, group):
        """
        !!!Admin add: must be protected when calling
        """
        # Needs admin
        if self.read_only:
            raise Exception('LDAP in Read only mode')

        self.bind()

        self.checkUserName(group)
        group_dn = self.group_filter(scope=scope, group=group)

        done = self.ldap_conn_mng.add(
            group_dn,
            'groupOfUniqueNames',
            {
            'cn': group,
            'uniqueMember': group_dn #  group itself as an empty members list
            })

        result = self.parse_async_add(done)
        self.unbind()
        return result


    @asyncio.coroutine
    def setPassword(self, username, password):
        """
        !!!Admin add: must be protected when calling
        """
        # Needs admin
        if self.read_only:
            raise Exception('LDAP in Read only mode')
        self.bind()
        user_dn = self.user_filter.format(username=username)
        hashed_password = hashed(HASHED_SHA512, password)
        done = self.ldap_conn_mng.modify(
            user_dn,
            {'userPassword': [(MODIFY_REPLACE, [hashed_password])]}
            )
        result = self.parse_async_add(done)
        if result == 'success':
            return True
        else:
            return False


    @asyncio.coroutine
    def addScopeRole(self, scope, user_dn, role):
        """
        !!!Admin add: must be protected when calling

        `user_dn` can be a user or a group dn.
        """
        # Needs admin
        if self.read_only:
            raise Exception('LDAP in Read only mode')

        self.bind()

        role_dn = self.role_filter(scope=scope, role=role.lower())

        #Create role for first time
        done = self.ldap_conn_mng.add(
            role_dn,
            'groupOfUniqueNames',
            {'cn': role, 'uniqueMember': user_dn}
            )
        result = self.parse_async_add(done)
        if  result == 'entryAlreadyExists':
            #Extend role with new user
            done = self.ldap_conn_mng.modify(
                role_dn,
                {'uniqueMember': [(MODIFY_ADD, [user_dn])]}
                )
            result = self.parse_async_add(done)

        self.unbind()
        return result

    @asyncio.coroutine
    def addScopeRoleUser(self, scope, username, role):
        user_dn = self.user_filter.format(username=username)
        return self.addScopeRole(scope, user_dn, role)

    @asyncio.coroutine
    def addScopeRoleGroup(self, scope, groupname, role):
        group_dn = self.group_filter(scope, groupname)
        return self.addScopeRole(scope, group_dn, role)

    @asyncio.coroutine
    def delScopeRole(self, scope, username, role):
        """
        !!!Admin del: must be protected when calling
        """
        # Needs admin
        if self.read_only:
            raise Exception('LDAP in Read only mode')

        self.bind()

        role_dn = self.role_filter(scope=scope, role=role.lower())
        user_dn = self.user_filter.format(username=username)

        #Find role for first time
        done = self.ldap_conn_mng.modify(
            role_dn,
            {'uniqueMember': [(MODIFY_DELETE, [user_dn])]}
            )
        result = self.parse_async_add(done)

        if result == 'objectClassViolation':
            # member was the last remaining
            done = self.ldap_conn_mng.delete(role_dn)
            result = self.parse_async_add(done)

        self.unbind()
        return result

    @asyncio.coroutine
    def searchUser(self, scope, criteria, exact_match, attrs, page=None, num_x_page=0):
        """ !!!Admin search: must be protected when calling
        """
        total = 0
        result = []
        paged_size = num_x_page
        paged_cookie = page

        if exact_match is False and any(criteria.values()):
            for k in criteria.keys():
                criteria[k] = "*" + criteria[k] + "*"

        for objclass in self.user_profile:
            criteria['objectClass'] = objclass

        filter_ldap = ""
        for j, v in criteria.items():
            filter_ldap += "(%s=%s)" % (j, v)
        filter_ldap = "(&%s)" % filter_ldap

        self.ldap_conn_mng.bind()
        done = self.ldap_conn_mng.search(
            self.base_dn,
            filter_ldap,
            search_scope=SUBTREE,
            dereference_aliases=DEREF_ALWAYS,
            attributes=USER_ATTRIBUTES,
            size_limit=0,
            time_limit=0,
            types_only=False,
            get_operational_attributes=False,
            controls=None,
            paged_size=paged_size,
            paged_criticality=False,
            paged_cookie=paged_cookie)

        if done:
            result = self.ldap_conn_mng.get_response(done)[0]
            total = len(result)
        self.ldap_conn_mng.unbind()
        return [dict(r['attributes']) for r in result], total

    @asyncio.coroutine
    def getUser(self, dn, ldap_conn):
        # We should be logged in with the user
        with (yield from self.cache_users) as redis:
            user = yield from redis.get(dn)
            if user and user != b'{}':
                return ujson.loads(user)
        r = ldap_conn.search(
            dn,
            '(objectClass=*)',
            search_scope=BASE,
            attributes=USER_ATTRIBUTES)
        if r:
            try:
                res = ldap_conn.response[0]
            except:
                res = ldap_conn.get_response(r)[0]
                res = [x for x in res]
                res = res[0]
            with (yield from self.cache_users) as redis:
                redis.set(res['dn'], ujson.dumps(dict(res['attributes'])))
                redis.expire(res['dn'], self.ttl_users)
            return res['attributes']

    @asyncio.coroutine
    def loginUser(self, username, password):
        user_dn = self.user_filter.format(username=username)
        bind_type = SYNC
        authentication_method = SIMPLE
        ldap_conn = Connection(
            self.ldap_server,
            authentication=authentication_method,
            client_strategy=bind_type,
            user=user_dn,
            password=password,
            read_only=True)
        try:
            result = ldap_conn.bind()
            if result:
                user = yield from self.getUser(user_dn, ldap_conn)
                ldap_conn.unbind()
                return user
            else:
                return None
        except LDAPException:
            return None


    @asyncio.coroutine
    def getUserName(self, username):
        user_dn = self.user_filter.format(username=username)
        ldap_conn = self.bind_root_readonly()
        result = yield from self.getUser(username, ldap_conn)
        ldap_conn.unbind()
        return ' '.join(result['cn'])


    @asyncio.coroutine
    def get_user_groups(self, ldap_conn, scope, user_dn):
        """
        Return all groups cn that `user_dn` has in `scope`

        :param user_dn: can be a user or a group dn
        :type user_dn: str
        """
        groups_dn = self.groups_filter(scope=scope)

        search_filter = '(uniqueMember={0})'.format(user_dn)

        r = ldap_conn.search(
            groups_dn,
            search_filter,
            search_scope=SUBTREE,
            attributes=['cn']
            )
        if r:
            groups = ldap_conn.get_response(r)[0]
            groups = filter(lambda x: x['dn'] != user_dn, groups) # filter self
            return [res['attributes']['cn'][0] for res in groups]

    @asyncio.coroutine
    def get_user_roles(self, ldap_conn, scope, user_dn, groups=None):
        """
        Return all roles cn that `user_dn` has in `scope`.
        Return all roles cn that each of `groups` has in `scope`.

        :param user_dn: can be a user or a group dn
        :type user_dn: str
        :param groups: (Optionally)
        :type groups: list
        """
        roles_dn = self.roles_filter(scope=scope)
        search_filter = '(uniqueMember={0})'.format(user_dn)

        if groups is not None:
            search_filter = '(|' + search_filter
            for group_cn in groups:
                group_dn = self.group_filter(scope=scope, group=group_cn)
                search_filter += '(uniqueMember={0})'.format(group_dn)
            search_filter += ')'


        r = ldap_conn.search(
            roles_dn,
            search_filter,
            search_scope=SUBTREE,
            attributes=['cn']
            )
        if r:
            roles = ldap_conn.get_response(r)[0]
            return [res['attributes']['cn'][0] for res in roles]

    @asyncio.coroutine
    def get_info_user_or_group(self, user_dn, scope):
        """
        !!!Admin search: must be protected when calling

        :returns:
            {
                'groups': {
                    'group1': 1,
                },
                'roles': {
                    'Manager': 1,
                }
            }
        """
        ldap_conn = self.bind_root_readonly()
        groups = yield from self.get_user_groups(ldap_conn, scope, user_dn)
        roles = yield from self.get_user_roles(
            ldap_conn,
            scope,
            user_dn,
            groups = groups,
            )
        ldap_conn.unbind()

        return {
            'roles': {e: 1 for e in roles},
            'groups': {e: 1 for e in groups},
        }


    @asyncio.coroutine
    def getUserInfo(self, username, scope):
        """
        !!!Admin search: must be protected when calling

        :returns:
            {
                'groups': {
                    'group1': 1,
                },
                'roles': {
                    'Manager': 1,
                }
                'name': 'Name'
            }
        """
        user_dn = self.user_filter.format(username=username)
        info = yield from self.get_info_user_or_group(user_dn, scope)
        info['name'] = username
        return info

    @asyncio.coroutine
    def getGroupInfo(self, scope, group=None):
        """
        !!!Admin search: must be protected when calling

        :rtype: dict or list of dict or None
        :returns:
            {
                'members': [
                    member1,
                ],
                'name': 'Name'
            }

            or list of groups if group is None
            or None if group is not found

        """
        ldap_conn = self.bind_root_readonly()

        groups_dn = self.groups_filter(scope=scope)

        if group is None:
            search_filter = '(objectClass=groupOfUniqueNames)'
        else:
            search_filter = '(cn={0})'.format(group)

        r = ldap_conn.search(
            groups_dn,
            search_filter,
            search_scope=SUBTREE,
            attributes=['cn', 'uniqueMember']
            )

        if not r:
            raise Exception('LDAP Group search bad formed')

        groups = ldap_conn.get_response(r)[0]
        ldap_conn.unbind()

        @asyncio.coroutine
        def ldap2json(entry):
            group_dn = entry['dn']
            group_name = entry['attributes']['cn'][0]
            members_ldap = entry['attributes']['uniqueMember']
            members_ldap = filter(lambda x: x != group_dn, members_ldap) # filter self
            info = yield from self.get_info_user_or_group(group_dn, scope)
            info.update({
                'name': group_name,
                'members': list(map(self.userdn2id, members_ldap)),
                })
            return info

        groups = yield from asyncio.gather(*map(ldap2json, groups))

        if group is None:
            return groups
        try:
            return groups[0]
        except IndexError:
            return None


    @asyncio.coroutine
    def get_all_scopes(self, ldap_conn):
        """
        """
        r = ldap_conn.search(
            self.scopes_filter(),
            "(objectClass=organizationalUnit)",
            search_scope=LEVEL,
            attributes=['ou']
            )
        if r:
            scopes = ldap_conn.get_response(r)[0]
            return [scope['attributes']['ou'][0] for scope in scopes]

    @asyncio.coroutine
    def getUserScopes(self, username):
        """
        Aquesta crida retorna tots els scopes als quals pertany un usuari

        Nota: es pot millorar. Recorre dos cops tots els scopes. Un cop per
        obtenir-los tots i un altre per filtrar segons si l'usuari pertany o no
        """
        ldap_conn = self.bind_root_readonly()

        all_scopes = yield from self.get_all_scopes(ldap_conn)

        if plone.oauth.is_superuser(username):
            scopes = all_scopes
        else:
            user_dn = self.user_filter.format(username=username)
            scopes = []
            for scope in all_scopes:
                roles = yield from self.get_user_roles(ldap_conn, scope, user_dn)
                if roles:
                    scopes.append(scope)

        ldap_conn.unbind()

        return {
            'scopes': scopes
        }

    @asyncio.coroutine
    def get_all_users(self, ldap_conn):
        """
        Return all users cn that `username` has in `scope`.
        Optionally also search by `groups`.
        """
        r = ldap_conn.search(
            self.users_filter(),
            "(objectClass=organizationalPerson)",
            search_scope=LEVEL,
            attributes=['mail']
            )
        if r:
            users = ldap_conn.get_response(r)[0]
            return [user['attributes']['mail'][0] for user in users]

    @asyncio.coroutine
    def getScopeUsers(self, scope):
        """
        Retorna tots els usuaris que pertanyen a un scope

        Nota: es pot millorar. Recorre dos cops tots els usuaris. Un cop per
        obtenir-los tots i un altre per filtrar segons si l'usuari pertany o no
        """
        ldap_conn = self.bind_root_readonly()

        all_users_ids = yield from self.get_all_users(ldap_conn)

        users = []
        for user_id in all_users_ids:
            user_dn = self.user_filter.format(username=user_id)
            roles = yield from self.get_user_roles(ldap_conn, scope, user_dn)
            if roles:
                user = {
                    'id': user_id,
                    'roles': roles
                }
                users.append(user)

        ldap_conn.unbind()

        return {
            'users': users
        }
