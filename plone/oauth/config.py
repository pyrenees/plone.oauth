
from ldap3 import Server, Connection, SUBTREE, BASE, ASYNC, SIMPLE, ANONYMOUS, SASL, ALL_ATTRIBUTES, DEREF_ALWAYS
from ldap3.core.exceptions import LDAPException
import sys


class LDAPConfigManager(object):

    def __init__(
            self,
            ldap_server=None,
            base_dn=None,
            root_dn=None,
            passwd_dn=None,
            read_only=True,
            cache_scopes=None,
            cache_client_id=None):
        self.ldap_server = ldap_server
        self.root_dn = root_dn
        self.passwd_dn = passwd_dn
        self.base_dn = base_dn
        self.read_only = read_only
        self.cache_scopes = cache_scopes
        self.cache_client_id = cache_client_id

    def bind(self):
        """ Binding with LDAP
        """
        if self.root_dn is None:
            raise Exception('No LDAP Admin Configuration')

        bind_type = SIMPLE
        self.ldap_conn = Connection(
            self.ldap_server,
            authentication=bind_type,
            user=self.root_dn,
            password=self.passwd_dn,
            read_only=self.read_only)
        self.ldap_conn.bind()

    def unbind(self):
        self.ldap_conn.unbind()

    def hasScope(self, scope):
        self.bind()
        if self.cache_scopes and scope in self.cache_scopes:
            return True
        search_base = 'ou={},ou=scopes,{}'.format(scope, self.base_dn)
        r = self.ldap_conn.search(
            search_base,
            '(objectClass=organizationalUnit)',
            search_scope=BASE,
            dereference_aliases=DEREF_ALWAYS,
            attributes=ALL_ATTRIBUTES,
            size_limit=0,
            time_limit=0,
            types_only=False,
            get_operational_attributes=False,
            controls=None,
            paged_size=None,
            paged_criticality=False,
            paged_cookie=None)
        if r:
            self.cache_scopes[scope] = r
            return True
        else:
            return False

    def hasClient(self, client):
        self.bind()
        if self.cache_client_id and client in self.cache_client_id:
            return self.cache_client_id[client]
        search_base = 'cn={},ou=clients,ou=config,{}'.format(client, self.base_dn)
        ret = self.ldap_conn.search(
            search_base,
            '(objectClass=person)',
            search_scope=BASE,
            dereference_aliases=DEREF_ALWAYS,
            attributes=ALL_ATTRIBUTES,
            size_limit=0,
            time_limit=0,
            types_only=False,
            get_operational_attributes=False,
            controls=None,
            paged_size=None,
            paged_criticality=False,
            paged_cookie=None)
        if ret:
            self.cache_client_id[client] = ret
            return True
        else:
            return False

    def clientAuth(self, client_id, secret):
        client_dn = 'cn={},ou=clients,ou=config,{}'.format(client_id, self.base_dn)
        bind_type = SIMPLE
        self.ldap_conn = Connection(
            self.ldap_server,
            authentication=bind_type,
            user=client_dn,
            password=secret)
        try:
            self.ldap_conn.bind()
            return True
        except:
            return False