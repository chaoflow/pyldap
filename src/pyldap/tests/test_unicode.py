from __future__ import absolute_import

from .. import PyReconnectLDAPObject
from ..testing import SlapdTestCase as TestCase


class TestUnicodeUtf8ReconnectLDAPObject(TestCase):
    """Test the UnicodeUtf8 mixin with a ReconnectLDAPObject

    FUTURE: parameterize test for SimpleLDAPObject and
    NonblockingLDAPObject

    """
    UNICODE = u'\xe4'
    UNICODE_DN = 'o=' + UNICODE + ',o=o'
    UNICODE_PW = UNICODE
    UTF8 = UNICODE.encode('utf8')
    UTF8_DN = 'o=' + UTF8 + ',o=o'
    UTF8_PW = UTF8
    ENTRIES = {
        UTF8_DN: (('objectClass', ['organization']),
                  ('o', UTF8),
                  ('userPassword', UTF8_PW)),
    }

    LDAPObject = PyReconnectLDAPObject

    def setUp(self):
        TestCase.setUp(self)
        self.pyldap = self.LDAPObject(uri=self.uri)
        self.pyldap.bind_s('cn=root,o=o', 'secret')

    def test_utf8_dn(self):
        self.assertEquals(self.UTF8.decode('utf8'), u'\xe4')
        self.assertEquals(self.UTF8_DN.decode('utf8'), u'o=\xe4,o=o')

    def add_s(self):
        pass

    def delete_s(self):
        pass

    def test_bind_whoami_s(self):
        self.ldap.bind_s(self.UTF8_DN, self.UTF8_PW)
        self.assertEqual(self.ldap.whoami_s(), 'dn:' + self.UTF8_DN)
        self.pyldap.bind_s(self.UNICODE_DN, self.UNICODE_PW)
        self.assertEqual(self.pyldap.whoami_(), 'dn:' + self.UNICODE_DN)

    def test_modify_s(self):
        pass

    def test_result(self):
        pass

    def test_search(self):
        pass

    def test_search_s(self):
        pass
