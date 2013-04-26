from __future__ import absolute_import

from ldap import SCOPE_BASE
from ldap import NO_SUCH_OBJECT
from ldap import MOD_REPLACE
from ldap import MOD_ADD

from .. import PyReconnectLDAPObject
from ..testing import SlapdTestCase as TestCase

import ipdb

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
                  ('userPassword', UTF8_PW),
                  ('description', UTF8_DN))
    }

    UNICODE_ENTRIES = {
        UNICODE_DN: (('objectClass', ['organization']),
                     ('o', UNICODE),
                     ('userPassword', UNICODE_PW),
                     ('description', UNICODE_DN))

    }

    LDAPObject = PyReconnectLDAPObject

    def setUp(self):
        TestCase.setUp(self)
        self.pyldap = self.LDAPObject(uri=self.uri)
        self.pyldap.bind_s('cn=root,o=o', 'secret')

    def test_utf8_dn(self):
        self.assertEquals(self.UTF8.decode('utf8'), u'\xe4')
        self.assertEquals(self.UTF8_DN.decode('utf8'), u'o=\xe4,o=o')

    def test_bind_whoami_s(self):
        self.ldap.bind_s(self.UTF8_DN, self.UTF8_PW)
        self.assertEqual(self.ldap.whoami_s(), 'dn:' + self.UTF8_DN)
        self.pyldap.bind_s(self.UNICODE_DN, self.UNICODE_PW)
        self.assertEqual(self.pyldap.whoami_s(), 'dn:' + self.UNICODE_DN)

    def test_search(self):
        result = self.pyldap.search(self.UNICODE_DN, SCOPE_BASE)
        #XXX generator returns a list, check if this is ok
        node = iter(result).next()[0]
        self.assertEqual(node[0], self.UNICODE_DN)

    def test_search_s(self):
        result = self.pyldap.search_s(self.UNICODE_DN, SCOPE_BASE)[0]
        #ipdb.set_trace()
        self.assertEqual(result[0], self.UNICODE_DN)
        self.assertEqual(result[1]['description'], self.UNICODE_DN)

    def test_add_s(self):
        self.pyldap.delete_s(self.UNICODE_DN)
        self.pyldap.add_s(self.UNICODE_DN,
                          self.UNICODE_ENTRIES[self.UNICODE_DN])
        result = self.pyldap.search_s(self.UNICODE_DN, SCOPE_BASE)[0]
        self.assertEqual(result[0], self.UNICODE_DN)
        self.assertEqual(result[1]['description'], self.UNICODE_DN)

    def test_delete_s(self):
        result = self.pyldap.search_s(self.UNICODE_DN, SCOPE_BASE)
        self.assertTrue(result is not None)
        self.pyldap.delete_s(self.UNICODE_DN)
        self.assertRaises(NO_SUCH_OBJECT, lambda: self.pyldap.search_s(
            self.UNICODE_DN, SCOPE_BASE))

    def test_modify_s(self):
        self.pyldap.modify_s(self.UNICODE_DN,
                             [(MOD_REPLACE, 'description', self.UNICODE)])
        result = self.pyldap.search_s(self.UNICODE_DN, SCOPE_BASE)[0]
        self.assertEqual(result[1]['description'], self.UNICODE)

    def test_blockattributes(self):
        result = self.pyldap.search_s(self.UNICODE_DN, SCOPE_BASE)[0]
        self.assertEqual(result[1]['userPassword'], [])

    #def test_binary(self):
    #    self.pyldap.modify_s(self.UNICODE_DN,
    #                         [(MOD_ADD, 'description',
    #                           self.UNICODE_DN)])
    #    result = self.pyldap.search_s(self.UNICODE_DN, SCOPE_BASE)[0]
    #    self.assertEqual(result[1]['userPassword'],
    #                     bytearray(self.UNICODE_DN, 'utf8'))
