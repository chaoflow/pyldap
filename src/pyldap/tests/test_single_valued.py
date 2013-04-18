from __future__ import absolute_import

from .. import PyReconnectLDAPObject
from ..testing import SlapdTestCase as TestCase


class TestSingleValuedReconnectLDAPObject(TestCase):
    """Test the UnicodeUtf8 mixin with a ReconnectLDAPObject

    FUTURE: parameterize test for SimpleLDAPObject and
    NonblockingLDAPObject

    """
    ENTRIES = {
        'dc=org,o=o': (('objectClass', ['top', 'dcObject', 'organization']),
                       ('o', 'organization'),
                       ('dc', 'org')),
    }

    LDAPObject = PyReconnectLDAPObject

    def setUp(self):
        TestCase.setUp(self)
        self.pyldap = self.LDAPObject(uri=self.uri)
        self.pyldap.bind_s('cn=root,o=o', 'secret')

    def test_result(self):
        # XXX: probably either here or in test_search
        pass

    def test_search(self):
        # XXX needs result to get async search result
        pass

    def test_search_s(self):
        # XXX: uses search and result internally
        pass
