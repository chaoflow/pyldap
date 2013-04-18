"""Enriching python-ldap with a more pythonic API

- unicode/utf8 decoding/encoding
- boolean and binary conversion (according to ldap schema)
- multi valued vs single valued attributes
"""
from __future__ import absolute_import

from ldap import ldapobject

ENCODING = "utf8"


BINARY_ATTRIBUTES=(
    'jpegPhoto'
)

BOOLEAN_ATTRIBUTES=(
)

SINGLE_VALUED=(
    'dc', 'domainComponent'
)


class PyReconnectLDAPObject(ldapobject.ReconnectLDAPObject):
    """
    Encode/Decode unicode to/from utf8
    ----------------------------------

    LDAP is a string-based protocol and at least openldap uses the
    utf8 encoding. `python-ldap` simply passes these strings on.

    We don't want to care about the LDAP encoding and would like
    unicode instead, for all strings that are really strings.

    """
    encoding = ENCODING

    def add_ext(self, dn, modlist):
        # encode dn
        # encode strings in modlist
        # convert booleans to utf8 strings
        # convert bytearray to string (maybe base64)
        msgid = ldapobject.ReconnectLDAPObject.add_ext(self, fn, *args, **kw)
        return msgid

    def _encode(fn_name, *args, **kw):
        """deep inspect args and kw, encode all unicode to utf8
        """
        return (utf8args, utfs8kw)

    def result4(self, *args, **kw):
        result = ldapobject.ReconnectLDAPObject.result4(self, *args, **kw)
        # results types: dn, (dn, attrs), [dn, attrs]
        return result
