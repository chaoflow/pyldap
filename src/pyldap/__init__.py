"""Enriching python-ldap with a more pythonic API

- unicode/utf8 decoding/encoding
- boolean and binary conversion (according to ldap schema)
- multi valued vs single valued attributes
"""
from __future__ import absolute_import

import ldap

from . import aspects


SCOPE_BASE = ldap.SCOPE_BASE
SCOPE_ONELEVEL = ldap.SCOPE_ONELEVEL
SCOPE_SUBTREE = ldap.SCOPE_SUBTREE


PyReconnectLDAPObject = aspects.pythonise(ldap.ldapobject.ReconnectLDAPObject)
