"""Enriching python-ldap with a more pythonic API

- unicode/utf8 decoding/encoding
- boolean and binary conversion (according to ldap schema)
- multi valued vs single valued attributes
"""
from __future__ import absolute_import

from ldap import ldapobject
from pyldap.aspects import pythonise

PyReconnectLDAPObject = pythonise(ldapobject.ReconnectLDAPObject)
