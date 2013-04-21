"""Enriching python-ldap with a more pythonic API

- unicode/utf8 decoding/encoding
- boolean and binary conversion (according to ldap schema)
- multi valued vs single valued attributes
"""
from __future__ import absolute_import

from ldap import ldapobject

import ipdb

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

 #XXX the class should do this:
 # encode dn --- check
 # encode strings in modlist --- check
 # convert booleans to utf8 strings --- no boolean attributes used, or???
 # convert bytearray to string (maybe base64)
 # return values only for single valued attributes???

    def simple_bind(self, who='', cred='', serverctrls=None, clientctrls=None):
        who = self._encode(who)
        cred = self._encode(cred)
        return ldapobject.ReconnectLDAPObject.simple_bind(self,
                who, cred, serverctrls, clientctrls)

    def whoami_s(self):
        result = ldapobject.ReconnectLDAPObject.whoami_s(self)
        return self._decode(result)

    def delete_ext(self, dn, serverctrls=None, clientctrls=None):
        return ldapobject.ReconnectLDAPObject.delete_ext(
            self, self._encode(dn), serverctrls, clientctrls)

    def add_ext(self, dn, modlist, serverctrls=None, clientctrls=None):
        return ldapobject.ReconnectLDAPObject.add_ext(self, self._encode(dn),
                                                   self._encodeaddlist(modlist),
                                                   serverctrls, clientctrls)

    def search_ext(self, base, scope, filterstr='(objectClass=*)',
                   attrlist=None, attrsonly=0, serverctrls=None,
                   clientctrls=None, timeout=-1, sizelimit=0):
        #XXX test filterstr and attrlist!
        return ldapobject.ReconnectLDAPObject.search_ext(self,
                                            self._encode(base),
                                            scope,
                                            self._encode(filterstr),
                                            self._encode_listorvalue(attrlist),
                                            attrsonly,
                                            serverctrls,
                                            clientctrls,
                                            timeout, sizelimit)

    def search_ext_s(self, base, scope, filterstr='(objectClass=*)',
                   attrlist=None, attrsonly=0, serverctrls=None,
                   clientctrls=None, timeout=-1, sizelimit=0):
        #XXX test filterstr and attrlist!
        result = ldapobject.ReconnectLDAPObject.search_ext_s(self,
                                            self._encode(base),
                                            scope,
                                            self._encode(filterstr),
                                            self._encode_listorvalue(attrlist),
                                            attrsonly,
                                            serverctrls,
                                            clientctrls,
                                            timeout, sizelimit)
        return self._decode_search(result)

    def modify_ext(self, dn, modlist, serverctrls=None, clientctrls=None):
        return ldapobject.ReconnectLDAPObject.modify_ext(self, self._encode(dn),
                                                self._encodemodifylist(modlist),
                                                serverctrls,
                                                clientctrls)


    #def result4(self, *args, **kw):
        #result = ldapobject.ReconnectLDAPObject.result4(self, *args, **kw)
        #results types: dn, (dn, attrs), [dn, attrs]
        #result = self._decode(result)
        #ipdb.set_trace()
        #if isinstance(result, list):
        #    for index, x in result:
        #        if isinstance(x, tuple):
        #            ipdb.set_trace()
        #return result

#-----------------------------------------------------------------------------
    def _encode(self, s):
        if isinstance(s, unicode):
            return s.encode(ENCODING)
        return s

    def _encodeaddlist(self, modlist):
        result = [(self._encode(x[0]) ,
                   self._encode_listorvalue(x[1]))
                  for x in modlist]
        return result

    def _encodemodifylist(self, modlist):
        result = [(x[0],
                   self._encode(x[1]),
                   self._encode_listorvalue(x[2]))
                  for x in modlist]
        return result

    def _encode_listorvalue(self, inputlist):
        if isinstance(inputlist, list):
            for index, x in enumerate(inputlist):
                inputlist[index] = self._encode(x)
        else:
            inputlist = self._encode(inputlist)
        return inputlist

    def _decode(self, s):
        if isinstance(s, str):
            return s.decode(ENCODING)
        return s

    def _decode_list(self, inputlist):
        for index, x in enumerate(inputlist):
            inputlist[index] = self._decode(x)
        return inputlist

    def _decode_search(self, result):
        for index, x in enumerate(result):
            if isinstance (x, tuple):
                d = dict()
                for key, value in x[1].iteritems():
                    new_key = self._decode(key)
                    new_value = self._decode_list(value)
                    d[new_key] = new_value
                result[index] = (self._decode(x[0]), d)
        return result
