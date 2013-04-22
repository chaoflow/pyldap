"""Enriching python-ldap with a more pythonic API

- unicode/utf8 decoding/encoding
- boolean and binary conversion (according to ldap schema)
- multi valued vs single valued attributes
"""
from __future__ import absolute_import

from ldap import ldapobject
from ldap import RES_ANY
from ldap import RES_SEARCH_ENTRY

import ipdb

ENCODING = "utf8"


BINARY_ATTRIBUTES=(
    'jpegPhoto', 'description'
)

BOOLEAN_ATTRIBUTES=(
)

SINGLE_VALUED=(
    'userPassword', 'domainComponent', 'description'
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
 # convert bytearray to string (maybe base64) --- check
 # return values only for single valued attributes --- check

    def simple_bind(self, who='', cred='', serverctrls=None, clientctrls=None):
        who = self._encode(who)
        cred = self._encode(cred)
        return ldapobject.ReconnectLDAPObject.simple_bind(self,
                who, cred, serverctrls, clientctrls)

    def whoami_s(self):
        result = ldapobject.ReconnectLDAPObject.whoami_s(self)
        return self._decode(result)

    def delete_ext(self, dn, serverctrls=None, clientctrls=None):
        dn = self._encode(dn)
        return ldapobject.ReconnectLDAPObject.delete_ext(
            self, dn, serverctrls, clientctrls)

    def add_ext(self, dn, modlist, serverctrls=None, clientctrls=None):
        dn = self._encode(dn)
        modlist = self._encodeaddlist(modlist)
        return ldapobject.ReconnectLDAPObject.add_ext(self, dn,
                                                   modlist,
                                                   serverctrls, clientctrls)

    def search(self, base, scope, filterstr='(objectClass=*)', attrlist=None,
                attrsonly=0):
        base = self._encode(base)
        filterstr = self._encode(filterstr)
        attrlist = self._encode_listorvalue(attrlist)
        #XXX test filterstr and attrlist!
        """asynchronous ldap search returning a generator
        """
        msgid = ldapobject.ReconnectLDAPObject.search(self, base, scope,
                                        filterstr=filterstr, attrlist=attrlist)
        rtype = RES_SEARCH_ENTRY
        while rtype is RES_SEARCH_ENTRY:
            # Fetch results single file, the final result (usually)
            # has an empty field. <sigh>
            (rtype, data) = ldapobject.ReconnectLDAPObject.result(self,
                                               msgid=msgid, all=0, timeout=-1)
            if rtype is RES_SEARCH_ENTRY or data:
                yield self._decode_search(data)

    def search_ext_s(self, base, scope, filterstr='(objectClass=*)',
                   attrlist=None, attrsonly=0, serverctrls=None,
                   clientctrls=None, timeout=-1, sizelimit=0):
        base = self._encode(base)
        filterstr = self._encode(filterstr)
        attrlist = self._encode_listorvalue(attrlist)
        #XXX test filterstr and attrlist!
        result = ldapobject.ReconnectLDAPObject.search_ext_s(self,
                                                             base,
                                                             scope,
                                                             filterstr,
                                                             attrlist,
                                                             attrsonly,
                                                             serverctrls,
                                                             clientctrls,
                                                             timeout, sizelimit)
        return self._decode_search(result)

    def modify_ext(self, dn, modlist, serverctrls=None, clientctrls=None):
        dn = self._encode(dn)
        modlist = self._encodemodifylist(modlist)
        return ldapobject.ReconnectLDAPObject.modify_ext(self, dn,
                                                         modlist,
                                                         serverctrls,
                                                         clientctrls)


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

    def _decode_list(self, key, inputlist):
        """ encodes return values to unicode and returns single
            element if list contains only one element
        """
        for index, x in enumerate(inputlist):
            if key in BINARY_ATTRIBUTES:
                #XXX check which attrs other then certificates
                #    should be converted
                x = bytearray(x)
            inputlist[index] = self._decode(x)
        if key in SINGLE_VALUED:
            #XXX determine if single-valued attribute over schema
            return inputlist[0]
        return inputlist

    def _decode_search(self, result):
        for index, x in enumerate(result):
            if isinstance (x, tuple):
                d = dict()
                for key, value in x[1].iteritems():
                    new_key = self._decode(key)
                    new_value = self._decode_list(key, value)
                    d[new_key] = new_value
                result[index] = (self._decode(x[0]), d)
        return result
