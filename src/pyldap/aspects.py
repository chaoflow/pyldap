from __future__ import absolute_import

from metachao import aspect
from metachao.aspect import Aspect

from ldap import RES_ANY
from ldap import RES_SEARCH_ENTRY
from ldap import SCOPE_BASE


from . import config


class pythonise(Aspect):
    """
    Encode/Decode unicode to/from utf8
    ----------------------------------

    LDAP is a string-based protocol and at least openldap uses the
    utf8 encoding. `python-ldap` simply passes these strings on.

    We don't want to care about the LDAP encoding and would like
    unicode instead, for all strings that are really strings.

    """
    @aspect.plumb
    def simple_bind(_next, self, who='', cred='',
                    serverctrls=None, clientctrls=None):
        who = self._encode(who)
        cred = self._encode(cred)
        return _next( who, cred, serverctrls, clientctrls)

    @aspect.plumb
    def whoami_s(_next, self):
        result = _next()
        return self._decode(result)

    @aspect.plumb
    def delete_ext(_next, self, dn, serverctrls=None, clientctrls=None):
        dn = self._encode(dn)
        return _next(dn, serverctrls, clientctrls)

    @aspect.plumb
    def add_ext(_next, self, dn, modlist, serverctrls=None, clientctrls=None):
        dn = self._encode(dn)
        modlist = self._encodeaddlist(modlist)
        return _next(dn, modlist, serverctrls, clientctrls)

    @aspect.plumb
    def search(_next, self, base, scope,
               filterstr='(objectClass=*)', attrlist=None,
                attrsonly=0):
        """asynchronous ldap search returning a generator
        """
        base = self._encode(base)
        filterstr = self._encode(filterstr)
        attrlist = self._encode_listorvalue(attrlist)
        #XXX test filterstr and attrlist!
        msgid_res = _next(base, scope, filterstr=filterstr, attrlist=attrlist)
        rtype = RES_SEARCH_ENTRY
        while rtype is RES_SEARCH_ENTRY:
            # Fetch results single file, the final result (usually)
            # has an empty field. <sigh>
            (rtype, data) = self.result(msgid=msgid_res,
                                        all=0, timeout=-1)
            if rtype is RES_SEARCH_ENTRY or data:
                yield self._decode_search(data)

    @aspect.plumb
    def search_ext_s(_next, self, base, scope, filterstr='(objectClass=*)',
                   attrlist=None, attrsonly=0, serverctrls=None,
                   clientctrls=None, timeout=-1, sizelimit=0):
        base = self._encode(base)
        filterstr = self._encode(filterstr)
        attrlist = self._encode_listorvalue(attrlist)
        #XXX test filterstr and attrlist!
        result = _next(base, scope, filterstr, attrlist, attrsonly,
                       serverctrls, clientctrls, timeout, sizelimit)
        return self._decode_search(result)

    @aspect.plumb
    def modify_ext(_next, self, dn, modlist,
                   serverctrls=None, clientctrls=None):
        dn = self._encode(dn)
        modlist = self._encodemodifylist(modlist)
        return _next(dn, modlist, serverctrls, clientctrls)

    @aspect.plumb
    def result(_next, self, msgid=RES_ANY, all=0, timeout=None):
        return _next(msgid, all, timeout)

#-----------------------------------------------------------------------------
    def _encode(self, s):
        if isinstance(s, unicode):
            return s.encode(config.ENCODING)
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
            return s.decode(config.ENCODING)
        return s


    def _decode_list(self, key, inputlist):
        result = []
        if key in config.BLOCKED_OUTGOING_ATTRIBUTES:
            return result
        for x in inputlist:
            if key in config.BOOLEAN_ATTRIBUTES:
                result.append(x in config.POSITIVE_BOOLEAN_VALUES)
            else:
                if key in config.BINARY_ATTRIBUTES:
                    x = bytearray(x)
                result.append(self._decode(x))
        if key in config.SINGLE_VALUED and len(result)>0:
            #XXX determine if single-valued attribute over schema
            return result[0]
        return result

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


# XXX fill SINGLE_VALUED --------------------------------------------------

    def _get_single_valued(self):
        result = self.search_s('cn=subschema', SCOPE_BASE,
                                 attrlist=['*', '+'])[0]
        attributelist = result[1]['attributeTypes']
        singlelist = [self._extract_att_name(x, 'NAME ')
                      for x in attributelist if 'SINGLE-VALUE' in x]
        singlelist = self._get_atts(singlelist)
        return singlelist
       # "( 2.5.21.9 NAME 'structuralObjectClass'
       # DESC 'RFC4512: structural object class of entry'
       #       EQUALITY objectIdentifierMatch
       # SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
       # SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )"

    def _extract_att_name(self, raw_string, start_marker):
        MARKERS = ('DESC', 'EQUALITY', 'SYNTAX', 'SUP')
        start = raw_string.index(start_marker) + len(start_marker)
        for marker in MARKERS:
            if marker in raw_string:
                end = raw_string.index(' ' + marker, start)
                break
        return raw_string[start:end]

    def _get_atts(self, attrlist):
        for index, x in enumerate(attrlist):
            if '(' in x:
                x = x.strip('(')
                x = x.strip(')')
                x = x.strip()
                arr = x.split()
                attrlist[index] = self._encode(arr[0])
                for att in arr[1:]:
                    attrlist.append(self._encode(att))
            else:
                attrlist[index] = self._encode(x)
        return attrlist
