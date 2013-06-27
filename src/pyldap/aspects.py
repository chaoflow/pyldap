from __future__ import absolute_import

from metachao import aspect
from metachao.aspect import Aspect

from ldap import RES_ANY
from ldap import RES_SEARCH_ENTRY

#import tpv
#from tpv import ordereddict
from tpv.ordereddict import OrderedDict

from . import config


class async_search_returns_generator(Aspect):

    @aspect.plumb
    def search_ext(_next, self, base, scope, filterstr='(objectClass=*)',
                   attrlist=None, attrsonly=0, serverctrls=None,
                   clientctrls=None, timeout=-1, sizelimit=0):
        msgid_res = _next(base, scope, filterstr, attrlist, attrsonly,
                          serverctrls, clientctrls, timeout, sizelimit)
        rtype = RES_SEARCH_ENTRY
        while rtype is RES_SEARCH_ENTRY:
            # Fetch results single file, the final result (usually)
            # has an empty field. <sigh>
            (rtype, data) = self.result(msgid=msgid_res,
                                        all=0, timeout=-1)
            if rtype is RES_SEARCH_ENTRY or data:
                yield data

    @aspect.plumb
    def search_ext_s(_next, self, base, scope, filterstr='(objectClass=*)',
                     attrlist=None, attrsonly=0, serverctrls=None,
                     clientctrls=None, timeout=-1, sizelimit=0):
        return [x[0] for x in self.search_ext(base, scope, filterstr, attrlist,
                                              attrsonly, serverctrls,
                                              clientctrls, timeout, sizelimit)]


class type_conversion(Aspect):
    """
    Encode/Decode unicode to/from utf8
    ----------------------------------

    LDAP is a string-based protocol and at least openldap uses the
    utf8 encoding. `python-ldap` simply passes these strings on.

    We don't want to care about the LDAP encoding and would like
    unicode instead, for all strings that are really strings.

    We also want to convert incoming boolean and binary to strings
    for LDAP and vice versa.
    """
    @aspect.plumb
    def simple_bind(_next, self, who='', cred='',
                    serverctrls=None, clientctrls=None):
        who = self._encode(who)
        cred = self._encode(cred)
        return _next(who, cred, serverctrls, clientctrls)

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
    def modify_ext(_next, self, dn, modlist,
                   serverctrls=None, clientctrls=None):
        dn = self._encode(dn)
        modlist = self._encodemodifylist(modlist)
        return _next(dn, modlist, serverctrls, clientctrls)

    @aspect.plumb
    def search_ext(_next, self, base, scope, filterstr='(objectClass=*)',
                   attrlist=None, attrsonly=0, serverctrls=None,
                   clientctrls=None, timeout=-1, sizelimit=0):
        base = self._encode(base)
        filterstr = self._encode(filterstr)
        attrlist = self._encode_listorvalue(listorvalue=attrlist)
        #XXX test filterstr and attrlist!
        return _next(base, scope, filterstr, attrlist, attrsonly,
                     serverctrls, clientctrls, timeout, sizelimit)

    @aspect.plumb
    def rename(_next, self, dn, newrdn, newsuperior=None, delold=1,
               serverctrls=None, clientctrls=None):
        dn = self._encode(dn)
        newrdn = self._encode(newrdn)
        return _next(dn, newrdn, newsuperior, delold, serverctrls, clientctrls)

    @aspect.plumb
    def passwd(_next, self, user, oldpw, newpw,
               serverctrls=None, clientctrls=None):
        user = self._encode(user)
        oldpw = self._encode(oldpw)
        newpw = self._encode(newpw)
        return _next(user, oldpw, newpw, serverctrls, clientctrls)

    @aspect.plumb
    def result4(_next, self, msgid=RES_ANY, all=1, timeout=None,
                add_ctrls=0, add_intermediates=0, add_extop=0,
                resp_ctrl_classes=None):
        result = _next(msgid, all, timeout, add_ctrls,
                       add_intermediates, add_extop, resp_ctrl_classes)
        return self._decode_search(result)

#-----------------------------------------------------------------------------
    def _encode(self, s):
        if isinstance(s, unicode):
            return s.encode(config.ENCODING)
        return s

    def _encodeaddlist(self, modlist):
        result = [(self._encode(x[0]),
                   self._encode_listorvalue(x[0], x[1]))
                  for x in modlist]
        return result

    def _encodemodifylist(self, modlist):
        result = [(x[0],
                   self._encode(x[1]),
                   self._encode_listorvalue(x[1], x[2]))
                  for x in modlist]
        return result

    def _encode_listorvalue(self, key='', listorvalue=None):
        if listorvalue is None:
            return None
        if key in config.BOOLEAN_ATTRIBUTES:
            if (listorvalue):
                return 'TRUE'
            return 'FALSE'
        if isinstance(listorvalue, list):
            for index, x in enumerate(listorvalue):
                if key in config.BINARY_ATTRIBUTES:
                    x = self._decodebinary(x)
                listorvalue[index] = self._encode(x)
        else:
            if key in config.BINARY_ATTRIBUTES:
                listorvalue = self._decodebinary(listorvalue)
            listorvalue = self._encode(listorvalue)
        return listorvalue

    def _decode(self, s):
        if isinstance(s, str):
            return s.decode(config.ENCODING)
        return s

    def _decodebinary(self, binary):
        return binary.decode()

    def _decode_list(self, key, inputlist):
        if key in config.BOOLEAN_ATTRIBUTES:
            # boolean attributes are single valued
            return inputlist[0] == 'TRUE'
        result = []
        for x in inputlist:
            if key in config.BINARY_ATTRIBUTES:
                x = bytearray(x)
            result.append(self._decode(x))
        return result

    def _decode_search(self, result):
        node = []
        for x in result[1]:
            if isinstance(x, tuple):
                d = dict()
                for key, value in x[1].iteritems():
                    new_key = self._decode(key)
                    new_value = self._decode_list(new_key, value)
                    d[new_key] = new_value
                    x = (self._decode(x[0]), d)
            node.append(x)
        return (result[0], node, result[2], result[3], result[4], result[5])


class block_attributes(Aspect):

    @aspect.plumb
    def result4(_next, self, msgid=RES_ANY, all=1, timeout=None,
                add_ctrls=0, add_intermediates=0, add_extop=0,
                resp_ctrl_classes=None):
        result = _next(msgid, all, timeout, add_ctrls,
                       add_intermediates, add_extop, resp_ctrl_classes)
        return self._block_attributes(result)

    def _block_attributes(self, result):
        for x in result[1]:
            for key in x[1].keys():
                if key in config.BLOCKED_OUTGOING_ATTRIBUTES:
                    del x[1][key]
        return result


class single_values_as_scalars(Aspect):

    @aspect.plumb
    def result4(_next, self, msgid=RES_ANY, all=1, timeout=None,
                add_ctrls=0, add_intermediates=0, add_extop=0,
                resp_ctrl_classes=None):
        result = _next(msgid, all, timeout, add_ctrls,
                       add_intermediates, add_extop, resp_ctrl_classes)
        return self._single_values_as_scalars(result)

    def _single_values_as_scalars(self, result):
        for x in result[1]:
            for key in x[1].keys():
                if (key in config.SINGLE_VALUED):
                    #XXX determine if single-valued attribute over schema
                    if isinstance(x[1][key], list) and len(x[1][key]) > 0:
                        x[1][key] = x[1][key][0]
        return result


class attribute_name_mapping_base(Aspect):
    @property
    def incoming_attribute_map(self):
        return dict(self.attribute_name_map or ())

    @property
    def outgoing_attribute_map(self):
        return dict((v, k) for k, v in (self.attribute_name_map or ()))


class attribute_name_mapping(attribute_name_mapping_base):
    @property
    def attribute_name_map(self):
        return self.directory.attribute_name_map

    @aspect.plumb
    def __getitem__(_next, self, key):
        key = self.incoming_attribute_map.get(key, key)
        value = _next(key)
        return value

    @aspect.plumb
    def __setitem__(_next, self, key, value):
        key = self.incoming_attribute_map.get(key, key)
        return _next(key, value)

    @aspect.plumb
    def iteritems(_next, self):
        return ((self.outgoing_attribute_map.get(k, k), v) for k, v in _next())

    def items(self):
        return self.iteritems()

    @aspect.plumb
    def update(_next, self, attributes):
        attributes = OrderedDict(
            (self.incoming_attribute_map.get(k, k), v)
            for k, v in attributes.items()
        )
        return _next(attributes)


class children_attribute_name_mapping(attribute_name_mapping_base):
    attribute_name_map = aspect.aspectkw(None)

    @aspect.plumb
    def add(_next, self, attributes):
        attributes = OrderedDict(
            (self.incoming_attribute_map.get(k, k), v)
            for k, v in attributes.items()
        )
        return _next(attributes)

    # @aspect.plumb
    # def __getitem__(_next, self, key):
    #     node = _next(key)
    #     if self.attribute_name_map:
    #         dn = node.dn
    #         id = node._id
    #         node = attribute_name_mapping(
    #             node,
    #             attribute_name_map=self.attribute_name_map,
    #         )
    #         node.dn = dn
    #         node._id = id
    #     return node

    @aspect.plumb
    def search(_next, self, criteria=None, base_criteria=None, **kw):
        if criteria is not None:
            criteria = [dict((self.incoming_attribute_map.get(k, k), v)
                             for k, v in crit.items())
                        for crit in criteria]
        if base_criteria is not None:
            base_criteria = [dict((self.incoming_attribute_map.get(k, k), v)
                                  for k, v in crit.items())
                             for crit in base_criteria]
        return _next(criteria=criteria, base_criteria=base_criteria, **kw)

    # XXX: we need a way to block this, but let add from earlier
    # on use the unblocked version. Actually @add should take care
    # of that
    # @aspect.plumb
    # def __setitem__(_next, self, key, value):
    #     pass
