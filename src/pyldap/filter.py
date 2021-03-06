# -*- coding: utf-8 -*-


# all special characters except * are escaped, that means * can be
# used to perform suffix/prefix/contains searches, monkey-patch if you
# don't like
ESCAPE_CHARS = {
    #'*': '\\2a',
    '(': '\\28',
    ')': '\\29',
    '/': '\\2f',
    '\\': '\\5c',
    '\x00': '\\00',
}


def escape_some_special_chars(value):
    return map(lambda x: ESCAPE_CHARS.get(x, x), value)


class LDAPFilter(object):
    def __init__(self, queryFilter=None):
        if queryFilter is not None \
                and not isinstance(queryFilter, basestring) \
                and not isinstance(queryFilter, LDAPFilter):
            raise TypeError('Query filter must be LDAPFilter or string')
        self._filter = queryFilter
        if isinstance(queryFilter, LDAPFilter):
            self._filter = unicode(queryFilter)

    def __and__(self, other):
        if other is None:
            return self
        res = ''
        if isinstance(other, LDAPFilter):
            other = unicode(other)
        elif not isinstance(other, basestring):
            raise TypeError(u"unsupported operand type")
        us = unicode(self)
        if us and other:
            res = '(&%s%s)' % (us, other)
        elif us:
            res = us
        elif other:
            res = other
        return LDAPFilter(res)

    def __or__(self, other):
        if other is None:
            return self
        res = ''
        if isinstance(other, LDAPFilter):
            other = unicode(other)
        elif not isinstance(other, basestring):
            raise TypeError(u"unsupported operand type")
        us = unicode(self)
        if us and other:
            res = '(|%s%s)' % (us, other)
        return LDAPFilter(res)

    def __contains__(self, attr):
        attr = '(%s=' % (attr,)
        return attr in self._filter

    def __str__(self):
        return self._filter and self._filter or ''

    def __repr__(self):
        return "LDAPFilter('%s')" % (self._filter,)


class LDAPDictFilter(LDAPFilter):
    def __init__(self, criteria, or_search=False, or_keys=None,
                 or_values=None):
        self.criteria = criteria
        self.or_search = or_search
        self.or_keys = or_keys
        self.or_values = or_values

    def __str__(self):
        if not self.criteria:
            return ''
        return unicode(dict_to_filter(self.criteria,
                                  or_search=self.or_search,
                                  or_keys=self.or_keys,
                                  or_values=self.or_values))

    def __repr__(self):
        return "LDAPDictFilter(criteria=%r)" % (self.criteria,)


class LDAPRelationFilter(LDAPFilter):
    """XXX: WARNING: THIS SEEMS BROKEN
    """

    def __init__(self, node, relation, or_search=True):
        self.relation = relation
        self.gattrs = node.attrs
        self.or_search = or_search

    def __str__(self):
        """turn relation string into ldap filter string
        """
        _filter = LDAPFilter()
        dictionary = dict()

        parsedRelation = dict()
        for pair in self.relation.split('|'):
            k, _, v = pair.partition(':')
            if not k in parsedRelation:
                parsedRelation[k] = list()
            parsedRelation[k].append(v)

        existing = [k for k in self.gattrs]
        for k, vals in parsedRelation.items():
            for v in vals:
                if str(v) == '' \
                   or str(k) == '' \
                   or str(k) not in existing:
                    continue
                dictionary[str(v)] = self.gattrs[str(k)]

        self.dictionary = dictionary

        if len(dictionary) is 1:
            _filter = LDAPFilter(self.relation)
        else:
            _filter = dict_to_filter(parsedRelation, self.or_search)

        return self.dictionary and \
            unicode(dict_to_filter(self.dictionary, self.or_search)) or ''

    def __repr__(self):
        return "LDAPRelationFilter('%s')" % (unicode(self),)


def dict_to_filter(dct):
    """Turn dictionary criteria into ldap queryFilter string

    Within a dictionary all things are combined with AND. Use a list
    of dictionaries to OR (see criteria_to_filter)

    ! as value prefix negates
    """
    _filter = None
    for attr, values in dct.items():
        attr = ''.join(escape_some_special_chars(attr))
        if not isinstance(values, (list, tuple)):
            values = [values]
        attrfilter = None
        for value in values:
            negate_value = False
            if isinstance(value, basestring):
                if value[0] == "!":
                    negate_value = True
                    value = value[1:]
                value = ''.join(escape_some_special_chars(value))
            valuefilter = '(%s=%s)' % (attr, value)
            if negate_value:
                valuefilter = '(!%s)' % (valuefilter,)
            if attrfilter is None:
                attrfilter = LDAPFilter(valuefilter)
                continue
            attrfilter &= valuefilter
        if _filter is None:
            _filter = attrfilter
            continue
        _filter &= attrfilter
    if _filter is None:
        _filter = LDAPFilter()
    return _filter


def criteria_to_filter(criteria):
    if isinstance(criteria, dict):
        return dict_to_filter(criteria)

    if isinstance(criteria, (list, tuple)):
        return reduce(lambda acc, x: acc | x,
                      (dict_to_filter(x) for x in criteria))

    raise ValueError("Unknown criteria type. Need dict or list of dicts")
