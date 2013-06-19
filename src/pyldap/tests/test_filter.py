from ..testing import unittest

from .. import filter


class TestFilter(unittest.TestCase):
    def test_dict_to_filter(self):
        dct = dict(a=[1, 2], b=['!x', '!y'])
        self.assertEqual(unicode(filter.dict_to_filter(dct)),
                         u'(&(&(a=1)(a=2))(&(!(b=x))(!(b=y))))')

    def test_criteria_to_filter(self):
        criteria = [dict(a=1), dict(b=2)]
        self.assertEqual(unicode(filter.criteria_to_filter(criteria)),
                         u'(|(a=1)(b=2))')
