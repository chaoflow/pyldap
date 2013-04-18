from __future__ import absolute_import

from . import unittest
from . import mixins


class SlapdTestCase(mixins.Slapd, unittest.TestCase):
    pass
