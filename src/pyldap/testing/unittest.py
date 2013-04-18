"""Wrap unittest2 for python <2.7
"""
from __future__ import absolute_import

import sys


if sys.version_info[0] is 2 and sys.version_info[1] < 7:
    from unittest2 import *
else:
    from unittest import *
