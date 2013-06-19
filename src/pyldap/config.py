"""monkey patch this!
"""


ENCODING = "utf8"


BLOCKED_OUTGOING_ATTRIBUTES = [
    'userPassword',
]

BINARY_ATTRIBUTES = [
    'jpegPhoto'
]

BOOLEAN_ATTRIBUTES = [
    'dereferenceAliases', 'followReferrals'
]

# allows other positive flags, ie 1 etc.
POSITIVE_BOOLEAN_VALUES = [
    'TRUE'
]

SINGLE_VALUED = [
    'domainComponent', 'description'
]
