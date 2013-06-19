"""monkey patch this!
"""


ENCODING = "utf8"


BLOCKED_OUTGOING_ATTRIBUTES = [
    'userPassword',
]

BINARY_ATTRIBUTES = [
    'jpegPhoto'
]

# allows other positive flags, ie 1 etc.
POSITIVE_BOOLEAN_VALUES = [
    'True'
]

BOOLEAN_ATTRIBUTES = (
    'dereferenceAliases'
)

SINGLE_VALUED = [
    'domainComponent', 'description'
]
