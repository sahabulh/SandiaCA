from enum import Enum

class CertFormat(Enum):
    PEM = 0
    DER = 1

class ValidityStart(Enum):
    NOW = 0
    PAST = 1
    FUTURE = 2