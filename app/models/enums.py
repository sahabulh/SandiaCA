from enum import Enum, StrEnum

class CertFormat(Enum):
    PEM = 0
    DER = 1

class ValidityStart(Enum):
    NOW = 0
    PAST = 1
    FUTURE = 2

class ExtendedKeyUsage(StrEnum):
    OCSP_SIGNING = "ocsp_signing"
    SERVER_AUTH = "server_auth"
    CLIENT_AUTH = "client_auth"