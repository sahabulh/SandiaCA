from pydantic import BaseModel
from typing import List, NamedTuple, Optional, Union
from datetime import datetime

class KeyUsage(NamedTuple):
    digitalSignature: bool = False
    nonRepudiation: bool = False
    keyEncipherment: bool = False
    dataEncipherment: bool = False
    keyAgreement: bool = False
    keyCertSign: bool = False
    cRLSign: bool = False
    encipherOnly: bool = False
    decipherOnly: bool = False

class BasicConstraints(NamedTuple):
    """
    Identifies whether the subject of the certificate is a CA and the maximum
    depth of valid certification paths that include this certificate. See RFC
    5280 for more information.
    """

    ca: bool = False
    """Indicates whether the certified public key may be used to verify
    certificate signatures."""

    pathLength: Optional[int] = None
    """Gives the maximum number of non-self-issued intermediate certificates
    that may follow this certificate in a valid certification path."""

class Validity(NamedTuple):
    years: int = 1
    months: int = 0
    days: int = 0

class CryptoProfile(BaseModel):
    name: Optional[str] = None
    key_algorithm: Optional[str] = None
    signature_hash: Optional[str] = None

class EntityProfile(BaseModel):
    name: Optional[str] = None
    key_usage: Optional[KeyUsage] = None
    extended_key_usage: Optional[List[str]] = None
    basic_constraints: Optional[BasicConstraints] = None
    validity: Optional[Validity] = None
    ocsp_url: Optional[str] = None
    crl_url: Optional[str] = None

class CryptoProfileCreate(CryptoProfile):
    name: str
    key_algorithm: str
    signature_hash: str

class EntityProfileCreate(EntityProfile):
    name: str
    key_usage: KeyUsage = KeyUsage()
    extended_key_usage: Optional[List[str]] = None
    basic_constraints: BasicConstraints = BasicConstraints()
    validity: Validity = Validity()
    ocsp_url: Optional[str] = None
    crl_url: Optional[str] = None

class EntityProfileTest(BaseModel):
    name: str
    validity: Validity = Validity()

    key_usage: Optional[KeyUsage] = None
    extended_key_usage: Optional[List[str]] = None
    basic_constraints: Optional[BasicConstraints] = None
    ocsp_url: Optional[str] = None
    crl_url: Optional[str] = None

class Profile(BaseModel):
    crypto_profile_name: Optional[str] = None
    entity_profile_name: str

class Cert(BaseModel):
    domain: str
    profile: Profile

class RootCert(Cert):
    domain: str = "V2G"

class SubCACert(Cert):
    issuer_serial: str
    tier: int = 1

class OCSPCert(Cert):
    domain: str = "OCSP"
    issuer_serial: str

class LeafCert(Cert):
    issuer_serial: str
    name: str

class Extension(BaseModel):
    value: Optional[Union[str, BasicConstraints, KeyUsage]] = None
    critical: bool

class Dates(BaseModel):
    start: str = "now"
    duration: Validity = Validity()

class TestCert(BaseModel):
    """
    Certificate model for test certificate generation.
    """

    name: str
    dates: Dates
    issuer_serial: Optional[str] = None
    domain: Optional[str] = None
    key_algorithm: Optional[str] = "secp256r1"
    signature_hash: Optional[str] = "sha256"
    subject_key_identifier: Optional[Extension] = None
    authority_key_identifier: Optional[Extension] = None
    basic_constraints: Optional[Extension] = None
    key_usage: Optional[Extension] = None
    extended_key_usage: Optional[Extension] = None
    ocsp_url: Optional[Extension] = None
    crl_url: Optional[Extension] = None

class CertInfo(BaseModel):
    serial: str
    key: str
    issuer: str
    responder: Optional[str] = None
    status: int
    revocation_time: Optional[str] = None
    profile: Profile

class CertChain(BaseModel):
    rootca: RootCert | None
    subca1: SubCACert | None
    subca2: SubCACert | None
    leaf: LeafCert | None

class ISO15118CertBundle(BaseModel):
    CPO: CertChain
    MO: CertChain | None
    OEM: CertChain | None
    CSMS_SERVER: CertChain | None
    CSMS_CLIENT: CertChain | None
    
class RevokedCert(BaseModel):
    serial: int
    revocation_date: datetime