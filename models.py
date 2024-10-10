from pydantic import BaseModel
from typing import List, Tuple, NamedTuple, Optional

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
    ca: bool = False
    pathLength: Optional[int] = None

class Validity(NamedTuple):
    years: int = 0
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

class CryptoProfileCreate(CryptoProfile):
    name: str
    key_algorithm: str
    signature_hash: str

class EntityProfileCreate(BaseModel):
    name: str
    key_usage: KeyUsage = KeyUsage()
    extended_key_usage: Optional[List[str]] = None
    basic_constraints: BasicConstraints = BasicConstraints()
    validity: Validity = Validity()

class Profile(BaseModel):
    crypto_profile_name: Optional[str] = None
    entity_profile_name: str

class Cert(BaseModel):
    domain: str
    profile: Profile

class RootCert(Cert):
    pass

class SubCACert(Cert):
    issuer_serial: str
    tier: int

class OCSPCert(Cert):
    domain: str = "OCSP"
    issuer_serial: str

class LeafCert(Cert):
    issuer_serial: str
    name: str

class CertInfo(BaseModel):
    serial: str
    key: str
    issuer: str
    responder: Optional[str] = None
    status: int
    revocation_time: Optional[str] = None
    profile: Profile