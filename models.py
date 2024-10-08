from pydantic import BaseModel
from typing import List, Tuple, NamedTuple, Optional

class RootCert(BaseModel):
    domain: str

class SubCACert(BaseModel):
    issuer_serial: str
    domain: str
    tier: int

class OCSPCert(BaseModel):
    issuer_serial: str

class LeafCert(BaseModel):
    issuer_serial: str
    domain: str
    name: str

class KeyUsage(NamedTuple):
    digitalSignature: bool
    nonRepudiation: bool
    keyEncipherment: bool
    dataEncipherment: bool
    keyAgreement: bool
    keyCertSign: bool
    cRLSign: bool
    encipherOnly: bool
    decipherOnly: bool

class BasicConstraints(NamedTuple):
    ca: bool
    pathLength: Optional[int] = None

class CryptoProfile(BaseModel):
    name: str
    key_algorithm: str
    signature_hash: str

class EntityProfile(BaseModel):
    name: str
    key_usage: KeyUsage
    extended_key_usage: Optional[List[str]] = None
    basic_constraints: BasicConstraints

class Profile(BaseModel):
    crypto_profile: CryptoProfile
    entity_profile: EntityProfile