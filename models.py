from pydantic import BaseModel
from typing import List, Tuple, NamedTuple, Optional
import requests
from abc import ABC

headers = {
    'accept':       'application/json',
    'X-API-KEY':    'iamadmin',
    'Content-Type': 'application/json',
}

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
    ocsp_url: Optional[str] = None

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
    ocsp_url: Optional[str] = "http://127.0.0.1:8001"

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

class CertCreate(ABC):
    cert = None

    def __init__(self, cert: Cert):
        self.cert = cert

    def issue(self, ca_url) -> str:
        r = requests.post(ca_url, headers=headers, data=self.cert.model_dump_json())
        res_data = r.json()
        serial = res_data["serial"]
        return serial
    
class CertChainCreate(ABC):
    def __init__(self, chain: CertChain, ca_url = "http://127.0.0.1:8000/"):
        self.chain = chain
        self.ca_url = ca_url

    def issue(self) -> dict:
        res = dict()
        if self.chain.rootca:
            rootca_create = CertCreate(cert=self.chain.rootca)
            res["rootca"] = rootca_create.issue(ca_url = self.ca_url+"rootca")
            self.chain.subca1.issuer_serial = res["rootca"]
        else:
            res["rootca"] = self.chain.subca1.issuer_serial
        if self.chain.subca1:
            subca1_create = CertCreate(cert=self.chain.subca1)
            res["subca1"] = subca1_create.issue(ca_url = self.ca_url+"subca")
            if self.chain.subca2:
                self.chain.subca2.issuer_serial = res["subca1"]
            else:
                self.chain.leaf.issuer_serial = res["subca1"]
        else:
            if self.chain.subca2:
                res["subca1"] = self.chain.subca2.issuer_serial
            else:
                res["subca1"] = self.chain.leaf.issuer_serial
        if self.chain.subca2:
            subca2_create = CertCreate(cert=self.chain.subca2)
            res["subca2"] = subca2_create.issue(ca_url = self.ca_url+"subca")
            self.chain.leaf.issuer_serial = res["subca2"]
        else:
            res["subca2"] = self.chain.leaf.issuer_serial
        leaf_create = CertCreate(cert=self.chain.leaf)
        leaf_serial = leaf_create.issue(ca_url = self.ca_url+"leaf")
        res["leaf"] = leaf_serial
        return res

class ISO15118CertBundleCreate(ABC):
    def __init__(self, bundle: ISO15118CertBundle, ca_url = "http://127.0.0.1:8000/"):
        self.bundle = bundle
        self.ca_url = ca_url

    def issue(self) -> dict:
        res = dict()
        CPO = CertChainCreate(self.bundle.CPO, self.ca_url)
        res["CPO"] = CPO.issue()
        if self.bundle.MO:
            MO = CertChainCreate(self.bundle.MO, self.ca_url)
            if not MO.chain.rootca:
                MO.chain.subca1.issuer_serial = res["CPO"]["rootca"]
            res["MO"] = MO.issue()
        if self.bundle.OEM:
            OEM = CertChainCreate(self.bundle.OEM, self.ca_url)
            if not OEM.chain.rootca:
                OEM.chain.subca1.issuer_serial = res["CPO"]["rootca"]
            res["OEM"] = OEM.issue()
        if self.bundle.CSMS_SERVER:
            res["CSMS_SERVER"] = {"rootca": res["CPO"]["rootca"], "subca1": res["CPO"]["subca1"]}
            leaf_model = self.bundle.CSMS_SERVER.leaf
            if CPO.chain.subca2:
                leaf_model.issuer_serial = res["CPO"]["subca2"]
                res["CSMS_SERVER"]["subca2"] = res["CPO"]["subca2"]
            else:
                leaf_model.issuer_serial = res["CPO"]["subca1"]
            leaf_create = CertCreate(cert=leaf_model)
            leaf_serial = leaf_create.issue(ca_url = self.ca_url+"leaf")
            res["CSMS_SERVER"]["leaf"] = leaf_serial
        if self.bundle.CSMS_CLIENT:
            res["CSMS_CLIENT"] = {"rootca": res["CPO"]["rootca"], "subca1": res["CPO"]["subca1"]}
            leaf_model = self.bundle.CSMS_CLIENT.leaf
            if CPO.chain.subca2:
                leaf_model.issuer_serial = res["CPO"]["subca2"]
                res["CSMS_CLIENT"]["subca2"] = res["CPO"]["subca2"]
            else:
                leaf_model.issuer_serial = res["CPO"]["subca1"]
            leaf_create = CertCreate(cert=leaf_model)
            leaf_serial = leaf_create.issue(ca_url = self.ca_url+"leaf")
            res["CSMS_CLIENT"]["leaf"] = leaf_serial
        return res