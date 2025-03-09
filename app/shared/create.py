import requests
from abc import ABC

from app.models.models import Cert, CertChain, ISO15118CertBundle

headers = {
    'accept':       'application/json',
    'X-API-KEY':    'iamadmin',
    'Content-Type': 'application/json',
}

class CertCreate(ABC):
    cert = None

    def __init__(self, cert: Cert):
        self.cert = cert

    def issue(self, ca_url: str) -> str:
        r = requests.post(ca_url, headers=headers, data=self.cert.model_dump_json())
        res_data = r.json()
        serial = res_data["serial"]
        return serial
    
class CertChainCreate(ABC):
    def __init__(self, chain: CertChain, ca_url: str):
        self.chain = chain
        self.ca_url = ca_url

    def issue(self) -> dict:
        res = dict()
        if self.chain.rootca:
            rootca_create = CertCreate(cert=self.chain.rootca)
            res["rootca"] = rootca_create.issue(ca_url = self.ca_url+"/rootca")
            self.chain.subca1.issuer_serial = res["rootca"]
        else:
            res["rootca"] = self.chain.subca1.issuer_serial
        if self.chain.subca1:
            subca1_create = CertCreate(cert=self.chain.subca1)
            res["subca1"] = subca1_create.issue(ca_url = self.ca_url+"/subca")
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
            res["subca2"] = subca2_create.issue(ca_url = self.ca_url+"/subca")
            self.chain.leaf.issuer_serial = res["subca2"]
        else:
            res["subca2"] = self.chain.leaf.issuer_serial
        leaf_create = CertCreate(cert=self.chain.leaf)
        leaf_serial = leaf_create.issue(ca_url = self.ca_url+"/leaf")
        res["leaf"] = leaf_serial
        return res

class ISO15118CertBundleCreate(ABC):
    def __init__(self, bundle: ISO15118CertBundle, ca_url: str):
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
            leaf_serial = leaf_create.issue(ca_url = self.ca_url+"/leaf")
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
            leaf_serial = leaf_create.issue(ca_url = self.ca_url+"/leaf")
            res["CSMS_CLIENT"]["leaf"] = leaf_serial
        return res