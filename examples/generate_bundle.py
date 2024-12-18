import requests, sys, os

from abc import ABC
from pathlib import Path
abs_path = str(Path(__file__).absolute().parent.parent)
sys.path.append(abs_path)

from typing import Tuple

import models
from generate_profiles import create_crypto_profile, create_entity_profiles

headers = {
    'accept':       'application/json',
    'X-API-KEY':    'iamadmin',
    'Content-Type': 'application/json',
}

crypto_profile = "secp256r1_sha256"
ca_url = "http://127.0.0.1:8000/"
ocsp_url = "http://host.docker.internal:8001/"

class EVerestSaver(ABC):
    cert_path_map = {
        "CPO": {
            "rootca": {"path": "ca/v2g/", "name": "V2G_ROOT_CA"},
            "subca1": {"path": "ca/csms/", "name": "CPO_SUB_CA1"},
            "subca2": {"path": "ca/csms/", "name": "CPO_SUB_CA2"},
            "leaf": {"path": "client/cso/", "name": "SECC_LEAF"}
        },
        "MO": {
            "rootca": {"path": "ca/mo/", "name": "MO_ROOT_CA"},
            "subca1": {"path": "ca/mo/", "name": "MO_SUB_CA1"},
            "subca2": {"path": "ca/mo/", "name": "MO_SUB_CA2"},
            "leaf": {"path": "client/mo/", "name": "MO_LEAF"}
        },
        "OEM": {
            "rootca": {"path": "ca/oem/", "name": "OEM_ROOT_CA"},
            "subca1": {"path": "ca/oem/", "name": "OEM_SUB_CA1"},
            "subca2": {"path": "ca/oem/", "name": "OEM_SUB_CA2"},
            "leaf": {"path": "client/oem/", "name": "OEM_LEAF"}
        },
        "CSMS_SERVER": {
            "leaf": {"path": "client/csms_server/", "name": "CSMS_SERVER"}
        },
        "CSMS_CLIENT": {
            "leaf": {"path": "client/csms/", "name": "CSMS_LEAF"}
        }
    }

    def __init__(self, serials: dict, bundle_name: str):
        self.serials = serials
        self.base_path = abs_path+"/vault/"+bundle_name+"/everest/certs/"

    def save(self):
        cpo_leaf, cpo_subca2, cpo_subca1 = "", "", ""
        for domain, entities in self.cert_path_map.items():
            if domain in self.serials:
                for entity, info in entities.items():
                    if entity in self.serials[domain]:
                        serial = self.serials[domain][entity]
                        path = self.base_path + info["path"]
                        filename = info["name"]
                        save_cert_and_key(serial=serial, entity=entity, path=path, filename=filename)

                        if domain == "MO":
                            if entity != "rootca":
                                os.system("openssl x509 -inform PEM -in " + path + filename + ".pem -outform DER -out " + path + filename + ".der")
                        elif domain == "CPO":
                            if entity == "leaf":
                                cpo_leaf = " " + path + filename + ".pem"
                            elif entity == "subca2":
                                cpo_subca2 = " " + path + filename + ".pem"
                            elif entity == "subca1":
                                cpo_subca1 = " " + path + filename + ".pem"

        if "CPO" in self.cert_path_map and "leaf" in self.cert_path_map["CPO"]:
            command = cpo_leaf + cpo_subca2 + cpo_subca1
            command = "cat" + command + " > " + self.base_path + self.cert_path_map["CPO"]["leaf"]["path"] + "CPO_CERT_CHAIN.pem"
            os.system(command)

class MaEVeSaver(ABC):
    cert_path_map = {
        "CPO": {
            "rootca": "root-V2G-cert",
            "subca1": "cpo_sub_ca1",
            "subca2": "cpo_sub_ca2"
        },
        "MO": {
            "rootca": "root-MO-cert"
        },
        "CSMS_SERVER": {
            "leaf": "csms"
        }
    }

    def __init__(self, serials: dict, bundle_name: str):
        self.serials = serials
        self.base_path = abs_path+"/vault/"+bundle_name+"/maeve/"

    def save(self):
        csms_server, cpo_subca2, cpo_subca1 = "", "", ""
        for domain, entities in self.cert_path_map.items():
            if domain in self.serials:
                for entity, filename in entities.items():
                    if entity in self.serials[domain]:
                        serial = self.serials[domain][entity]
                        save_cert_and_key(serial=serial, entity=entity, path=self.base_path, filename=filename)

                        if domain == "CPO":
                            if entity == "subca2":
                                cpo_subca2 = " " + self.base_path + filename + ".pem"
                            elif entity == "subca1":
                                cpo_subca1 = " " + self.base_path + filename + ".pem"
                        elif domain == "CSMS_SERVER":
                            if entity == "leaf":
                                csms_server = " " + self.base_path + filename + ".pem"

        if "CSMS_SERVER" in self.cert_path_map and "leaf" in self.cert_path_map["CSMS_SERVER"]:
            os.system("cp " + csms_server + " " + self.base_path + "csms_leaf.pem")
            command = cpo_subca2 + cpo_subca1
            command = "cat" + command + " > " + self.base_path + "trust.pem"
            os.system(command)
            command = " " + self.base_path + "csms_leaf.pem " + self.base_path + "trust.pem"
            command = "cat" + command + " > " + self.base_path + "csms.pem"
            os.system(command)

def load_cert_and_key(serial: str) -> Tuple[str, str]:
    r = requests.get(ca_url+"cert/"+serial, headers=headers)
    cert = r.json()["details"]
    r = requests.get(ca_url+"key/"+serial, headers=headers)
    key = r.json()["details"]
    return cert, key

def save_cert_and_key(serial: str, entity: str, path: str, filename: str):
    cert, key = load_cert_and_key(serial=serial)
    os.makedirs(path, exist_ok=True)
    with open(path+filename+".pem","w") as file:
        file.write(cert)
    if entity == "leaf":
        with open(path+filename+".key","w") as file:
            file.write(key)

def main():
    # Do it for only the first time if data is persisted
    # If data is not persisted, do it everytime after restarting the containers
    create_crypto_profile(crypto_profile=crypto_profile, ca_url=ca_url, headers=headers)
    create_entity_profiles(ocsp_url=ocsp_url, ca_url=ca_url, headers=headers)

    # Do it if data is persisted and ocsp url has to be changed
    # r = requests.put(ca_url+"profile/entity/iso2_subca1", headers=headers, json={"ocsp_url": ocsp_url})
    # r = requests.put(ca_url+"profile/entity/iso2_subca2", headers=headers, json={"ocsp_url": ocsp_url})
    # r = requests.put(ca_url+"profile/entity/iso2_leaf", headers=headers, json={"ocsp_url": ocsp_url})

    rootca_profile = models.Profile(crypto_profile_name=crypto_profile, entity_profile_name="iso2_rootca")
    subca1_profile = models.Profile(crypto_profile_name=crypto_profile, entity_profile_name="iso2_subca1")
    subca2_profile = models.Profile(crypto_profile_name=crypto_profile, entity_profile_name="iso2_subca2")
    leaf_profile = models.Profile(crypto_profile_name=crypto_profile, entity_profile_name="iso2_leaf")
    ocsp_profile = models.Profile(crypto_profile_name=crypto_profile, entity_profile_name="iso2_ocsp")

    cpo_rootca_model = models.RootCert(domain="V2G", profile=rootca_profile)
    cpo_subca1_model = models.SubCACert(domain="CPO", profile=subca1_profile, issuer_serial="", tier=1)
    cpo_subca2_model = models.SubCACert(domain="CPO", profile=subca2_profile, issuer_serial="", tier=2)
    cpo_leaf_model = models.LeafCert(domain="CPO", profile=leaf_profile, issuer_serial="", name="SECCLeaf")
    CPO = models.CertChain(rootca=cpo_rootca_model, subca1=cpo_subca1_model, subca2=cpo_subca2_model, leaf=cpo_leaf_model)
    
    mo_subca1_model = models.SubCACert(domain="MO", profile=subca1_profile, issuer_serial="", tier=1)
    mo_subca2_model = models.SubCACert(domain="MO", profile=subca2_profile, issuer_serial="", tier=2)
    mo_leaf_model = models.LeafCert(domain="MO", profile=leaf_profile, issuer_serial="", name="USCPIC001LTON3")
    MO = models.CertChain(rootca=None, subca1=mo_subca1_model, subca2=mo_subca2_model, leaf=mo_leaf_model)
    
    oem_subca1_model = models.SubCACert(domain="OEM", profile=subca1_profile, issuer_serial="", tier=1)
    oem_subca2_model = models.SubCACert(domain="OEM", profile=subca2_profile, issuer_serial="", tier=2)
    oem_leaf_model = models.LeafCert(domain="OEM", profile=leaf_profile, issuer_serial="", name="OEMLeaf")
    OEM = models.CertChain(rootca=None, subca1=oem_subca1_model, subca2=oem_subca2_model, leaf=oem_leaf_model)

    csms_server_leaf_model = models.LeafCert(domain="CSMS", profile=leaf_profile, issuer_serial="", name="host.docker.internal")
    CSMS_SERVER = models.CertChain(rootca=None, subca1=None, subca2=None, leaf=csms_server_leaf_model)

    csms_client_leaf_model = models.LeafCert(domain="CSMS", profile=leaf_profile, issuer_serial="", name="USCPIC001LTON3")
    CSMS_CLIENT = models.CertChain(rootca=None, subca1=None, subca2=None, leaf=csms_client_leaf_model)

    bundle = models.ISO15118CertBundle(CPO=CPO, MO=MO, OEM=OEM, CSMS_SERVER=CSMS_SERVER, CSMS_CLIENT=CSMS_CLIENT)
    bundleCreate = models.ISO15118CertBundleCreate(bundle=bundle, ca_url = ca_url)

    serials = bundleCreate.issue()

    ocsp_model = models.OCSPCert(profile=ocsp_profile, issuer_serial="", name="OCSP Responder")

    bundle_name="Any_AllValid_Pass"
    EVerestSaver(serials=serials, bundle_name=bundle_name).save()
    MaEVeSaver(serials=serials, bundle_name=bundle_name).save()
    
    seen = []
    for certs in serials.values():
        for entity, serial in certs.items():
            if entity == "leaf":
                continue
            if serial not in seen:
                seen.append(serial)
                ocsp_model.issuer_serial = serial
                ocsp_create = models.CertCreate(ocsp_model)
                ocsp_create.issue(ca_url = ca_url+"ocsp")

main()