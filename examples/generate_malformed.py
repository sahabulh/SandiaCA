import requests, sys, os
from dotenv import load_dotenv
from abc import ABC
from pydantic import BaseModel
from typing import Optional

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization

from pathlib import Path
abs_path = str(Path(__file__).absolute().parent.parent)
sys.path.append(abs_path)

import app.models.models as models

headers = {
    'accept':       'application/json',
    'X-API-KEY':    'iamadmin',
    'Content-Type': 'application/json',
}

load_dotenv()

ca_url = "http://127.0.0.1:"+os.getenv('CA_PORT')
ocsp_url = "http://host.docker.internal:"+os.getenv('OCSP_PORT')

class CertPath(BaseModel):
    """Defines a single certificate saving profile."""
    path: Optional[str] = None
    """Extra path under the basepath for more flexible organization. If None,
    certificate will be saved in the basepath."""
    name: str
    """Name for certificate and key files"""
    serial: str
    """Certificate serial number"""
    key: bool = False
    """Defines whether the private key will be saved or not. If False,
    the private key will not be saved."""
    format: list[str] = ['pem']
    """List of certificate file formats to be saved"""

    def save(self, basepath: str):
        """Saves the certificate."""
        if self.path:
            os.makedirs(basepath+"/"+self.path, exist_ok=True)
            path = basepath+"/"+self.path+"/"+self.name
        else:
            os.makedirs(basepath, exist_ok=True)
            path = basepath+"/"+self.name
        load_and_save_cert(self.serial, path, self.format)
        if self.key:
            load_and_save_key(self.serial, path)

class CertChainPath(BaseModel):
    """Defines a certificate chain to be saved."""
    root: Optional[CertPath] = None
    """The CertPath model for the Root CA"""
    subca1: Optional[CertPath] = None
    """The CertPath model for the SubCA 1"""
    subca2: Optional[CertPath] = None
    """The CertPath model for the SubCA 2"""
    leaf: Optional[CertPath] = None
    """The CertPath model for the leaf/end-entity"""

    def save(self, path: str):
        """Saves the certificate chain."""
        if self.root:
            self.root.save(basepath=path)
        if self.subca1:
            self.subca1.save(basepath=path)
        if self.subca2:
            self.subca2.save(basepath=path)
        if self.leaf:
            self.leaf.save(basepath=path)

class CertBundlePath(BaseModel):
    """Defines the full certificate bunudle to be saved."""
    cpo: Optional[CertChainPath] = None
    """The CPO/CSO chain"""
    oem: Optional[CertChainPath] = None
    """The OEM chain"""
    mo: Optional[CertChainPath] = None
    """The MO/eMSP chain"""
    csms_client: Optional[CertChainPath] = None
    """The client chain or charging station chain for OCPP"""
    csms_server: Optional[CertChainPath] = None
    """The CSMS server chain for OCPP"""

    def save(self, path: str):
        """Saves the certificate bundle."""
        if self.cpo:
            self.cpo.save(path=path)
        if self.oem:
            self.oem.save(path=path)
        if self.mo:
            self.mo.save(path=path)
        if self.csms_client:
            self.csms_client.save(path=path)
        if self.csms_server:
            self.csms_server.save(path=path)

def issue(cert: models.TestCert) -> str:
    """
    Issues certificate using the given certificate model.

    :param cert: Certificate model to be used to generate the certificate.
    :type cert: TestCert
    :raise Exception: If the server response doesn't contain the serial number.
    :return: Certificate serial number
    :rtype: str
    """
    r = requests.post(ca_url+"/test/cert", headers=headers,
                      data=cert.model_dump_json())
    try:
        res_data = r.json()
        return res_data["serial"]
    except:
        print(r.content)
        raise Exception("Cert issue error")

def load_and_save_cert(serial: str, path: str, format: list[str]):
    """
    Loads certificate querying by serial number and saves the cert in the given
    formats to the given path.

    :param serial: Certificate serial number.
    :type serial: str
    :param path: Full path to the save location without the file extension.
    :type path: str
    :param format: List of formats. Allowed formats: "pem" and "der".
    :type format: list[str]
    """

    r = requests.get(ca_url+"/cert/"+serial, headers=headers)
    cert_data = r.json()["details"]

    if "pem" in format:
        with open(path+".pem","w") as file:
            file.write(cert_data)

    if "der" in format:
        cert = load_pem_x509_certificate(cert_data.encode())
        cert_data = cert.public_bytes(encoding=serialization.Encoding.DER)
        with open(path+".der","wb") as file:
            file.write(cert_data)

def load_and_save_key(serial: str, path: str):
    """
    Loads private key querying by serial number and saves the key to the given
    path.

    :param serial: Serial number of the associate certificate.
    :type serial: str
    :param path: Full path to the save location without the file extension.
    :type path: str
    """

    r = requests.get(ca_url+"/key/"+serial, headers=headers)
    key_data = r.json()["details"]
    with open(path+".key","w") as file:
        file.write(key_data)

def main():
    # Initiate bundle with all None
    bundle = CertBundlePath()

    # Initiate CPO chain with all None
    cpo = CertChainPath()

    # Craft V2G Root CA model
    dates = models.Dates(start="future")
    model = models.TestCert(name="V2G ROOT CA 1", dates=dates,
                            key_algorithm="secp192r1", signature_hash="sha256")
    # Issue V2G Root CA and get the serial
    v2g_root_serial = issue(model)
    # Add V2G Root CA to the CPO Chain
    cpo.root = CertPath(path="ca/v2g", name="V2G_ROOT_CA",
                        serial=v2g_root_serial, key=True, format=["pem", "der"])

    # Craft CPO SUB CA1 model
    dates = models.Dates(start="past")
    ski = models.Extension(critical=True)
    basic_constraints = models.Extension(value=models.BasicConstraints(),
                                         critical=False)
    key_usage = models.Extension(value=models.KeyUsage(keyAgreement=True,
                                                       encipherOnly=True),
                                                       critical=True)
    extended_usage = models.Extension(value="ocsp_signing", critical=True)
    model = models.TestCert(name="CPO SUBCA1 1", dates=dates,
                            key_algorithm="secp192r1", signature_hash="sha256",
                            domain= "CPO",
                            basic_constraints=basic_constraints,
                            key_usage=key_usage, subject_key_identifier=ski,
                            extended_key_usage=extended_usage)
    # Issue CPO SUB CA1 and get the serial
    cpo_subca1_serial = issue(model)
    # Add CPO SUB CA1 to the CPO Chain
    cpo.subca1 = CertPath(path="ca/cso", name="CPO_SUB_CA_1",
                          serial=cpo_subca1_serial)

    # Craft CPO SUB CA2 model
    dates = models.Dates(start="past",
                         duration=models.Validity(years=0, months=6))
    ski = models.Extension(value="DEADBEEF", critical=False)
    aki = models.Extension(critical=True)
    basic_constraints = models.Extension(value=models.BasicConstraints(
                                         ca=True, pathLength=10),
                                         critical=True)
    key_usage = models.Extension(value=models.KeyUsage(nonRepudiation=True),
                                 critical=False)
    extended_usage = models.Extension(value="server_auth", critical=True)
    model = models.TestCert(name="CPO SUBCA2 1", dates=dates,
                            key_algorithm="secp192r1", signature_hash="sha256",
                            domain= "CPO", issuer_serial=v2g_root_serial,
                            subject_key_identifier=ski,
                            authority_key_identifier=aki,
                            basic_constraints=basic_constraints,
                            key_usage=key_usage,
                            extended_key_usage=extended_usage)
    # Issue CPO SUB CA2 and get the serial
    cpo_subca2_serial = issue(model)
    # Add CPO SUB CA2 to the CPO Chain
    cpo.subca2 = CertPath(path="ca/cso", name="CPO_SUB_CA_2",
                          serial=cpo_subca2_serial)

    # Craft SECC Leaf model
    dates = models.Dates(duration=models.Validity(years=0, months=3))
    ocsp = models.Extension(value="http://ocsp.sandiaca.com", critical=False)
    crl = models.Extension(value="http://crl.sandiaca.com/cpo-subca2-1.crl",
                           critical=False)
    model = models.TestCert(name="SECC Leaf", dates=dates,
                            key_algorithm="secp192r1", signature_hash="sha256",
                            domain= "CPO", issuer_serial=cpo_subca2_serial,
                            ocsp_url=ocsp, crl_url=crl)
    # Issue SECC Leaf and get the serial
    cpo_leaf_serial = issue(model)
    # Add SECC Leaf to the CPO Chain
    cpo.leaf = CertPath(path="client/cso", name="SECC_LEAF",
                        serial=cpo_leaf_serial, key=True)

    # All four certs of the CPO chain has been added, so add CPO chain itself
    # to the main bundle
    bundle.cpo = cpo

    # Ideally, we need to add the other chains but for this example, we will
    # just issue the CPO chain.
    bundleName = "test_bundle_fail"
    basePath = abs_path+"/vault/"+bundleName
    bundle.save(path=basePath)

main()