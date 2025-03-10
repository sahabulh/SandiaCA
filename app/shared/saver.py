import os, requests

from dotenv import load_dotenv
from pydantic import BaseModel
from typing import Optional, List

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization

from app.models.enums import CertFormat

load_dotenv()

headers = {
    'accept':       'application/json',
    'X-API-KEY':    os.getenv('API_KEY'),
    'Content-Type': 'application/json',
}

ca_url = os.getenv('CA_URL')+":"+os.getenv('CA_PORT')

class CertSaver(BaseModel):
    """Defines a single certificate saver profile."""
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
    format: List[CertFormat] = [CertFormat.PEM]
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

class CertChainSaver(BaseModel):
    """Defines a certificate chain to be saved."""
    root: Optional[CertSaver] = None
    """The CertSaver model for the Root CA"""
    subca1: Optional[CertSaver] = None
    """The CertSaver model for the SubCA 1"""
    subca2: Optional[CertSaver] = None
    """The CertSaver model for the SubCA 2"""
    leaf: Optional[CertSaver] = None
    """The CertSaver model for the leaf/end-entity"""

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

class CertBundleSaver(BaseModel):
    """Defines the full certificate bunudle to be saved."""
    cpo: Optional[CertChainSaver] = None
    """The CPO/CSO chain"""
    oem: Optional[CertChainSaver] = None
    """The OEM chain"""
    mo: Optional[CertChainSaver] = None
    """The MO/eMSP chain"""
    csms_client: Optional[CertChainSaver] = None
    """The client chain or charging station chain for OCPP"""
    csms_server: Optional[CertChainSaver] = None
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



def load_and_save_cert(serial: str, path: str, format: List[CertFormat]):
    """
    Loads certificate querying by serial number and saves the cert in the given
    formats to the given path.

    :param serial: Certificate serial number.
    :type serial: str
    :param path: Full path to the save location without the file extension.
    :type path: str
    :param format: List of formats.
    :type format: List[CertFormat]
    """

    r = requests.get(ca_url+"/cert/"+serial, headers=headers)
    cert_data = r.json()["details"]

    if CertFormat.PEM in format:
        with open(path+".pem","w") as file:
            file.write(cert_data)

    if CertFormat.DER in format:
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