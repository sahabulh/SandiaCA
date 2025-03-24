import os, requests

from dotenv import load_dotenv
from pydantic import BaseModel
from typing import Optional, List

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization

from app.models.enums import CertFormat
from app.models.models import CertBundleSerial

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
    full_path: Optional[str] = None
    """Holds the full path to the PEM certificate after local save. Not to be
    assigned manullay. Use the 'get_full_path_pem' method to get it."""

    def save(self, basepath: str):
        """Saves the certificate."""
        if self.path:
            os.makedirs(basepath+"/"+self.path, exist_ok=True)
            self.full_path = basepath+"/"+self.path+"/"+self.name
        else:
            os.makedirs(basepath, exist_ok=True)
            self.full_path = basepath+"/"+self.name
        load_and_save_cert(self.serial, self.full_path, self.format)
        if self.key:
            load_and_save_key(self.serial, self.full_path)

    def get_full_path_pem(self) -> Optional[str]:
        """Returns the full path to the PEM certificate."""
        if hasattr(self, 'full_path'):
            if CertFormat.PEM in self.format:
                return self.full_path+".pem"
            else:
                print("Certificate was not saved in PEM format.")
                return None
        else:
            print("Save first to get the full path.")
            return None

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

def EVerestSaver(serials: CertBundleSerial, path: str):
    """Saves certificate bundle following EVerest structure"""
    
    print("Initializing certificate saver for EVerest ...")
    everest = CertBundleSaver()

    cpo = CertChainSaver()
    cpo.root = CertSaver(path="ca/v2g", name="V2G_ROOT_CA",
                         serial=serials.cpo.root)
    cpo.subca1 = CertSaver(path="ca/csms", name="CPO_SUB_CA_1",
                          serial=serials.cpo.subca1)
    cpo.subca2 = CertSaver(path="ca/csms", name="CPO_SUB_CA_2",
                          serial=serials.cpo.subca2)
    cpo.leaf = CertSaver(path="client/cso", name="SECC_LEAF",
                        serial=serials.cpo.leaf, key=True)
    print("Adding CPO chain saver to the EVerest bundle")
    everest.cpo = cpo

    mo = CertChainSaver()
    mo.root = CertSaver(path="ca/mo", name="MO_ROOT_CA", serial=serials.mo.root)
    mo.subca1 = CertSaver(path="ca/mo", name="MO_SUB_CA_1",
                          format=[CertFormat.PEM, CertFormat.DER],
                          serial=serials.mo.subca1)
    mo.subca2 = CertSaver(path="ca/mo", name="MO_SUB_CA_2",
                          format=[CertFormat.PEM, CertFormat.DER],
                          serial=serials.mo.subca2)
    mo.leaf = CertSaver(path="client/mo", name="MO_LEAF",
                        format=[CertFormat.PEM, CertFormat.DER],
                        serial=serials.mo.leaf, key=True)
    print("Adding MO chain saver to the EVerest bundle")
    everest.mo = mo

    oem = CertChainSaver()
    oem.root = CertSaver(path="ca/oem", name="OEM_ROOT_CA", serial=serials.oem.root)
    oem.subca1 = CertSaver(path="ca/oem", name="OEM_SUB_CA_1",
                          serial=serials.oem.subca1)
    oem.subca2 = CertSaver(path="ca/oem", name="OEM_SUB_CA_2",
                          serial=serials.oem.subca2)
    oem.leaf = CertSaver(path="client/oem", name="OEM_LEAF",
                        serial=serials.oem.leaf, key=True)
    print("Adding OEM chain saver to the EVerest bundle")
    everest.oem = oem

    csms_client = CertChainSaver()
    csms_client.leaf = CertSaver(path="client/csms_client", name="CSMS_CLIENT",
                        serial=serials.csms_client.leaf, key=True)
    print("Adding CSMS CLIENT chain saver to the EVerest bundle")
    everest.csms_client = csms_client

    csms_server = CertChainSaver()
    csms_server.leaf = CertSaver(path="client/csms_server", name="CSMS_SERVER",
                        serial=serials.csms_server.leaf, key=True)
    print("Adding CSMS SERVER chain saver to the EVerest bundle")
    everest.csms_server = csms_server

    print(f"Saving EVerest bundle ...")
    everest.save(path)

    command = cpo.leaf.get_full_path_pem() + " " + cpo.subca2.get_full_path_pem() + " " + cpo.subca1.get_full_path_pem()
    command = "cat " + command + " > " + path + "/client/cso/CPO_CERT_CHAIN.pem"
    os.system(command)

def MaEVeSaver(serials: CertBundleSerial, path: str):
    """Saves certificate bundle following MaEVe structure"""

    print("Initializing certificate saver for MaEVe ...")
    maeve = CertBundleSaver()

    print("Adding CPO chain saver to the MaEVe bundle")
    cpo = CertChainSaver()
    cpo.root = CertSaver(name="root-V2G-cert", serial=serials.cpo.root)
    cpo.subca1 = CertSaver(name="cpo_sub_ca1", serial=serials.cpo.subca1)
    cpo.subca2 = CertSaver(name="cpo_sub_ca2", serial=serials.cpo.subca2)
    maeve.cpo = cpo

    print("Adding MO chain saver to the MaEVe bundle")
    mo = CertChainSaver()
    mo.root = CertSaver(name="root-MO-cert", serial=serials.mo.root)
    maeve.mo = mo

    print("Adding CSMS SERVER chain saver to the MaEVe bundle")
    csms_server = CertChainSaver()
    csms_server.leaf = CertSaver(name="csms", serial=serials.csms_server.leaf, key=True)
    maeve.csms_server = csms_server

    print(f"Saving MaEVe bundle ...")
    maeve.save(path)

    os.system("cp " + csms_server.leaf.get_full_path_pem() + " " + path + "/csms_leaf.pem")
    command = cpo.subca2.get_full_path_pem() + " " + cpo.subca1.get_full_path_pem()
    command = "cat " + command + " > " + path + "/trust.pem"
    os.system(command)
    command = path + "/csms_leaf.pem " + path + "/trust.pem"
    command = "cat " + command + " > " + path + "/csms.pem"
    os.system(command)

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