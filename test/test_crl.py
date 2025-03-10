# Tests revocation status of all the certs in the cert_db.json file
import base64, requests, sys, os
from dotenv import load_dotenv

from cryptography import x509

from pathlib import Path
abs_path = str(Path(__file__).absolute().parent)
sys.path.append(str(Path(__file__).absolute().parent.parent))

load_dotenv()

headers = {
    'accept':       'application/json',
    'X-API-KEY':    os.getenv('API_KEY'),
    'Content-Type': 'application/json',
}

ca_url = os.getenv('CA_URL')+":"+os.getenv('CA_PORT')

def get_SECC():
    r = requests.get(ca_url+"/cert", headers=headers)
    data = r.json()

    SECC_LEAF = None
    for cert in data["data"]:
        if cert["name"] == "SECCLeaf":
            SECC_LEAF = load_cert(cert["serial"])

    if not SECC_LEAF:
        exit()
    return SECC_LEAF

def load_cert(serial: str) -> x509.Certificate:
    cert_data = load_cert_as_string(serial).encode()
    cert = x509.load_pem_x509_certificate(cert_data)
    return cert

def load_cert_as_string(serial: str) -> str:
    r = requests.get(ca_url+"/cert/"+serial, headers=headers)
    return r.json()["details"]

cert = get_SECC()

def get_crl_url(cert: x509.Certificate) -> str:
    distribution_points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value._distribution_points
    for distribution_point in distribution_points:
        for name in distribution_point.full_name:
            if isinstance(name, x509.UniformResourceIdentifier):
                return name.value

def load_crl(crl_url: str):
    r = requests.get(crl_url, stream=True)
    crl_data = r.content
    crl = x509.load_pem_x509_crl(crl_data)
    return crl

def is_revoked(serial: int) -> bool:
    crl_url = get_crl_url(cert)
    crl = load_crl(crl_url)
    for revoked_cert in crl:
        if revoked_cert.serial_number == serial:
            return True
    return False

def test_check_crl_good():
    assert is_revoked(cert.serial_number) == False

def test_check_crl_revoked():
    r = requests.post(ca_url+"/revoke/"+str(cert.serial_number), headers=headers)
    print(r.json())
    assert is_revoked(cert.serial_number) == True
    r = requests.post(ca_url+"/unrevoke/"+str(cert.serial_number), headers=headers)
    print(r.json())
    assert is_revoked(cert.serial_number) == False