# Tests revocation status of all the certs in the cert_db.json file
import base64, requests, sys, os
from dotenv import load_dotenv

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.x509.ocsp import OCSPResponseStatus, OCSPCertStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

from pathlib import Path
abs_path = str(Path(__file__).absolute().parent)
sys.path.append(str(Path(__file__).absolute().parent.parent))

load_dotenv()

ca_url = "http://127.0.0.1:"+os.getenv('CA_PORT')

headers = {
    'accept':       'application/json',
    'X-API-KEY':    'iamadmin',
    'Content-Type': 'application/json',
}

def get_test_cases():
    r = requests.get(ca_url+"/cert", headers=headers)
    data = r.json()

    SECC_LEAF = None
    for cert in data["data"]:
        if cert["name"] == "SECCLeaf":
            SECC_LEAF = load_cert(cert["serial"])

    if not SECC_LEAF:
        exit()

    r = requests.get(ca_url+"/issuer/"+str(SECC_LEAF.serial_number), headers=headers)
    CPO_SUBCA_2 = load_cert(r.json()["details"])
    r = requests.get(ca_url+"/issuer/"+str(CPO_SUBCA_2.serial_number), headers=headers)
    CPO_SUBCA_1 = load_cert(r.json()["details"])
    r = requests.get(ca_url+"/issuer/"+str(CPO_SUBCA_1.serial_number), headers=headers)
    V2G_ROOT = load_cert(r.json()["details"])
    
    test_certs = [
        (CPO_SUBCA_1,V2G_ROOT,OCSPCertStatus.GOOD),
        (CPO_SUBCA_2,CPO_SUBCA_1,OCSPCertStatus.GOOD),
        (SECC_LEAF,CPO_SUBCA_2,OCSPCertStatus.GOOD),
        (SECC_LEAF,V2G_ROOT,OCSPResponseStatus.UNAUTHORIZED),
        (SECC_LEAF,CPO_SUBCA_1,OCSPResponseStatus.UNAUTHORIZED),
        (CPO_SUBCA_2,V2G_ROOT,OCSPResponseStatus.UNAUTHORIZED),
        (CPO_SUBCA_2,SECC_LEAF,OCSPResponseStatus.UNAUTHORIZED),
        (CPO_SUBCA_1,CPO_SUBCA_2,OCSPResponseStatus.UNAUTHORIZED),
        (CPO_SUBCA_1,SECC_LEAF,OCSPResponseStatus.UNAUTHORIZED)
    ]
    return test_certs

def load_cert(serial: str) -> x509.Certificate:
    cert_data = load_cert_as_string(serial).encode()
    cert = x509.load_pem_x509_certificate(cert_data)
    return cert

def load_cert_as_string(serial: str) -> str:
    r = requests.get(ca_url+"/cert/"+serial, headers=headers)
    return r.json()["details"]

test_certs = get_test_cases()

def get_cert_for_path(cert_path):
    with open(cert_path, "rb") as cert_file:
        certPEM = cert_file.read()
        return x509.load_pem_x509_certificate(certPEM)
    
def get_ocsp_server(cert):
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    ocsps = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP]
    if not ocsps:
        raise Exception(f'no ocsp server entry in AIA')
    return ocsps[0].access_location.value

def get_oscp_request(ocsp_server, cert, issuer_cert, hash):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hash)
    req = builder.build()
    req_path = base64.b64encode(req.public_bytes(serialization.Encoding.DER))
    return ocsp_server + '/' + req_path.decode('utf-8')

def get_ocsp_cert_status(ocsp_server, cert, issuer_cert, hash):
    ocsp_resp = requests.get(get_oscp_request(ocsp_server, cert, issuer_cert, hash))
    if ocsp_resp.ok:
        ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp.content)
        if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
            return ocsp_decoded.certificate_status
        else:
            return ocsp_decoded.response_status
    else:
        return ocsp_resp.status_code

def get_cert_status_for_path(cert, issuer_cert, hash):  
    ocsp_server = get_ocsp_server(cert)
    return get_ocsp_cert_status(ocsp_server, cert, issuer_cert, hash)

# Define the pytest_generate_tests hook to generate test cases
def pytest_generate_tests(metafunc):
    print(test_certs)
    if 'test_cert' in metafunc.fixturenames:
        # Generate test cases based on the test_certs list
        metafunc.parametrize('test_cert', test_certs)

def test_ocsp_sha1(test_cert):
    cert, issuer, expected_status = test_cert
    assert get_cert_status_for_path(cert,issuer,SHA1()) == expected_status

def test_ocsp_sha256(test_cert):
    cert, issuer, expected_status = test_cert
    assert get_cert_status_for_path(cert,issuer,SHA256()) == expected_status