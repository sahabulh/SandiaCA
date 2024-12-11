# Tests revocation status of all the certs in the cert_db.json file

import base64, requests, asyncio, sys, pytest, time
from enum import StrEnum
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.x509.ocsp import OCSPResponseStatus, OCSPCertStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

from pathlib import Path
abs_path = str(Path(__file__).absolute().parent)
sys.path.append(str(Path(__file__).absolute().parent.parent))

from pymongo import MongoClient

import utils

async def get_test_cases(serial: str):
    chain_serial = await utils.get_chain_serial_for_leaf(leaf_serial=serial)
    vault_path = "../vault/"
    class CERT_PATH(StrEnum):
        V2G_ROOT = vault_path + chain_serial["ROOT"] +".pem"
        CPO_SUBCA_1 = vault_path + chain_serial["SUBCA1"] +".pem"
        CPO_SUBCA_2 = vault_path + chain_serial["SUBCA2"] +".pem"
        SECC_LEAF = vault_path + chain_serial["LEAF"] +".pem"
    test_certs = [
        (CERT_PATH.CPO_SUBCA_1,CERT_PATH.V2G_ROOT,OCSPCertStatus.GOOD),
        (CERT_PATH.CPO_SUBCA_2,CERT_PATH.CPO_SUBCA_1,OCSPCertStatus.GOOD),
        (CERT_PATH.SECC_LEAF,CERT_PATH.CPO_SUBCA_2,OCSPCertStatus.GOOD),
        (CERT_PATH.SECC_LEAF,CERT_PATH.V2G_ROOT,OCSPResponseStatus.UNAUTHORIZED),
        (CERT_PATH.SECC_LEAF,CERT_PATH.CPO_SUBCA_1,OCSPResponseStatus.UNAUTHORIZED),
        (CERT_PATH.CPO_SUBCA_2,CERT_PATH.V2G_ROOT,OCSPResponseStatus.UNAUTHORIZED),
        (CERT_PATH.CPO_SUBCA_2,CERT_PATH.SECC_LEAF,OCSPResponseStatus.UNAUTHORIZED),
        (CERT_PATH.CPO_SUBCA_1,CERT_PATH.CPO_SUBCA_2,OCSPResponseStatus.UNAUTHORIZED),
        (CERT_PATH.CPO_SUBCA_1,CERT_PATH.SECC_LEAF,OCSPResponseStatus.UNAUTHORIZED)
    ]
    return test_certs

async def load_db():
    mongodb_client = MongoClient("localhost",27017, serverSelectionTimeoutMS=10, connectTimeoutMS=1000)
    sandia_ca = mongodb_client.sandia_ca
    await utils.load_db(sandia_ca)

mongodb_client = MongoClient("localhost",27017, serverSelectionTimeoutMS=10, connectTimeoutMS=1000)
sandia_ca = mongodb_client.sandia_ca
asyncio.run(load_db())
test_certs = asyncio.run(get_test_cases("219646264740797746216327186006366433638032474847"))

async def unload_db():
    mongodb_client = MongoClient("localhost",27017, serverSelectionTimeoutMS=10, connectTimeoutMS=1000)
    sandia_ca = mongodb_client.sandia_ca
    await utils.unload_db(sandia_ca)
    mongodb_client.close()

@pytest.fixture(autouse=True)
def run_before_and_after_tests():
    yield
    asyncio.run(unload_db())

def get_cert_for_path(cert_path):
    with open(cert_path, "rb") as cert_file:
        certPEM = cert_file.read()
        return x509.load_pem_x509_certificate(certPEM, default_backend())
    
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

def get_cert_status_for_path(path, issuer_path, hash):
    cert = get_cert_for_path(path)
    issuer_cert = get_cert_for_path(issuer_path)
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