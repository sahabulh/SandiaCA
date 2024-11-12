# Tests revocation status of all the certs in the cert_db.json file

import base64, requests, pytest
from enum import StrEnum
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.x509.ocsp import OCSPResponseStatus, OCSPCertStatus
from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID

vault_path = "../vault/"
class CERT_PATH(StrEnum):
    V2G_ROOT = vault_path + "431647055602704191126752956288276829964039214206.pem"
    CPO_SUBCA_1 = vault_path + "97217592481984594308766028463771473824272267858.pem"
    CPO_SUBCA_2 = vault_path + "553617654674554920333624267322230555008147737977.pem"
    MO_SUBCA_1 = vault_path + "132101457480042092308139199509196186130507388733.pem"
    MO_SUBCA_2 = vault_path + "224868133928769470824970054717591579703268557352.pem"
    OEM_SUBCA_1 = vault_path + "640718486964177086539683333726311868061009203854.pem"
    OEM_SUBCA_2 = vault_path + "155212398951671999164573189434246687977298841513.pem"
    SECC_LEAF = vault_path + "119505825501697624670649151090877782153652592699.pem"
    CSMS_SERVER = vault_path + "94059136114604030655694516174928038154438095118.pem"
    MO_LEAF = vault_path + "11654975046526437397282010594008129917387172308.pem"
    OEM_LEAF = vault_path + "701557789752286354724286575571082927854887818991.pem"

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

test_certs_good = [
    (CERT_PATH.CPO_SUBCA_1,CERT_PATH.V2G_ROOT,OCSPCertStatus.GOOD),
    (CERT_PATH.CPO_SUBCA_2,CERT_PATH.CPO_SUBCA_1,OCSPCertStatus.GOOD),
    (CERT_PATH.CSMS_SERVER,CERT_PATH.CPO_SUBCA_2,OCSPCertStatus.GOOD),
    (CERT_PATH.SECC_LEAF,CERT_PATH.CPO_SUBCA_2,OCSPCertStatus.GOOD),
    (CERT_PATH.MO_SUBCA_1,CERT_PATH.V2G_ROOT,OCSPCertStatus.GOOD),
    (CERT_PATH.MO_SUBCA_2,CERT_PATH.MO_SUBCA_1,OCSPCertStatus.GOOD),
    (CERT_PATH.MO_LEAF,CERT_PATH.MO_SUBCA_2,OCSPCertStatus.GOOD),
    (CERT_PATH.OEM_SUBCA_1,CERT_PATH.V2G_ROOT,OCSPCertStatus.GOOD),
    (CERT_PATH.OEM_SUBCA_2,CERT_PATH.OEM_SUBCA_1,OCSPCertStatus.GOOD),
    (CERT_PATH.OEM_LEAF,CERT_PATH.OEM_SUBCA_2,OCSPCertStatus.GOOD),
    (CERT_PATH.SECC_LEAF,CERT_PATH.V2G_ROOT,OCSPResponseStatus.UNAUTHORIZED),
    (CERT_PATH.SECC_LEAF,CERT_PATH.CPO_SUBCA_1,OCSPResponseStatus.UNAUTHORIZED),
    (CERT_PATH.CPO_SUBCA_2,CERT_PATH.V2G_ROOT,OCSPResponseStatus.UNAUTHORIZED),
    (CERT_PATH.CPO_SUBCA_2,CERT_PATH.SECC_LEAF,OCSPResponseStatus.UNAUTHORIZED),
    (CERT_PATH.CPO_SUBCA_1,CERT_PATH.CPO_SUBCA_2,OCSPResponseStatus.UNAUTHORIZED),
    (CERT_PATH.CPO_SUBCA_1,CERT_PATH.SECC_LEAF,OCSPResponseStatus.UNAUTHORIZED)
]

# Define the pytest_generate_tests hook to generate test cases
def pytest_generate_tests(metafunc):
    if 'test_cert' in metafunc.fixturenames:
        # Generate test cases based on the user_roles list
        metafunc.parametrize('test_cert', test_certs_good)

def test_ocsp_sha1(test_cert):
    cert, issuer, _ = test_cert
    assert get_cert_status_for_path(cert,issuer,SHA1()) == OCSPResponseStatus.UNAUTHORIZED

def test_ocsp_sha256(test_cert):
    cert, issuer, expected_status = test_cert
    assert get_cert_status_for_path(cert,issuer,SHA256()) == expected_status