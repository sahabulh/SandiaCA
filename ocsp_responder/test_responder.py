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
    V2G_ROOT = vault_path + "69209529157338116039252351700117378586588815973.pem"
    CPO_SUBCA_1 = vault_path + "373304069203686263112032072910449946790994875326.pem"
    CPO_SUBCA_2 = vault_path + "566591043559320403425012530516490216268664725918.pem"
    MO_SUBCA_1 = vault_path + "701533419137984456677667550840201066948765340390.pem"
    MO_SUBCA_2 = vault_path + "642027254343517846020644926428544681955124579176.pem"
    OEM_SUBCA_1 = vault_path + "454446033521019253649963954762034922134910170419.pem"
    OEM_SUBCA_2 = vault_path + "538847279514479163941697216058505528318000845584.pem"
    SECC_LEAF = vault_path + "719472711573694379318940222453654365273233047693.pem"
    CSMS_SERVER = vault_path + "616414041270758456950557715090708186514061344501.pem"
    MO_LEAF = vault_path + "615957962934163407942480300301599218371106489312.pem"
    OEM_LEAF = vault_path + "253025754814956320173450010202641110910549036242.pem"

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