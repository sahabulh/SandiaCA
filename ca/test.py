# Tests revocation status of all the certs in the cert_db.json file

import base64, requests, json, os
from urllib.parse import urljoin
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA384, SHA512
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID

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
    try:
        ocsp_resp = requests.get(get_oscp_request(ocsp_server, cert, issuer_cert, hash))
    except:
        print(f"Error: Can't connect to the OCSP server at {ocsp_server}.")
    if ocsp_resp.ok:
        ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp.content)
        if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
            print(f"Success: Certificate status: {ocsp_decoded.certificate_status.name}")
        else:
            print(f"Error: OCSP response status: {ocsp_decoded.response_status.name}")
    else:
        print(f"Error: HTTP response status: {ocsp_resp.status_code}")

def get_cert_status_for_path(path, issuer_path, hash):
    cert = get_cert_for_path(path)
    print(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
    issuer_cert = get_cert_for_path(issuer_path)
    ocsp_server = get_ocsp_server(cert)
    return get_ocsp_cert_status(ocsp_server, cert, issuer_cert, hash)

with open("cert_db.json","r") as file:
    cert_db = json.load(file)

for k, v in cert_db.items():
    try:
        get_cert_status_for_path("vault/"+k+".pem", "vault/"+str(v["issuer"])+".pem", SHA256())
    except FileNotFoundError:
        pass
    except Exception as err:
        print(f"{type(err).__name__}: {err.args}")