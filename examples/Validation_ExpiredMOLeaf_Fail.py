import requests, sys, os
from dotenv import load_dotenv

from pathlib import Path
abs_path = str(Path(__file__).absolute().parent.parent)
sys.path.append(abs_path)

from app.models.models import (
    TestCert, BasicConstraints, KeyUsage,
    Extension, Dates, Validity, CertBundleSerial
)
from app.models.enums import ExtendedKeyUsage, ValidityStart
from app.shared.saver import EVerestSaver, MaEVeSaver

load_dotenv()

headers = {
    'accept':       'application/json',
    'X-API-KEY':    os.getenv('API_KEY'),
    'Content-Type': 'application/json',
}

ca_url = os.getenv('CA_URL')+":"+os.getenv('CA_PORT')
ocsp_url = "http://host.docker.internal:"+os.getenv('OCSP_PORT')
crl_url = "http://host.docker.internal:"+os.getenv('CA_PORT')

def issue(cert: TestCert) -> str:
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
    
def issue_ocsp(serial: str, key_algorithm: str, signature_hash: str):
    """
    Issues certificate for an OCSP responder. The OCSP responder checks
    revocation status for the certificate authority specified by the 
    given serial number.

    :param serial: Serial number which specifies the CA.
    :type serial: str
    :param key_algorithm: Key generation algorithm for private key generation.
    :type key_algorithm: str
    :param signature_hash: Hash algorithm for singnatures.
    :type signature_hash: str
    """
    dates = Dates(duration=Validity(years=1))
    basic_cons = Extension(value=BasicConstraints(ca=False, pathLength=None),
                           critical=True)
    extended_key_usage = Extension(value=[ExtendedKeyUsage.OCSP_SIGNING],
                                   critical=False)
    key_usage = Extension(value=KeyUsage(), critical=True)
    ocsp_model =  TestCert(name="OCSP Responder", dates=dates, domain="OCSP",
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=basic_cons, key_usage=key_usage,
                     extended_key_usage=extended_key_usage,
                     issuer_serial=serial)
    issue(ocsp_model)

def main():
    """This example generates the full bundle of valid certificates according
    to ISO 15118-2. It also saves the certificates according to EVerest and
    MaEVe file structure, ready for SIL/HIL tests."""

    test_case_name = "Validation_ExpiredMOLeaf_Fail"

    # Define some general/shared properties for the certificates
    # Cryptographic properties
    key_algorithm = "secp256r1"
    signature_hash = "sha256"
    # Basic constraints
    rootca_basic_cons = Extension(value=BasicConstraints(ca=True, pathLength=None),
                                  critical=True)
    subca1_basic_cons = Extension(value=BasicConstraints(ca=True, pathLength=1),
                                  critical=True)
    subca2_basic_cons = Extension(value=BasicConstraints(ca=True, pathLength=0),
                                  critical=True)
    leaf_basic_cons = Extension(value=BasicConstraints(ca=False, pathLength=None),
                                critical=True)
    # Key usage
    ca_key_usage = Extension(value=KeyUsage(keyCertSign=True, cRLSign=True),
                                 critical=True)
    # Subject and Authority key identifiers are enabled by default

    bundle_serial = CertBundleSerial()

    print("Generating CPO chain")
    dates = Dates(duration=Validity(years=40))
    model = TestCert(name="V2G ROOT CA "+test_case_name, dates=dates, domain="V2G",
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=rootca_basic_cons, key_usage=ca_key_usage)
    v2g_root_serial = issue(model)
    bundle_serial.cpo.root = v2g_root_serial
    issue_ocsp(v2g_root_serial, key_algorithm, signature_hash)

    dates = Dates(duration=Validity(years=4))
    model = TestCert(name="CPO SUBCA 1", dates=dates, domain= "CPO",
                     issuer_serial=v2g_root_serial,
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=subca1_basic_cons, key_usage=ca_key_usage)
    cpo_subca1_serial = issue(model)
    bundle_serial.cpo.subca1 = cpo_subca1_serial
    issue_ocsp(cpo_subca1_serial, key_algorithm, signature_hash)

    dates = Dates(duration=Validity(years=2))
    model = TestCert(name="CPO SUBCA 2", dates=dates, domain= "CPO",
                     issuer_serial=cpo_subca1_serial,
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=subca2_basic_cons, key_usage=ca_key_usage)
    cpo_subca2_serial = issue(model)
    bundle_serial.cpo.subca2 = cpo_subca2_serial
    issue_ocsp(cpo_subca2_serial, key_algorithm, signature_hash)

    dates = Dates(duration=Validity(years=0, months=3))
    leaf_key_usage = Extension(value=KeyUsage(digitalSignature=True),
                               critical=True)
    model = TestCert(name="USSNLS00003C4D5578786756453309675434762", dates=dates,
                     domain= "CPO", issuer_serial=cpo_subca2_serial,
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=leaf_basic_cons, key_usage=leaf_key_usage)
    cpo_leaf_serial = issue(model)
    bundle_serial.cpo.leaf = cpo_leaf_serial

    print("Generating MO chain")
    bundle_serial.mo.root = v2g_root_serial

    dates = Dates(duration=Validity(years=4))
    model = TestCert(name="MO SUBCA 1", dates=dates, domain= "MO",
                     issuer_serial=v2g_root_serial,
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=subca1_basic_cons, key_usage=ca_key_usage)
    mo_subca1_serial = issue(model)
    bundle_serial.mo.subca1 = mo_subca1_serial
    issue_ocsp(mo_subca1_serial, key_algorithm, signature_hash)

    dates = Dates(duration=Validity(years=2))
    model = TestCert(name="MO SUBCA 2", dates=dates, domain= "MO",
                     issuer_serial=mo_subca1_serial,
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=subca2_basic_cons, key_usage=ca_key_usage)
    mo_subca2_serial = issue(model)
    bundle_serial.mo.subca2 = mo_subca2_serial
    issue_ocsp(mo_subca2_serial, key_algorithm, signature_hash)

    dates = Dates(start=ValidityStart.PAST, duration=Validity(years=0, months=3))
    leaf_key_usage = Extension(value=KeyUsage(digitalSignature=True,
                                              nonRepudiation=True,
                                              keyEncipherment=True,
                                              keyAgreement=True),
                               critical=True)
    # TODO: Generate EMAID with propoer checksum.
    # The EMAID below doesn't have a checksum
    model = TestCert(name="USCPIC001LTON3", dates=dates,
                     domain= "MO", issuer_serial=mo_subca2_serial,
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=leaf_basic_cons, key_usage=leaf_key_usage)
    mo_leaf_serial = issue(model)
    bundle_serial.mo.leaf = mo_leaf_serial

    print("Generating OEM chain")
    bundle_serial.oem.root = v2g_root_serial

    dates = Dates(duration=Validity(years=4))
    model = TestCert(name="OEM SUBCA 1", dates=dates, domain= "OEM",
                     issuer_serial=v2g_root_serial,
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=subca1_basic_cons, key_usage=ca_key_usage)
    oem_subca1_serial = issue(model)
    bundle_serial.oem.subca1 = oem_subca1_serial
    issue_ocsp(oem_subca1_serial, key_algorithm, signature_hash)

    dates = Dates(duration=Validity(years=2))
    model = TestCert(name="OEM SUBCA 2", dates=dates, domain= "OEM",
                     issuer_serial=oem_subca1_serial,
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=subca2_basic_cons, key_usage=ca_key_usage)
    oem_subca2_serial = issue(model)
    bundle_serial.oem.subca2 = oem_subca2_serial
    issue_ocsp(oem_subca2_serial, key_algorithm, signature_hash)

    dates = Dates(duration=Validity(years=0, months=3))
    leaf_key_usage = Extension(value=KeyUsage(digitalSignature=True,
                                              keyAgreement=True),
                               critical=True)
    model = TestCert(name="US3PAA00003C4D58Y9", dates=dates,
                     domain= "OEM", issuer_serial=oem_subca2_serial,
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=leaf_basic_cons, key_usage=leaf_key_usage)
    oem_leaf_serial = issue(model)
    bundle_serial.oem.leaf = oem_leaf_serial

    # For OCPP commmunication between the CSMS (CSMS SERVER) and
    # the Charging station (CSMS CLIENT)

    print("Generating CSMS CLIENT chain")
    bundle_serial.csms_client.root = v2g_root_serial
    bundle_serial.csms_client.subca1 = cpo_subca1_serial
    bundle_serial.csms_client.subca2 = cpo_subca2_serial

    dates = Dates(duration=Validity(years=0, months=3))
    leaf_key_usage = Extension(value=KeyUsage(digitalSignature=True),
                               critical=True)
    model = TestCert(name="USSNLS00003C4D5578786756453309675434762", dates=dates,
                     domain= "CSMS", issuer_serial=cpo_subca2_serial,
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=leaf_basic_cons, key_usage=leaf_key_usage)
    csms_client_serial = issue(model)
    bundle_serial.csms_client.leaf = csms_client_serial
    
    print("Generating CSMS SERVER chain\n")
    bundle_serial.csms_server.root = v2g_root_serial
    bundle_serial.csms_server.subca1 = cpo_subca1_serial
    bundle_serial.csms_server.subca2 = cpo_subca2_serial

    dates = Dates(duration=Validity(years=0, months=3))
    leaf_key_usage = Extension(value=KeyUsage(digitalSignature=True),
                               critical=True)
    model = TestCert(name="host.docker.internal", dates=dates,
                     domain= "CSMS", issuer_serial=cpo_subca2_serial,
                     key_algorithm=key_algorithm, signature_hash=signature_hash,
                     basic_constraints=leaf_basic_cons, key_usage=leaf_key_usage)
    csms_server_serial = issue(model)
    bundle_serial.csms_server.leaf = csms_server_serial

    # Certificates have been issued but we need to save them in proper format
    # and structure locally.

    # Saving EVerest bundle
    everestPath = abs_path+"/vault/"+test_case_name+"/everest"
    EVerestSaver(serials=bundle_serial, path=everestPath)

    # Saving MaEVe bundle
    print("")
    maevePath = abs_path+"/vault/"+test_case_name+"/maeve"
    MaEVeSaver(serials=bundle_serial, path=maevePath)
    
if __name__ == "__main__":
    main()