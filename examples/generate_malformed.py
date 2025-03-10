import requests, sys, os
from dotenv import load_dotenv

from pathlib import Path
abs_path = str(Path(__file__).absolute().parent.parent)
sys.path.append(abs_path)

import app.models.models as models
from app.models.enums import ValidityStart, CertFormat
from app.shared.saver import CertSaver, CertChainSaver, CertBundleSaver

load_dotenv()

headers = {
    'accept':       'application/json',
    'X-API-KEY':    os.getenv('API_KEY'),
    'Content-Type': 'application/json',
}

ca_url = os.getenv('CA_URL')+":"+os.getenv('CA_PORT')

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

def main():
    """This example generates the CPO chain but with many wrong properties
    according to ISO 15118-2. Check Annex F of the standard."""
    
    print("Initiating certificate bundle with all None")
    bundle = CertBundleSaver()

    print("Initiating CPO chain with all None\n")
    cpo = CertChainSaver()

    print("Crafting V2G Root CA model")
    # Issue: "Not before" date is one year in future
    dates = models.Dates(start=ValidityStart.FUTURE)
    # Issue: Signature hash is "secp192r1" which is not allowed for ISO 15118-2
    # Issue: Domain component is not set to "V2G"
    # Issue: Required extensions like KeyUsage, BasicConstraints are not added.
    model = models.TestCert(name="V2G ROOT CA 1", dates=dates,
                            key_algorithm="secp192r1", signature_hash="sha256")
    print("Issuing V2G Root CA and getting the serial number")
    v2g_root_serial = issue(model)
    print("Adding V2G Root CA to the CPO chain\n")
    cpo.root = CertSaver(path="ca/v2g", name="V2G_ROOT_CA",
                        serial=v2g_root_serial, key=True,
                        format=[CertFormat.PEM, CertFormat.DER])

    print("Crafting CPO SubCA 1 model")
    # Issue: "Not before" date is one year in past. Already expired.
    dates = models.Dates(start=ValidityStart.PAST)
    # Issue: SKI should be non critical (set to False)
    ski = models.Extension(critical=True)
    # Issue: BasicConstraints is set using default value which is wrong
    # for CPO SubCA 1. Also, it should be set critical.
    basic_constraints = models.Extension(value=models.BasicConstraints(),
                                         critical=False)
    # Issue: KeyUsage is set using wrong flags for CPO SubCA 1
    key_usage = models.Extension(value=models.KeyUsage(keyAgreement=True,
                                                       encipherOnly=True),
                                                       critical=True)
    # Issue: Wrong ExtendedKeyUsage extension for CPO SubCA 1
    extended_usage = models.Extension(value="ocsp_signing", critical=True)
    # Issue: Not issuer serial is set. The cert will be self signed instead of
    # signed by the V2G Root CA. Issuer serial should have been set to the 
    # value of "v2g_root_serial" from above
    model = models.TestCert(name="CPO SUBCA1 1", dates=dates,
                            key_algorithm="secp256r1", signature_hash="sha256",
                            domain= "CPO",
                            basic_constraints=basic_constraints,
                            key_usage=key_usage, subject_key_identifier=ski,
                            extended_key_usage=extended_usage)
    print("Issuing CPO SubCA 1 and getting the serial number")
    cpo_subca1_serial = issue(model)
    print("Adding CPO SubCA 1 to the CPO chain\n")
    cpo.subca1 = CertSaver(path="ca/cso", name="CPO_SUB_CA_1",
                          serial=cpo_subca1_serial)

    print("Crafting CPO SubCA 2 model")
    # Issue: "Not before" date is one year in past with a validity period of
    # 6 months. Already expired.
    dates = models.Dates(start=ValidityStart.PAST,
                         duration=models.Validity(years=0, months=6))
    # Issue: SKI is set to random value
    ski = models.Extension(value="DEADBEEF", critical=False)
    # Issue: AKI should be non critical (set to False)
    aki = models.Extension(critical=True)
    # Issue: BasicConstraints has wrong values for CPO SubCA 2
    basic_constraints = models.Extension(value=models.BasicConstraints(
                                         ca=True, pathLength=10),
                                         critical=True)
    # Issue: KeyUsage has wrong values for CPO SubCA 2.
    # Also it should be critical.
    key_usage = models.Extension(value=models.KeyUsage(nonRepudiation=True),
                                 critical=False)
    # Issue: Wrong ExtendedKeyUsage extension for CPO SubCA 2
    extended_usage = models.Extension(value="server_auth", critical=True)
    # Issue: Issuer is set to V2G Root CA instead of CPO SubCA 1
    model = models.TestCert(name="CPO SUBCA2 1", dates=dates,
                            key_algorithm="secp256r1", signature_hash="sha256",
                            domain= "CPO", issuer_serial=v2g_root_serial,
                            subject_key_identifier=ski,
                            authority_key_identifier=aki,
                            basic_constraints=basic_constraints,
                            key_usage=key_usage,
                            extended_key_usage=extended_usage)
    print("Issuing CPO SubCA 2 and getting the serial number")
    cpo_subca2_serial = issue(model)
    print("Adding CPO SubCA 2 to the CPO chain\n")
    cpo.subca2 = CertSaver(path="ca/cso", name="CPO_SUB_CA_2",
                          serial=cpo_subca2_serial)

    print("Crafting SECC Leaf model")
    dates = models.Dates(duration=models.Validity(years=0, months=3))
    ocsp = models.Extension(value="http://ocsp.sandiaca.com", critical=False)
    # Issue: CRL extension should be non critical
    crl = models.Extension(value="http://crl.sandiaca.com",
                           critical=True)
    # Issue: Name (sets CN field) should be the CPID.
    # Issue: Required extensions like KeyUsage, BasicConstraints are not added.
    model = models.TestCert(name="SECC Leaf", dates=dates,
                            key_algorithm="secp256r1", signature_hash="sha256",
                            domain= "CPO", issuer_serial=cpo_subca2_serial,
                            ocsp_url=ocsp, crl_url=crl)
    print("Issuing SECC Leaf and getting the serial number")
    cpo_leaf_serial = issue(model)
    print("Adding SECC Leaf to the CPO chain\n")
    cpo.leaf = CertSaver(path="client/cso", name="SECC_LEAF",
                        serial=cpo_leaf_serial, key=True)

    # All four certs of the CPO chain has been added, so add CPO chain itself
    # to the main bundle
    print("Adding CPO chain to the main bundle\n")
    bundle.cpo = cpo

    # Ideally, we need to add the other chains but for this example, we will
    # just issue the CPO chain.
    bundleName = "test_bundle_fail"
    basePath = abs_path+"/vault/"+bundleName
    print(f"Saving bundle to {basePath}")
    bundle.save(path=basePath)

if __name__ == "__main__":
    main()