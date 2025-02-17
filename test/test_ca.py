import json, requests, asyncio, sys, pytest

from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import ec, ed448
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from typing import Union, Tuple

from pymongo import MongoClient

from pathlib import Path
abs_path = str(Path(__file__).absolute().parent.parent)
sys.path.append(abs_path)
sys.path.append(abs_path+"\\app")

import app.utils as utils

headers = {
    'accept':       'application/json',
    'X-API-KEY':    'iamadmin',
    'Content-Type': 'application/json',
}

test_cases_crypto_profile = [
    ("secp256r1_sha256","secp256r1","sha256"),
    ("secp384r1_sha384","secp384r1","sha384"),
    ("secp521r1_sha512","secp521r1","sha512"),
    ("Ed448_Ed448","Ed448","Ed448")
]

test_cases_entity_profile = [
    ("iso2_rootca", [False, False, False, False, False, True, True, False, False], None, [True, None], [40, 0, 0], None),
    ("iso2_subca1", [False, False, False, False, False, True, True, False, False], None, [True, 1], [4, 0, 0], "http://127.0.0.1:8001/"),
    ("iso2_subca2", [False, False, False, False, False, True, True, False, False], None, [True, 0], [2, 0, 0], "http://127.0.0.1:8001/"),
    ("iso2_leaf", [True, False, False, False, False, False, False, False, False], None, [False, None], [1, 0, 0], "http://127.0.0.1:8001/"),
    ("iso2_ocsp", [False, False, False, False, False, False, False, False, False], ["ocsp_signing"], [False, None], [1, 0, 0], None)
]

test_cases_ec_good = [
    ("secp256r1_sha256","ecdsa-with-SHA256","secp256r1"),
    ("secp521r1_sha512","ecdsa-with-SHA512","secp521r1")
]

test_cases_error = [
    ("secp384r1_sha384","Key algorithms except secp256r1, secp512r1 and Ed448 are not yet supported."),
    ("secp256r1_sha512","Entry with name secp256r1_sha512 not found in the database.")
]

test_cases_ed_good = [
    ("Ed448_Ed448","ed448",ed448.Ed448PrivateKey)
]

async def load_db():
    mongodb_client = MongoClient("localhost",27017, serverSelectionTimeoutMS=10, connectTimeoutMS=1000)
    sandia_ca = mongodb_client.sandia_ca
    await utils.load_db(sandia_ca)

async def unload_db():
    mongodb_client = MongoClient("localhost",27017, serverSelectionTimeoutMS=10, connectTimeoutMS=1000)
    sandia_ca = mongodb_client.sandia_ca
    await utils.unload_db(sandia_ca)
    # sandia_ca.certs.drop()

@pytest.fixture(autouse=True)
def run_before_and_after_tests():
    asyncio.run(load_db())
    yield
    asyncio.run(unload_db())

# Define the pytest_generate_tests hook to generate test cases
def pytest_generate_tests(metafunc):
    if 'test_case_crypto_profile' in metafunc.fixturenames:
        # Generate test cases based on the test_cases_ec_good list
        metafunc.parametrize('test_case_crypto_profile', test_cases_crypto_profile)
    if 'test_case_entity_profile' in metafunc.fixturenames:
        # Generate test cases based on the test_cases_ec_good list
        metafunc.parametrize('test_case_entity_profile', test_cases_entity_profile)
    if 'test_case_ec_good' in metafunc.fixturenames:
        # Generate test cases based on the test_cases_ec_good list
        metafunc.parametrize('test_case_ec_good', test_cases_ec_good)
    if 'test_case_ed_good' in metafunc.fixturenames:
        # Generate test cases based on the test_cases_ed_good list
        metafunc.parametrize('test_case_ed_good', test_cases_ed_good)
    if 'test_case_error' in metafunc.fixturenames:
        # Generate test cases based on the test_cases_error list
        metafunc.parametrize('test_case_error', test_cases_error)

def test_create_crypto_profile(test_case_crypto_profile):
    profile, curve, hash = test_case_crypto_profile
    data = {
        "name": profile,
        "key_algorithm": curve,
        "signature_hash": hash
    }
    r = requests.post("http://127.0.0.1:8000/profile/crypto", headers=headers, json=data)
    assert "error" not in r.json()
    r = requests.get("http://127.0.0.1:8000/profile/crypto/"+profile, headers=headers)
    assert "error" not in r.json()
    res_data = r.json()
    assert res_data["key_algorithm"] == curve
    assert res_data["signature_hash"] == hash

def test_create_entity_profile(test_case_entity_profile):
    profile, key_usage, extended_key_usage, basic_constraints, validity, ocsp_url = test_case_entity_profile
    data = {
        "name": profile,
        "key_usage": key_usage,
        "basic_constraints": basic_constraints,
        "extended_key_usage": extended_key_usage,
        "validity": validity,
        "ocsp_url": ocsp_url
    }
    if extended_key_usage == None:
        del data["extended_key_usage"]
    r = requests.post("http://127.0.0.1:8000/profile/entity", headers=headers, json=data)
    assert "error" not in r.json()
    r = requests.get("http://127.0.0.1:8000/profile/entity/"+profile, headers=headers)
    assert "error" not in r.json()
    res_data = r.json()
    assert res_data["key_usage"] == key_usage
    assert res_data["basic_constraints"] == basic_constraints
    assert res_data["validity"] == validity
    assert res_data["ocsp_url"] == ocsp_url
    if extended_key_usage:
        res_data["extended_key_usage"] == extended_key_usage
    

def test_issue_ec_good(test_case_ec_good):
    profile, signature, curve = test_case_ec_good
    res_data = issue_root_cert(profile)
    print(res_data)
    root_serial = res_data["serial"]
    cert, key = load_cert_and_key(root_serial)
    assert cert.signature_algorithm_oid._name == signature
    assert key.curve.name == curve

def test_issue_ed_good(test_case_ed_good):
    profile, signature, private_key_class = test_case_ed_good
    res_data = issue_root_cert(profile)
    print(res_data)
    root_serial = res_data["serial"]
    cert, key = load_cert_and_key(root_serial)
    assert cert.signature_algorithm_oid._name == signature
    assert isinstance(key, private_key_class)

def test_issue_ec_error(test_case_error):
    profile, error = test_case_error
    res_data = issue_root_cert(profile)
    print(res_data)
    assert "error" in res_data
    assert res_data["error"] == error

def test_issue_chain():
    crypto_profile = "Ed448_Ed448"

    res_data = issue_root_cert(crypto_profile)
    print(res_data)
    root_serial = res_data["serial"]
    cert, key = load_cert_and_key(root_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_subca1_cert(crypto_profile, root_serial)
    print(res_data)
    subca1_serial = res_data["serial"]
    cert, key = load_cert_and_key(subca1_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_subca2_cert(crypto_profile, subca1_serial)
    print(res_data)
    subca2_serial = res_data["serial"]
    cert, key = load_cert_and_key(subca2_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_leaf_cert(crypto_profile, subca2_serial)
    print(res_data)
    leaf_serial = res_data["serial"]
    cert, key = load_cert_and_key(leaf_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_ocsp_cert(crypto_profile, subca2_serial)
    print(res_data)
    ocsp_subca2_serial = res_data["serial"]
    cert, key = load_cert_and_key(ocsp_subca2_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_ocsp_cert(crypto_profile, subca1_serial)
    print(res_data)
    ocsp_subca1_serial = res_data["serial"]
    cert, key = load_cert_and_key(ocsp_subca1_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_ocsp_cert(crypto_profile, root_serial)
    print(res_data)
    ocsp_root_serial = res_data["serial"]
    cert, key = load_cert_and_key(ocsp_root_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

def load_cert_and_key(serial: str) -> Tuple[x509.Certificate, Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]]:
    cert = load_cert(serial)
    key = load_key(serial)
    return cert, key

def load_cert(serial: str) -> x509.Certificate:
    cert_data = load_cert_as_string(serial).encode()
    cert = load_pem_x509_certificate(cert_data)
    return cert

def load_key(serial: str) -> Union[ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey]:
    key_data = load_key_as_string(serial).encode()
    key = load_pem_private_key(key_data, password=None)
    return key

def load_cert_as_string(serial: str) -> str:
    r = requests.get('http://127.0.0.1:8000/cert/'+serial, headers=headers)
    return r.json()["details"]

def load_key_as_string(serial: str) -> str:
    r = requests.get('http://127.0.0.1:8000/key/'+serial, headers=headers)
    return r.json()["details"]

def issue_root_cert(profile: str) -> dict:
    req_data = {
        "domain": "V2G",
        "profile": {
            "crypto_profile_name": profile,
            "entity_profile_name": "iso2_rootca"
        }
    }
    r = requests.post('http://127.0.0.1:8000/rootca', headers=headers, data=json.dumps(req_data))
    return r.json()

def issue_subca1_cert(profile: str, issuer_serial: str) -> dict:
    req_data = {
        "domain": "CPO",
        "profile": {
            "crypto_profile_name": profile,
            "entity_profile_name": "iso2_subca1"
        },
        "issuer_serial": issuer_serial,
        "tier": 1
    }
    r = requests.post('http://127.0.0.1:8000/subca', headers=headers, data=json.dumps(req_data))
    return r.json()

def issue_subca2_cert(profile: str, issuer_serial: str) -> dict:
    req_data = {
        "domain": "CPO",
        "profile": {
            "crypto_profile_name": profile,
            "entity_profile_name": "iso2_subca2"
        },
        "issuer_serial": issuer_serial,
        "tier": 2
    }
    r = requests.post('http://127.0.0.1:8000/subca', headers=headers, data=json.dumps(req_data))
    return r.json()

def issue_leaf_cert(profile: str, issuer_serial: str) -> dict:
    req_data = {
        "domain": "CPO",
        "profile": {
            "crypto_profile_name": profile,
            "entity_profile_name": "iso2_leaf"
        },
        "issuer_serial": issuer_serial,
        "name": "SECCLeaf"
    }
    r = requests.post('http://127.0.0.1:8000/leaf', headers=headers, data=json.dumps(req_data))
    return r.json()

def issue_ocsp_cert(profile: str, issuer_serial: str) -> dict:
    req_data = {
        "domain": "OCSP",
        "profile": {
            "crypto_profile_name": profile,
            "entity_profile_name": "iso2_ocsp"
        },
        "issuer_serial": issuer_serial
    }
    r = requests.post('http://127.0.0.1:8000/ocsp', headers=headers, data=json.dumps(req_data))
    return r.json()