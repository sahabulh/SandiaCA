import json, requests, asyncio, sys, pytest

from cryptography.hazmat.primitives.asymmetric import ed448

from pymongo import MongoClient

from pathlib import Path
abs_path = str(Path(__file__).absolute().parent)
sys.path.append(str(Path(__file__).absolute().parent.parent))

import utils
from utils import load_cert_and_key

headers = {
    'accept':       'application/json',
    'X-API-KEY':    'iamadmin',
    'Content-Type': 'application/json',
}

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
    if 'test_case_ec_good' in metafunc.fixturenames:
        # Generate test cases based on the test_cases_ec_good list
        metafunc.parametrize('test_case_ec_good', test_cases_ec_good)
    if 'test_case_ed_good' in metafunc.fixturenames:
        # Generate test cases based on the test_cases_ed_good list
        metafunc.parametrize('test_case_ed_good', test_cases_ed_good)
    if 'test_case_error' in metafunc.fixturenames:
        # Generate test cases based on the test_cases_error list
        metafunc.parametrize('test_case_error', test_cases_error)

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
    root_serial = res_data["serial"]
    cert, key = load_cert_and_key(root_serial)
    assert cert.signature_algorithm_oid._name == signature
    assert isinstance(key, private_key_class)

def test_issue_ec_error(test_case_error):
    profile, error = test_case_error
    res_data = issue_root_cert(profile)
    assert "error" in res_data
    assert res_data["error"] == error

def test_issue_chain():
    crypto_profile = "Ed448_Ed448"

    res_data = issue_root_cert(crypto_profile)
    root_serial = res_data["serial"]
    cert, key = load_cert_and_key(root_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_subca1_cert(crypto_profile, root_serial)
    subca1_serial = res_data["serial"]
    cert, key = load_cert_and_key(subca1_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_subca2_cert(crypto_profile, subca1_serial)
    subca2_serial = res_data["serial"]
    cert, key = load_cert_and_key(subca2_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_leaf_cert(crypto_profile, subca2_serial)
    leaf_serial = res_data["serial"]
    cert, key = load_cert_and_key(leaf_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_ocsp_cert(crypto_profile, subca2_serial)
    ocsp_subca2_serial = res_data["serial"]
    cert, key = load_cert_and_key(ocsp_subca2_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_ocsp_cert(crypto_profile, subca1_serial)
    ocsp_subca1_serial = res_data["serial"]
    cert, key = load_cert_and_key(ocsp_subca1_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

    res_data = issue_ocsp_cert(crypto_profile, root_serial)
    ocsp_root_serial = res_data["serial"]
    cert, key = load_cert_and_key(ocsp_root_serial)
    assert cert.signature_algorithm_oid._name == "ed448"
    assert isinstance(key, ed448.Ed448PrivateKey)

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