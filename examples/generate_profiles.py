import requests

def create_crypto_profile(crypto_profile: str, ca_url: str, headers: dict):
    data = {
        "name": crypto_profile,
        "key_algorithm": crypto_profile.split(sep = "_")[0],
        "signature_hash": crypto_profile.split(sep = "_")[1]
    }
    r = requests.post(ca_url+"profile/crypto", headers=headers, json=data)
    print(r.json())

def create_entity_profiles(ocsp_url: str, ca_url: str, headers: dict):
    data = {
        "name": "iso2_rootca",
        "key_usage": [
            False, False, False, False, False, True, True, False, False
        ],
        "basic_constraints": [
            True, None
        ],
        "validity": [
            40, 0, 0
        ],
        "ocsp_url": None
    }
    r = requests.post(ca_url+"profile/entity", headers=headers, json=data)
    print(r.json())

    data = {
        "name": "iso2_subca1",
        "key_usage": [
            False, False, False, False, False, True, True, False, False
        ],
        "basic_constraints": [
            True, 1
        ],
        "validity": [
            4, 0, 0
        ],
        "ocsp_url": ocsp_url
    }
    r = requests.post(ca_url+"profile/entity", headers=headers, json=data)
    print(r.json())

    data = {
        "name": "iso2_subca2",
        "key_usage": [
            False, False, False, False, False, True, True, False, False
        ],
        "basic_constraints": [
            True, 0
        ],
        "validity": [
            2, 0, 0
        ],
        "ocsp_url": ocsp_url
    }
    r = requests.post(ca_url+"profile/entity", headers=headers, json=data)
    print(r.json())

    data = {
        "name": "iso2_leaf",
        "key_usage": [
            True, False, False, False, False, False, False, False, False
        ],
        "basic_constraints": [
            False, None
        ],
        "validity": [
            1, 0, 0
        ],
        "ocsp_url": ocsp_url
    }
    r = requests.post(ca_url+"profile/entity", headers=headers, json=data)
    print(r.json())

    data = {
        "name": "iso2_ocsp",
        "key_usage": [
            False, False, False, False, False, False, False, False, False
        ],
        "extended_key_usage": [
            "ocsp_signing"
        ],
        "basic_constraints": [
            False, None
        ],
        "validity": [
            1, 0, 0
        ],
        "ocsp_url": None
    }
    r = requests.post(ca_url+"profile/entity", headers=headers, json=data)
    print(r.json())