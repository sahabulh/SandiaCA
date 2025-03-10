import requests

def create_crypto_profile(crypto_profile: str, ca_url: str, headers: dict):
    """Generates example crypto profiles.

    :param crypto_profile: Name of the crypto profile. It is in the format of
                           {key_algorithm}_{signature_hash}
    :type crypto_profile: str
    :param ca_url: URL of the CA server.
    :type ca_url: str
    :param headers: Headers for authenticating endpoint in FastAPI. 
    :type headers: dict
    """
    data = {
        "name": crypto_profile,
        "key_algorithm": crypto_profile.split(sep = "_")[0],
        "signature_hash": crypto_profile.split(sep = "_")[1]
    }
    r = requests.post(ca_url+"/profile/crypto", headers=headers, json=data)

def create_entity_profiles(ocsp_url: str, ca_url: str, headers: dict):
    """Generates example entity profiles.

    :param ocsp_url: OCSP responder URL
    :type ocsp_url: str
    :param ca_url: URL of the CA server. Is also the base URL for CRLs.
    :type ca_url: str
    :param headers: Headers for authenticating endpoint in FastAPI. 
    :type headers: dict
    """
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
        "ocsp_url": None,
        "crl_url": None
    }
    r = requests.post(ca_url+"/profile/entity", headers=headers, json=data)

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
        "ocsp_url": ocsp_url,
        "crl_url": ca_url
    }
    r = requests.post(ca_url+"/profile/entity", headers=headers, json=data)

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
        "ocsp_url": ocsp_url,
        "crl_url": ca_url
    }
    r = requests.post(ca_url+"/profile/entity", headers=headers, json=data)

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
        "ocsp_url": ocsp_url,
        "crl_url": ca_url
    }
    r = requests.post(ca_url+"/profile/entity", headers=headers, json=data)

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
        "ocsp_url": None,
        "crl_url": None
    }
    r = requests.post(ca_url+"/profile/entity", headers=headers, json=data)