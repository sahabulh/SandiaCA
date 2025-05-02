import requests

headers = {
    'accept':       'application/json',
    'X-API-KEY':    'iamadmin',
    'Content-Type': 'application/json',
}

def revoke_cert(serial):
    d = {"serial": serial}
    r = requests.post('http://127.0.0.1:8000/revoke/'+serial, headers=headers)
    res = r.json()
    print(res['details'])

if __name__ == "__main__":
    r = requests.get('http://127.0.0.1:8000/cert', headers=headers)
    d = r.json()["data"]

    for cert in d:
        if cert['name'] == 'Contract Certificate':
            revoke_cert(cert['serial'])