import json, os, requests

headers = {
    'accept':       'application/json',
    'Content-Type': 'application/json',
}

data = {
    "name": "abc"
}

r = requests.post('http://127.0.0.1:8000/', headers=headers, data=json.dumps(data))
d = r.json()

print(d)