from src import DLSigner

# Sample test of class

opt = {
    'service': 'pulsapi',
    'access_key': 'AKID',
    'secret_key': 'TEST',
    'solution': 'region',
}

request = {
    'method': 'GET',
    'uri': '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20&test=t^e s&aws',
    'headers': {
        'host': 'test',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-DL-Date': '20190128T155100Z'
    },
    'body': bytearray('test', encoding='utf-8'),
}

authlib = DLSigner(**opt)
sign_header = authlib.sign(request)
print(sign_header)
