from src import DLSigner

# Sample test of class

opt = {
    'service': 'pulsapi',
    'access_key': 'access_key',
    'secret_key': 'secret_key',
}

request = {
    'method': 'GET',
    'uri': '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20&test=t^e s&aws',
    'headers': {
        'host': 'api.ring.example.eu',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-DL-Date': '20190201T143000Z'
    }
}

signer = DLSigner(**opt)
signature = signer.sign(request)
print(signature)
