import authclient

# Sample test of class

lib = {
    'method': 'POST',
    'uri': '/api/test/getall',
    'hash_method': 'DL-HMAC-SHA256',
    'payload': '',
    'headers': {
        'host': '1',
        'content-type': 'costam',
    },
    'solution': 'onetapi',
    'api_key': 'apikey',
    'secret': 'secret'
}

authlib = authclient.AuthLib(lib)
header = authlib.sign()
print(header)
