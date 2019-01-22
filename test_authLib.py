import authclient

# Sample test of class

lib = {
    'method': 'POST',
    'uri': '/api/test/getall',
    'hash_method': 'DL-HMAC-SHA256',
    'payload': '',
    'headers': {
        'host': '1',
        'elel2p': '1',
        'elel23p': '1',
        'ele555lp': '1',
        'abcd': '2'
    },
    'solution': 'onetapi',
    'api_key': 'apikey',
    'api-client-id': 'apiclientid'
}

authlib = authclient.AuthLib(lib)
header = authlib.signrequest()
print(header)
