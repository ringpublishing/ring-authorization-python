# ring-authorization-python

RING requests authorization library for Python (version > 2).
For more information, please read [RING authorization docs](http://doc.dreamlab/RingAuth/index.html)

# Example usage

When sending HTTP requests to RING, all requests must be signed so that RING can identify who sent them.
In order to sign a request, you need to provide RING access key, RING secret key and the name of the service you make a
request to. If you do not know what those properties are or how to get them, please contact someone from RING Publishing.

```python
from src import DLSigner

options = {
    'service': 'pulsapi',
    'access_key': 'access_key',
    'secret_key': 'secret_key',
}

signer = DLSigner(**options)
```

Then, prepare a request which **must** contain *method* and *headers* fields. Moreover, *headers* **must** contain *Host*
and *Content-Type* fields.

```python
request = {
    'method': 'GET',
    'uri': '/resources?param1=val1',
    'headers': {
        'Host': 'api.ring.example.eu',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
}

signature = signer.sign(request)
print(signature)
# { 
#   Authorization: 'DL-HMAC-SHA256 Credential=access_key/20190618/RING/pulsapi/dl1_request,SignedHeaders=accept;content-type;host;x-dl-date,Signature=1abb0ff8c0869749e9db5c50ca3202b1ccae610155b4e7fcaca02ff07398b4d6'
#   'X-DL-Date': '20190618T103857Z'
# }

```

Finally, add calculated signature to the request.
```python
signedRequest = {
    'method': 'GET',
    'uri': '/resources?param1=val1',
    'headers': {
        'Host': 'api.ring.example.eu',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'DL-HMAC-SHA256 Credential=access_key/20190618/RING/pulsapi/dl1_request,SignedHeaders=accept;content-type;host;x-dl-date,Signature=1abb0ff8c0869749e9db5c50ca3202b1ccae610155b4e7fcaca02ff07398b4d6',
        'X-DL-Date': '20190618T103857Z'
    }
}
```

## POST request

If a request contains a body, then it should be passed as a array of bytes.

```python
request = {
    "method": "POST",   
    "uri": "/resources",  
    "headers": {  
        'Host': 'api.ring.example.eu',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    },
    'body': b'', # array of bytes
}
```
