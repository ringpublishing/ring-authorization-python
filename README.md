# Dreamlab AWS signer

### Quick start

To create a new object that will sign your request you have to create two dictionaries with following keys:  

```
options = {
    'service': 'pulsapi',
    'access_key': 'AKID',
    'secret_key': 'TEST',
    'solution': 'region',
}
```
Solution key is not cecessary to provide. The default value is RING.

Also you are allowed to provide your own encrypting algorithm. To do that you have to insert into options dictionary
key named 'algorithm' with one of following values:
* DL-HMAC-SHA224
* DL-HMAC-SHA256
* DL-HMAC-SHA384
* DL-HMAC-SHA512

**PREFIX DL-HMAC-SHA IS NECESSESARY**

```
request = {
    "method": "POST",   
    "uri": "/test/api",  
    "headers": {  
        "host": "tmp",  
        "Content-Type": "application/json"   
    },
    'body': ''
}
```
As body value you have to put data as an bytearray encoded with utf-8 as shown below.

```
'body': bytearray(data, encoding='utf-8')
```

Next create instance of DLSigner class with dictionary given as a parameter of a constructor.
And call 'sign' method with a second dictionary which you created in parameter of method.
```
authlib = ring_auth_python.Auth(**options)
header = authlib.sign(request)
```

From now variable 'header' will store dictionary with keys 'Authorization' and 'X-DL-Date' which are nessesary to authenticate your request. 
