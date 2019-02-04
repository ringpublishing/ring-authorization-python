# Dreamlab AWS signer

### Quick start

To create a new object that will sign your request you have to create two dictionaries with following keys:  

```
options = {
    'service': 'pulsapi',
    'access_key': 'AKID',
    'secret_key': 'TEST',
}
```

You can specify encrypting algorithm used in signature creation. 
Add *algorithm* key with one of the following values:
* DL-HMAC-SHA224
* DL-HMAC-SHA256 (default value)
* DL-HMAC-SHA384
* DL-HMAC-SHA512

**PREFIX DL-HMAC-SHA IS NECESSESARY**

Additionaly you are allowed to specify a key named *solution*. In this case
this word means solution that aggregates a several services. The default value is "RING".

```
request = {
    "method": "POST",   
    "uri": "/test/api",  
    "headers": {  
        "host": "tmp",  
        "Content-Type": "application/json"   
    },
    'body': b'',
}
```
As body value you have to put data as an bytearray.

Next, create instance of a DLSigner class with an *options* dictionary given as a parameter of a constructor.
Then call *sign* method with a *request* dictionary.
```
authlib = DLSigner(**options)
header = authlib.sign(request)
```

From now variable *header* will store dictionary which allows to authenticate your request. 
