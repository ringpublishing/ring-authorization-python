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
    'body': bytearray('test', encoding='utf-8'),
}
```
As body value you have to put data as an bytearray encoded with utf-8 as shown below.

```
'body': bytearray(data, encoding='utf-8')
```

Next, create instance of a DLSigner class with an *options* dictionary given as a parameter of a constructor.
Then call *sign* method with a *request* dictionary.
```
authlib = DLSigner(**options)
header = authlib.sign(request)
```

From now variable 'header' will store dictionary which allows to authenticate your request. 
