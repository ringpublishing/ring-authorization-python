import datetime, urllib, hmac
from functools import partial
from urllib import parse

query_parser = partial(urllib.parse.parse_qsl, keep_blank_values=True)


class AuthLib(object):
    __slots__ = ['info']

    def __init__(self, info):
        self.info = info
        assert isinstance(info, dict), 'In constructor you have to insert dictionary.'
        assert len(info) > 0, 'Dictionary is empty.'
        assert info['method'].upper() == 'POST' or \
               info['method'].upper() == 'GET' or \
               info['method'].upper() == 'PUT' or \
               info['method'].upper() == 'DELETE', 'Invalid REST method.'
        assert info['hash_method'].startswith('DL-HMAC-SHA'), 'Invalid hashing method.'
        assert info['headers']['host'] is not None, 'You have to insert host into headers.'
        assert isinstance(info['payload'], str), 'Payload has to be converted to string.'
        # info['hash_method'] = info['hash_method'].split('-')[-1].lower()
        # assert info['hash_method'] in ('sha224', 'sha256', 'sha384', 'sha512'), 'Invalid hash method'
        assert info['hash_method'].split('-')[-1].lower() in (
            'sha224', 'sha256', 'sha384', 'sha512'), 'Invalid hash method'
        if info['payload'] is None:
            info['payload'] = ''
        info['date'] = datetime.datetime.utcnow()
        assert info['solution'] is not None, 'You have to write solution'

    def _sign(self, key, msg, hex_output=False):
        """Performs hashing, returns digest or hexdigest depending on 'hex_output' argument"""
        sign = hmac.new(bytes(str(key), encoding='utf-8'), msg.encode('utf-8'),
                        self.info['hash_method'].split('-')[-1].lower())
        return sign.digest() if not hex_output else sign.hexdigest()

    def _getcanonicalreq(self):
        method = self.info['method']
        uri = self.info['uri']
        payload = self.info['payload']
        headers = self._getheaders()

        # CanonicalQueryString
        if '?' in uri:
            uri, params = uri.split('?', 1)
            params = sorted(query_parser(params))
            params = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        else:
            params = ''

        return "\n{method}\n{uri}\n{params}\n{canonical_headers}\n{signed_headers}\n{payload_hash}".format(
            method=method,
            uri=uri,
            params=params,
            canonical_headers=headers['canonical_headers'],
            signed_headers=headers['sign_headers'],
            payload_hash=self._sign(self.info['secret'], payload, True)
        )

    def _getheaders(self):
        can_headers = ''
        sign_headers = ''

        for key, value in sorted(self.info['headers'].items()):
            can_headers += '{}:{}'.format(key.lower().strip(), value.lower().strip())
            sign_headers += key + ' '
        sign_headers = ';'.join(sign_headers.split())

        return {'canonical_headers': can_headers,
                'sign_headers': sign_headers}

    def _getstringtosign(self, canreq):
        return "{hash_method}\n{date}\n{scope}\n{canreqhash}".format(
            hash_method=self.info['hash_method'],
            date=self.info['date'].strftime('%Y%m%dT%H%M%SZ'),
            scope='dl1_request',
            canreqhash=self._sign(self.info['secret'], canreq, True)
        )

    def _getsigningkey(self):
        key = self._sign(self.info['secret'], self.info['date'].strftime('%Y%m%d'))
        key = self._sign(key, 'solution')
        key = self._sign(key, 'pulsapi')
        key = self._sign(key, 'dl1_request')
        return key

    def _getsignature(self):
        canrequest = self._getcanonicalreq()
        strtosign = self._getstringtosign(canrequest)
        signingkey = self._getsigningkey()
        signature = self._sign(signingkey, strtosign, True)
        return signature

    def signrequest(self):
        return {'Authorization': self.info['hash_method'] + \
                                 ' Credential=' +
                                 self.info['api_key'] + '/' +
                                 self.info['date'].strftime('%Y%m%d') + '/' +
                                 self.info['solution'] +
                                 '/pulsapi/dl1_request, SignedHeaders=' + \
                                 self._getheaders()['sign_headers'] + \
                                 ', Signature=' + self._getsignature()}
