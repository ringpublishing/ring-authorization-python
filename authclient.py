import datetime
import hmac
import urllib
from functools import partial
from urllib import parse

query_parser = partial(urllib.parse.parse_qsl, keep_blank_values=True)
ring_service = 'pulsapi'
request_scope = 'dl1_request'


class AuthLib(object):
    __slots__ = ['info']

    def __init__(self, info):
        self.info = info
        assert isinstance(info, dict), 'Invalid type of constructor parameter.'
        assert len(info) > 0, 'Dictionary is empty.'
        assert info['method'].upper() == 'POST' or \
               info['method'].upper() == 'GET' or \
               info['method'].upper() == 'PUT' or \
               info['method'].upper() == 'DELETE', 'Invalid REST method.'
        assert info['hash_method'].startswith('DL-HMAC-SHA'), 'Invalid hashing method.'
        assert info['hash_method'].split('-')[-1].lower() in (
            'sha224', 'sha256', 'sha384', 'sha512'), 'Invalid hashing algorithm.'
        assert info['headers']['host'] is not None, 'Missing host parameter.'
        if info['payload'] is None:
            info['payload'] = ''
        assert isinstance(info['payload'], str), 'Payload has to be converted to string.'
        assert info['solution'] is not None, 'Missing solution.'
        info['date'] = datetime.datetime.utcnow()

    def _sign(self, key, msg, hex_output=False):
        """Performs hashing, returns digest or hexdigest depending on 'hex_output' argument"""
        sign = hmac.new(bytes(str(key).encode('utf-8')), msg.encode('utf-8'), self.info['hash_method'].split('-')[-1].lower())
        return sign.digest() if not hex_output else sign.hexdigest()

    def _get_canonical_request(self):
        method = self.info['method']
        uri = self.info['uri']
        payload = self.info['payload']
        headers = self._get_headers()

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

    def _get_headers(self):
        canonical_headers = ''
        sign_headers = ''

        for header_key, header_value in sorted(self.info['headers'].items()):
            canonical_headers += '{}:{}'.format(header_key.lower().strip(), header_value.lower().strip())
            sign_headers += header_key + ' '
        sign_headers = ';'.join(sign_headers.split())

        return {'canonical_headers': canonical_headers,
                'sign_headers': sign_headers}

    def _get_string_to_sign(self, canonical_request):
        return "{hash_method}\n{date}\n{scope}\n{canonical_request_hash}".format(
            hash_method=self.info['hash_method'],
            date=self.info['date'].strftime('%Y%m%dT%H%M%SZ'),
            scope=request_scope,
            canonical_request_hash=self._sign(self.info['secret'], canonical_request, True)
        )

    def _get_signing_key(self):
        key = self._sign(self.info['secret'], self.info['date'].strftime('%Y%m%d'))
        key = self._sign(key, 'solution')
        key = self._sign(key, ring_service)
        key = self._sign(key, request_scope)
        return key

    def _get_signature(self):
        canonical_request = self._get_canonical_request()
        string_to_sign = self._get_string_to_sign(canonical_request)
        signing_key = self._get_signing_key()
        signature = self._sign(signing_key, string_to_sign, True)
        return signature

    def sign(self):
        return {'Authorization':
                '{hash_method} Credential={credentials},SignedHeaders={signed_headers},Signature={signature}'.format(
                    hash_method=self.info['hash_method'],
                    credentials=self.info['api_key'] + '/' + self.info['date'].strftime('%Y%m%d') + '/' + self.info['solution'] + '/' + ring_service + '/' + request_scope,
                    signed_headers=self._get_headers()['sign_headers'],
                    signature=self._get_signature()
                )}
