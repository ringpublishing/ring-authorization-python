# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import hmac
import hashlib
import copy
from functools import partial
from datetime import datetime

#TODO Compability issues - not solved

try:
    # Py2
    import urlparse as parse
    from urllib import urlencode
except ImportError:
    # Py3
    from urllib import parse

query_parser = partial(parse.parse_qsl, keep_blank_values=True)
SCOPE = 'dl1_request'


class DLSigner(object):
    __slots__ = ['service', 'access_key', 'secret_key', 'algorithm', 'solution', 'hash_method']

    def __init__(self, service, access_key, secret_key, algorithm='DL-HMAC-SHA256', solution='RING'):
        """
        This class is initiated with five parameters in constructor. Also you are allowed to insert dictionary
        with keys as:
            :param service:
            :param access_key: Key that allows you to access to API
            :param secret_key: Key
            :param algorithm: This value has to include prefix 'DL-HMAC-SHA' with hashing algorithm.
            You are allowed to put hashing algorithms such as:
               * SHA224,
               * SHA256, - if algorithm param is missing, used as default value
               * SHA384,
               * SHA512
            for example if you choose SHA256 finally the value of 'algorithm' key looks like DL-HMAC-SHA256.
            """
        assert service is not None, 'Missing service param.'
        assert len(service) > 1, 'Missing service param.'
        self.service = service
        assert access_key is not None, 'Missing access_key param.'
        assert len(access_key) > 1, 'Missing access_key param.'
        self.access_key = access_key
        assert secret_key is not None, 'Missing secret_key param.'
        assert len(secret_key) > 1, 'Missing secret_key param.'
        self.secret_key = secret_key
        self.solution = solution

        assert algorithm.startswith('DL-HMAC-SHA'), 'Invalid hashing method.'
        self.algorithm = algorithm
        self.hash_method = algorithm.split('-')[-1].lower()
        assert self.hash_method in (
            'sha224', 'sha256', 'sha384', 'sha512'), 'Invalid hashing algorithm.'
        self.hash_method = getattr(hashlib, self.hash_method)

    @staticmethod
    def _check_sign_params(request):
        """Checks params of request dictionary."""
        assert request['method'].upper() in ('POST', 'GET', 'PUT', 'DELETE'), 'Invalid REST method.'
        assert 'headers' in request, 'Missing headers parameter.'
        assert_headers = set(k.lower() for k in request['headers'])
        assert 'host' in assert_headers, 'Missing Host parameter.'
        if 'body' in request:
            assert isinstance(request['body'], bytearray), 'Body must be instance of bytes.'
        assert 'content-type' in assert_headers
        del assert_headers
        copied_request = copy.copy(request)
        if 'X-DL-Date' not in request['headers']:
            copied_request['headers']['X-DL-Date'] = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        return copied_request

    def _sign(self, key, msg, hex_output=False):
        """Performs hashing, returns digest or hexdigest depending on 'hex_output' argument"""
        key = key if isinstance(key, bytes) else key.encode('utf-8')
        msg = msg if isinstance(msg, bytes) else msg.encode('utf-8')
        sign = hmac.new(key, msg, self.hash_method)
        return sign.digest() if not hex_output else sign.hexdigest()

    def _get_canonical_request(self, request):
        """Return formatted string of canonical request data"""
        method = request['method']
        uri = request['uri'] or '/'
        payload = request.get('body', b'')
        headers = self._get_headers(request)

        if '?' in uri:
            uri, params = uri.split('?', 1)
            params = sorted(query_parser(params))
            params = parse.urlencode(params, quote_via=parse.quote)
        else:
            params = ''

        return "{method}\n{uri}\n{params}\n{canonical_headers}\n{signed_headers}\n{payload_hash}".format(
            method=method,
            uri=parse.quote(uri, safe='', encoding='utf-8'),
            params=params,
            canonical_headers=headers['canonical_headers'],
            signed_headers=headers['signed_headers'],
            payload_hash=self.hash_method(payload).hexdigest()
        )

    @staticmethod
    def _get_headers(request):
        """Method returning dictionary with formatted string of canonical_headers and signned_headers"""
        canonical_headers = []
        signed_headers = []

        for header_key, header_value in sorted(request['headers'].items(), key=lambda s: s[0].lower()):
            canonical_headers.append('{}:{}'.format(header_key.lower(), header_value.strip()))
            signed_headers.append(header_key.lower())
        canonical_headers = '\n'.join(canonical_headers)
        signed_headers = ';'.join(signed_headers)

        return {'canonical_headers': canonical_headers,
                'signed_headers': signed_headers}

    def _get_string_to_sign(self, canonical_request, date):
        return "{algorithm}\n{date}\n{scope}\n{canonical_request_hash}".format(
            algorithm=self.algorithm,
            date=date,
            scope=date[:8] + '/' + self.solution + '/' + self.service + '/' + SCOPE,
            canonical_request_hash=self.hash_method(canonical_request.encode('utf-8')).hexdigest()
        )

    def _get_signing_key(self, date):
        key = self._sign('DL' + self.secret_key, date[:8])
        key = self._sign(key, self.solution)
        key = self._sign(key, self.service)
        key = self._sign(key, SCOPE)
        return key

    def _get_signature(self, request):
        """Get_signature is calling other methods to process data to finally
            return a signature. """
        canonical_request = self._get_canonical_request(request)
        string_to_sign = self._get_string_to_sign(canonical_request, request['headers']['X-DL-Date'])
        signing_key = self._get_signing_key(request['headers']['X-DL-Date'])
        signature = self._sign(signing_key, string_to_sign, True)
        return signature

    def sign(self, original_request):
        """
        Method dedicated for signing requests.

            :param original_request: has to be an instance of dict with values:
                * method: - with values POST/GET/PUT/DELETE
                * uri: URI of the request. If there is no URI given in request dict,
                program will insert default value of URI.
                * headers: - headers of your requests. This key has to be a dictionary.
                    Into headers you have to put 'host' key.
                * payload: - optional.

        Before method proceed all data they are being checked by check_sign_params method and
        if there will not happen any failture function is returning dictionary with Authorization
        and X-DL-Date header.

        :returns: dict:
        """
        request = self._check_sign_params(original_request)
        return {'Authorization':
            '{algorithm} Credential={credentials},SignedHeaders={signed_headers},Signature={signature}'.format(
                algorithm=self.algorithm.upper(),
                credentials=self.access_key + '/' + request['headers']['X-DL-Date'] +
                            '/' + self.solution + '/'
                            + self.service + '/' + SCOPE,
                signed_headers=self._get_headers(request)['signed_headers'],
                signature=self._get_signature(request)
            ),
            'X-DL-Date': request['headers']['X-DL-Date']}

    def verify_sign(self, request, authorization_header):
        return self.sign(request)['Authorization'] == authorization_header
