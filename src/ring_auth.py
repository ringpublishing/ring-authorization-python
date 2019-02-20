#! /usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import hmac
import hashlib
from copy import deepcopy
from datetime import datetime

try:
    from urllib import quote
    from urlparse import urlparse, parse_qsl
except ImportError:
    from urllib.parse import quote, urlparse, parse_qsl

SCOPE = 'dl1_request'


class DLSigner(object):
    __slots__ = ['service', 'access_key', 'secret_key', 'algorithm', 'solution', 'hash_method']

    def __init__(self, service, access_key, secret_key, algorithm='DL-HMAC-SHA256', solution='RING'):
        """
        Signer initialization, accepts arguments that are constant in
        signing process and not related to specific request
        :param service:
        :param access_key: Key that allows you to access to API
        :param secret_key: Key
        :param algorithm: One of following hashing algorithms:
            * DL-HMAC-SHASHA224,
            * DL-HMAC-SHASHA256, - if algorithm param is missing, used as default value
            * DL-HMAC-SHASHA384,
            * DL-HMAC-SHASHA512
        :param solution: Solution which aggregates a several services.
        """
        assert service, 'Missing service parameter.'
        self.service = service
        assert access_key, 'Missing access_key parameter.'
        self.access_key = access_key
        assert secret_key, 'Missing secret_key parameter'
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
        assert 'headers' in request, 'Missing headers.'
        assert_headers = set(k.lower() for k in request['headers'])
        assert 'host' in assert_headers, 'Missing Host parameter.'
        if 'body' in request:
            assert isinstance(request['body'], bytearray), 'Body must be instance of bytes.'
        assert 'content-type' in assert_headers
        copied_request = deepcopy(request)
        if 'x-dl-date' not in assert_headers:
            copied_request['headers']['X-DL-Date'] = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        del assert_headers
        return copied_request

    def _sign(self, key, msg, hex_output=False):
        """Performs hashing, returns digest or hexdigest depending on 'hex_output' argument."""
        key = key if isinstance(key, bytes) else key.encode('utf-8')
        msg = msg if isinstance(msg, bytes) else msg.encode('utf-8')
        sign = hmac.new(key, msg, self.hash_method)
        return sign.digest() if not hex_output else sign.hexdigest()

    def _get_canonical_request(self, request):
        """Return formatted string of canonical request data."""
        method = request['method']
        uri = urlparse(request.get('uri', '/'))
        payload = request.get('body', b'')
        headers = self._get_headers(request)

        params = parse_qsl(uri.query, keep_blank_values=True)
        params = '&'.join('{}={}'.format(quote(k, safe='-_.~'), quote(v, safe='-_.~')) for k, v in sorted(params))

        return "{method}\n{uri}\n{params}\n{canonical_headers}\n{signed_headers}\n{payload_hash}".format(
            method=method,
            uri=quote(uri.path, safe='/-_.~'),
            params=params,
            canonical_headers=headers['canonical_headers'],
            signed_headers=headers['signed_headers'],
            payload_hash=self.hash_method(payload).hexdigest()
        )

    @staticmethod
    def _get_headers(request):
        """Method returning dictionary with formatted strings of canonical_headers and signed_headers."""
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
        Signs request and returns dictionary with parameters required for authorization process.
            :param original_request: has to be an instance of dict with keys:
                * method: - with values POST/GET/PUT/DELETE
                * uri: URI of the request. If there is no URI given in request dict,
                program will insert default value of URI.
                * headers: - headers of your requests. This key has to be a dictionary.
                    Into headers you have to put 'host' key.
                * payload: - optional.
        :returns: dict:
        """
        request = self._check_sign_params(original_request)
        return {
            'Authorization':
                '{algorithm} Credential={credentials},SignedHeaders={signed_headers},Signature={signature}'.format(
                    algorithm=self.algorithm.upper(),
                    credentials=self.access_key + '/' + request['headers']['X-DL-Date'][:8] +
                                '/' + self.solution + '/'
                                + self.service + '/' + SCOPE,
                    signed_headers=self._get_headers(request)['signed_headers'],
                    signature=self._get_signature(request)
                ),
            'X-DL-Date': request['headers']['X-DL-Date']}


if __name__ == '__main__':
    import sys
    from functools import partial

    try:
        import argparse
    except ImportError:
        print('Python 2.7 or >= 3.2 required')
        exit(-1)

    parser = argparse.ArgumentParser(prog='ring_auth',
                                     description='Generates signature headers for Ring publishing API requests')

    parser.add_argument('--service', help='Ring service (e.g. "pulsapi")', required=True)
    parser.add_argument('--access', help='API access key', required=True)
    parser.add_argument('--secret', help='API secret key', required=True)
    parser.add_argument('--header', help='Headers to sign in format Name:Value, '
                                         '(at least "Host" and "Content-Type" must be provided)',
                        required=True, nargs='+')
    parser.add_argument('--payload', help='Request payload (UTF-8 string)', default='',
                        type=partial(bytearray, encoding='utf-8'))
    parser.add_argument('--method', help='HTTP method', required=True,
                        choices=['GET', 'POST', 'PUT', 'DELETE'])
    parser.add_argument('--uri', help='Request URI, (default: /)', default='/')
    parser.add_argument('--algorithm', help='Hashing method (default: "DL-HMAC-SHA256")',
                        default='DL-HMAC-SHA256', dest='alg')
    parser.add_argument('--output-file', nargs='?', type=argparse.FileType('w'), default=sys.stdout)
    parser.add_argument('--output-format', help='Signature output format', default='raw', choices=['json', 'raw'])
    args = parser.parse_args()

    signer = DLSigner(service=args.service, access_key=args.service, secret_key=args.secret, algorithm=args.alg)
    try:
        result = signer.sign(dict(
            method=args.method,
            uri=args.uri,
            headers=dict(h.split(':') for h in args.header)
        ))
    except Exception as e:
        print('Unable to generate signature due to error: ', e)
        exit(1)
    else:
        if args.output_format == 'json':
            import json

            result = json.dumps(result)
        else:
            result = '\n'.join(':'.join(r) for r in result.items())

        args.output_file.write(result)
        args.output_file.write('\n')
        args.output_file.close()

        exit(0)
