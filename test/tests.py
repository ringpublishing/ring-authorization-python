import unittest
import sys
from datetime import datetime
from src import DLSigner

try:
    from unittest.mock import patch
    from unittest.mock import MagicMock
except ImportError:
    pass


class SignerTests(unittest.TestCase):
    def setUp(self):
        self.request = {
            'method': 'GET',
            'uri': '/test',
            'headers': {
                'host': 'test',
                'Content-Type': 'application/json',
                'X-DL-Date': '19700101T010000Z',
                'accept': 'application/json'
            },
        }

        self.request_with_payload = {
            'method': 'POST',
            'uri': '/test',
            'headers': {
                'host': 'test',
                'content-type': 'application/json',
                'accept': 'application/json',
                'X-DL-Date': '19700101T010000Z'
            },
            'body': bytearray('test', encoding='utf-8')
        }

        self.options = {
            'service': 'pulsapi',
            'access_key': 'test',
            'secret_key': 'test'
        }

    def test_returned_instance_after_sign(self):
        self.assertTrue(isinstance(DLSigner(**self.options).sign(self.request), dict),
                        'Sign method is not returning dictionary.')

    def test_if_exists_returned_authorization_key_after_call_sign_method(self):
        self.assertFalse(DLSigner(**self.options).sign(self.request).get('Authorization', None) is None,
                         'Authorization header does not exist.')

    def test_returned_authorization_header_algorithm_prefix(self):
        values = DLSigner(**self.options).sign(self.request)['Authorization'].split()
        self.assertEqual(values[0][:11], 'DL-HMAC-SHA', 'Returned header contains invalid algorithm header.')

    def test_assertion_error_on_invalid_algorithm(self):
        self.options['algorithm'] = 'sha256'
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_on_invalid_algorithm_prefix(self):
        self.options['algorithm'] = 'DL-HMAC-SHA1'
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_algorithm_default_value_insertion_on_return(self):
        self.assertEqual(DLSigner(**self.options).algorithm, 'DL-HMAC-SHA256',
                         'Invalid default value of algorithm.')

    def test_assertion_error_on_service_None_type(self):
        self.options['service'] = None
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_on_service_empty_string(self):
        self.options['service'] = ''
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_on_access_key_None_type(self):
        self.options['access_key'] = None
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_on_access_key_empty_string(self):
        self.options['access_key'] = ''
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_on_secret_key_None_type(self):
        self.options['secret_key'] = None
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_on_secret_key_empty_string(self):
        self.options['secret_key'] = ''
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_on_request_body_string_type(self):
        self.request['body'] = 'string'
        with self.assertRaises(AssertionError):
            DLSigner(**self.options).sign(self.request)

    def test_assertion_error_on_no_host_provided_in_headers(self):
        self.request['headers'].pop('host')
        with self.assertRaises(AssertionError):
            DLSigner(**self.options).sign(self.request)

    def test_assertion_error_on_no_content_type_provided(self):
        self.request['headers'].pop('Content-Type')
        with self.assertRaises(AssertionError):
            DLSigner(**self.options).sign(self.request)

    def test_assertion_error_on_invalid_body(self):
        self.request_with_payload['body'] = 'test'
        with self.assertRaises(AssertionError):
            DLSigner(**self.options).sign(self.request_with_payload)

    def test_default_date_if_date_was_not_provided(self):
        self.request['headers'].pop('X-DL-Date')
        test_request = DLSigner(**self.options).sign(self.request)
        self.assertTrue('X-DL-Date' in test_request.keys(), 'Signer did not return X-DL-Date header.')
        self.assertNotIn('X-DL-Date', self.request['headers'])

    def test_signature_with_default_date_and_returned_date_key(self):
        self.request['headers'].pop('X-DL-Date')
        self.assertEqual(DLSigner(**self.options).sign(self.request)['X-DL-Date'],
                         datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'),
                         'Default value of X-DL-Date is not equal to actual date.')

    @unittest.skipIf(sys.version_info < (3, 3, 0), 'Test not supported by this Python version.')
    @patch('src.ring_auth.datetime')
    def test_insertion_of_datetime(self, mock_datetime):
        mock_datetime.utcnow = MagicMock(return_value=datetime(2010, 12, 21, 10, 0, 0))
        self.request['headers'].pop('X-DL-Date')
        self.assertEqual(DLSigner(**self.options).sign(self.request)['X-DL-Date'],
                         mock_datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'),
                         'Default value of X-DL-Date is not equal to actual date.')

    def test_sign_without_query(self):
        self.assertEqual(DLSigner(**self.options).sign(self.request)['Authorization'],
                         'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                         'accept;content-type;host;x-dl-date,Signature=' +
                         '267247df1f154aefc4d27033245fa55cb8abb31f48a85ba55ebfaf82aec4a187')

    def test_sign_with_query(self):
        self.request['uri'] = '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20'
        self.assertEqual(DLSigner(**self.options).sign(self.request)['Authorization'],
                         'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                         'accept;content-type;host;x-dl-date,Signature=' +
                         'ca334d74f2c3b9cc0415b9383966ac1e3c18bd43d9941c5ecdfe272a90aec8f0')

    def test_sign_with_unsorted_query(self):
        self.request['uri'] = '/test?Zzz&aaa=B&Aaa'
        self.assertEqual(DLSigner(**self.options).sign(self.request)['Authorization'],
                         'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                         'accept;content-type;host;x-dl-date,Signature=' +
                         'ebfa4276ec80c405cf24d8c5b0816449309427a50cfbd3975a8894aea9d6fdbc')

    def test_sign_with_whitespace_in_query(self):
        self.request['uri'] = '/test/test2?Zzz&aaa=B&Aaa= aw'
        self.assertEqual(DLSigner(**self.options).sign(self.request)['Authorization'],
                         'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                         'accept;content-type;host;x-dl-date,Signature=' +
                         '9e5bc2455a134e86095e7fb631c57d84b2d6c7c8b3db3c0e9ecac96a9068af62')

    def test_sign_with_unreserved_chars_in_query(self):
        self.request['uri'] = '/test/test2?Zzz&aaa=B&Aaa= /aw'
        self.assertEqual(DLSigner(**self.options).sign(self.request)['Authorization'],
                         'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                         'accept;content-type;host;x-dl-date,Signature=' +
                         '2ce30a1edcc686c79b816189c653be1c980a850c04140cbdbde3d2572f62041a')

    def test_sign_sha_512_hash(self):
        self.options['algorithm'] = 'DL-HMAC-SHA512'
        self.request['uri'] = '/test/test2?Zzz&aaa=B&Aaa= /aw.~~'
        self.assertEqual(DLSigner(**self.options).sign(self.request)['Authorization'],
                         'DL-HMAC-SHA512 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' +
                         'accept;content-type;host;x-dl-date,Signature=' +
                         'bfcf0da0eaeb312f4d4164685996cdb319c57993700a9d0b398b3c5da4da40291e0a25a695752ba08b05019c6b24caec7e9862820bfca149a29be40ee2f4583f')

    def test_sign_with_payload(self):
        self.assertEqual(DLSigner(**self.options).sign(self.request_with_payload)['Authorization'],
                         'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' + \
                         'accept;content-type;host;x-dl-date,Signature=' + \
                         '0e45160526c02e432cf2b08988a4ae1341cc9a608da5efe330397f581bf32bc2')

    def test_sign_with_additional_header(self):
        self.request_with_payload['headers']['test'] = 'test'
        self.assertEqual(DLSigner(**self.options).sign(self.request_with_payload)['Authorization'],
                         'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' + \
                         'accept;content-type;host;test;x-dl-date,Signature=' + \
                         'f9bdf85e5226b3889098e799e65bd21cdbb22443893460c2ed050f8ca7b8dabb')

    def test_sign_with_whitespaces_in_header(self):
        self.request_with_payload['headers']['test'] = '    test  '
        self.assertEqual(DLSigner(**self.options).sign(self.request_with_payload)['Authorization'],
                         'DL-HMAC-SHA256 Credential=test/19700101/RING/pulsapi/dl1_request,SignedHeaders=' + \
                         'accept;content-type;host;test;x-dl-date,Signature=' + \
                         'f9bdf85e5226b3889098e799e65bd21cdbb22443893460c2ed050f8ca7b8dabb')
