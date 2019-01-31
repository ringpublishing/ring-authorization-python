from datetime import datetime
import unittest
from ring_auth import DLSigner


class SignerTests(unittest.TestCase):
    def setUp(self):
        self.request = {
            'method': 'POST',
            'uri': '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20',
            'headers': {
                'host': 'tmp',
                'Content-Type': 'application/json',
                'X-DL-Date': '20190121T131439Z'
            },
        }

        self.options = {
            'service': 'pulsapi',
            'access_key': 'accesskey',
            'secret_key': 'secret',
            'algorithm': 'DL-HMAC-SHA256',
            'solution': 'RING'
        }

    def test_returned_instance_of_variable_after_call_sign_request_method(self):
        self.assertTrue(isinstance(DLSigner(**self.options).sign(self.request), dict),
                        'Class is not returning dictionary.')

    def test_if_exists_returned_authorization_key_after_call_sign_method(self):
        self.assertFalse(DLSigner(**self.options).sign(self.request)['Authorization'] is None,
                         'Authorization header does not exist.')

    def test_returned_authorization_header_value_algorithm_prefix(self):
        values = DLSigner(**self.options).sign(self.request)['Authorization'].split()
        self.assertEqual(values[0][:11], 'DL-HMAC-SHA', 'Returned header contains invalid algorithm header.')

    def test_assertion_error_raised_when_invalid_algorithm_provided(self):
        self.options['algorithm'] = 'sha256'
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_raised_when_invalid_algorithm_prefix_provided(self):
        self.options['algorithm'] = 'DL-HMAC-SHA1'
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_algorithm_default_value_insertion_in_returned_dictionary(self):
        self.options.pop('algorithm')
        self.assertEqual(DLSigner(**self.options).algorithm, 'DL-HMAC-SHA256',
                         'Invalid default value of algorithm.')

    def test_assertion_error_raised_when_service_None_type_provided(self):
        self.options['service'] = None
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_raised_when_service_empty_string_provided(self):
        self.options['service'] = ''
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_raised_when_access_key_None_type_provided(self):
        self.options['access_key'] = None
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_raised_when_access_key_empty_string_provided(self):
        self.options['access_key'] = ''
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_raised_when_secret_key_None_type_provided(self):
        self.options['secret_key'] = None
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_raised_when_secret_key_empty_string_provided(self):
        self.options['secret_key'] = ''
        with self.assertRaises(AssertionError):
            DLSigner(**self.options)

    def test_assertion_error_raised_when_method_empty_string_provided(self):
        self.request['method'] = ''
        with self.assertRaises(AssertionError):
            DLSigner(**self.options).sign(self.request)

    def test_assertion_error_raised_when_request_body_string_type_provided(self):
        self.request['body'] = 'string'
        with self.assertRaises(AssertionError):
            DLSigner(**self.options).sign(self.request)

    def test_assertion_error_raised_when_no_host_provided_in_headers(self):
        self.request['headers'].pop('host')
        with self.assertRaises(AssertionError):
            DLSigner(**self.options).sign(self.request)

    def test_assertion_error_raised_when_no_content_type_provided_in_headers(self):
        self.request['headers'].pop('Content-Type')
        with self.assertRaises(AssertionError):
            DLSigner(**self.options).sign(self.request)

    def test_equality_of_payload_hash_on_empty_string_as_body(self):
        self.request['body'] = bytearray('', encoding='utf-8')
        testobj = DLSigner(**self.options)
        self.assertEqual(testobj._get_canonical_request(self.request).split('\n')[7].lower(),
                         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                         'Hashing method does not work correctly.')

    def test_if_date_was_not_provided_there_will_return_default_date_key(self):
        self.request['headers'].pop('X-DL-Date')
        self.assertFalse('X-DL-Date' in self.request['headers'], 'X-DL-Date still exists in request headers.')
        test_request = DLSigner(**self.options).sign(self.request)
        self.assertTrue('X-DL-Date' in test_request.keys(), 'Signer did not return X-DL-Date header.')

    def test_signature_with_actual_default_date_and_returned_date_key(self):
        self.request['headers'].pop('X-DL-Date')
        self.assertFalse('X-DL-Date' in self.request['headers'], 'X-DL-Date still exists in request headers.')
        self.assertEqual(DLSigner(**self.options).sign(self.request)['X-DL-Date'],
                         datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'),
                         'Default value of X-DL-Date is not equal to actual date.')

    def test_conditions_of_returned_string_to_sign_params(self):
        test_object = DLSigner(**self.options)
        canonical_request = test_object._get_canonical_request(self.request)
        string_to_sign = test_object._get_string_to_sign(canonical_request, self.request['headers']['X-DL-Date']).split('\n')
        self.assertEqual(string_to_sign[1], self.request['headers']['X-DL-Date'], 'String to sign does not include date.')
        self.assertEqual(string_to_sign[2], '20190121/RING/pulsapi/dl1_request',
                         'String to sign does not include scope value.')
        self.assertTrue(len(string_to_sign[3]) == 64, 'Hashing of body did not work correctly.')

    def test_formatting_of_returned_signed_headers_in_get_headers_method(self):
        self.assertEqual(DLSigner._get_headers(self.request)['signed_headers'],
                         'content-type;host;x-dl-date')

    def test_formatting_of_returned_canonical_headers_in_get_headers_method(self):
        self.request['headers'] = {
            'host': 'host',
            'HEADER1': '  val1  ',
            'heaDer2': ' val2',
            'Header3': 'va l3',
            'header4': ''
        }
        self.assertEqual(DLSigner._get_headers(self.request)['canonical_headers'],
                         'header1:val1\nheader2:val2\nheader3:va l3\nheader4:\nhost:host')

    def test_formatting_of_canonical_query_string(self):
        test_object = DLSigner(**self.options)
        canonical_request = test_object._get_canonical_request(self.request)
        self.assertEqual(canonical_request.split('\n')[2],
                         'marker=someMarker&max-keys=20&prefix=somePrefix')

    def test_formatting_of_canonical_query_string_with_encoded_values(self):
        self.request['uri'] = '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20&test=t^e s'
        test_object = DLSigner(**self.options)
        canonical_request = test_object._get_canonical_request(self.request)
        self.assertEqual(canonical_request.split('\n')[2],
                         'marker=someMarker&max-keys=20&prefix=somePrefix&test=t%5Ee%20s')

    def test_formatting_of_canonical_query_string_with_encoded_values_and_empty_value(self):
        self.request['uri'] = '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20&test=t^e s&aws'
        test_object = DLSigner(**self.options)
        canonical_request = test_object._get_canonical_request(self.request)
        self.assertEqual(canonical_request.split('\n')[2],
                         'aws=&marker=someMarker&max-keys=20&prefix=somePrefix&test=t%5Ee%20s')

    def test_equality_of_sorting_in_query_string(self):
        self.request['uri'] = '/examplebucket?zzz=someValue&Aaaa=someValue&aaa=20&test=t^e s&aws'
        test_object = DLSigner(**self.options)
        canonical_request = test_object._get_canonical_request(self.request)
        self.assertEqual(canonical_request.split('\n')[2],
                         'Aaaa=someValue&aaa=20&aws=&test=t%5Ee%20s&zzz=someValue')

    def test_format_and_equality_in_returned_canonical_request(self):
        test_object = DLSigner(**self.options)
        canonical_request = test_object._get_canonical_request(self.request)
        self.assertEqual(canonical_request, 'POST\n' +
                         '/examplebucket' + '\n' +
                         'marker=someMarker&max-keys=20&prefix=somePrefix\n' +
                         'content-type:application/json\n' +
                         'host:tmp\n' +
                         'x-dl-date:20190121T131439Z\n' +
                         'content-type;host;x-dl-date\n' +
                         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def test_returned_canonical_request_values_if_no_query_string_provided(self):
        self.request['uri'] = '/examplebucket'
        test_object = DLSigner(**self.options)
        canonical_request = test_object._get_canonical_request(self.request)
        self.assertEqual(canonical_request, 'POST\n' +
                         '/examplebucket' + '\n' +
                         '\n' +
                         'content-type:application/json\n' +
                         'host:tmp\n' +
                         'x-dl-date:20190121T131439Z\n' +
                         'content-type;host;x-dl-date\n' +
                         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
