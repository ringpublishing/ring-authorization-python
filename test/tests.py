from datetime import datetime
import unittest
import ring_auth_python


class SignerTests(unittest.TestCase):
    @staticmethod
    def get_options_dict():
        return {
            'service': 'pulsapi',
            'access_key': 'accesskey',
            'secret_key': 'secret',
            'algorithm': 'DL-HMAC-SHA256',
            'solution': 'RING'
        }

    @staticmethod
    def get_request_dict():
        return {
            'method': 'POST',
            'uri': '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20',
            'headers': {
                'host': 'tmp',
                'Content-Type': 'application/json',
                'X-DL-Date': '20190121T131439Z'
            },
        }

    def test_created_instance_of_class(self):
        options = self.get_options_dict()
        testobj = ring_auth_python.DLSigner(**options)
        self.assertIsInstance(testobj, ring_auth_python.DLSigner, 'Variable is not instance of DLSigner.')

    def test_returned_instance(self):
        options = self.get_options_dict()
        request = self.get_request_dict()
        self.assertTrue(isinstance(ring_auth_python.DLSigner(**options).sign(request), dict),
                        'Class is not returning dictionary.')

    def test_returned_authorization_header_key(self):
        options = self.get_options_dict()
        request = self.get_request_dict()
        self.assertFalse(ring_auth_python.DLSigner(**options).sign(request)['Authorization'] is None,
                         'Authorization header does not exist.')

    def test_returned_authorization_header_value_algorithm(self):
        options = self.get_options_dict()
        request = self.get_request_dict()
        values = ring_auth_python.DLSigner(**options).sign(request)['Authorization'].split()
        self.assertEqual(values[0][:11], 'DL-HMAC-SHA', 'Returned header contains invalid algorithm header.')

    def test_algorithm_prefix_assertion(self):
        options = self.get_options_dict()
        options['algorithm'] = 'sha256'
        with self.assertRaises(AssertionError):
            ring_auth_python.DLSigner(**options)

    def test_hashing_method_assertion(self):
        options = self.get_options_dict()
        options['algorithm'] = 'DL-HMAC-SHA1'
        with self.assertRaises(AssertionError):
            ring_auth_python.DLSigner(**options)

    def test_algorithm_default_value_insertion(self):
        options = self.get_options_dict()

        options.pop('algorithm')
        self.assertEqual(ring_auth_python.DLSigner(**options).algorithm, 'DL-HMAC-SHA256',
                         'Invalid default value of algorithm.')

    def test_service_none_value_validation(self):
        options = self.get_options_dict()

        options['service'] = None
        with self.assertRaises(AssertionError):
            ring_auth_python.DLSigner(**options)

    def test_service_empty_value_validation(self):
        options = self.get_options_dict()

        options['service'] = ''
        with self.assertRaises(AssertionError):
            ring_auth_python.DLSigner(**options)

    def test_access_key_none_value_validation(self):
        options = self.get_options_dict()

        options['access_key'] = None
        with self.assertRaises(AssertionError):
            ring_auth_python.DLSigner(**options)

    def test_access_key_empty_value_validation(self):
        options = self.get_options_dict()

        options['access_key'] = ''
        with self.assertRaises(AssertionError):
            ring_auth_python.DLSigner(**options)

    def test_secret_key_none_value_validation(self):
        options = self.get_options_dict()

        options['secret_key'] = None
        with self.assertRaises(AssertionError):
            ring_auth_python.DLSigner(**options)

    def test_secret_key_empty_value_validation(self):
        options = self.get_options_dict()

        options['secret_key'] = ''
        with self.assertRaises(AssertionError):
            ring_auth_python.DLSigner(**options)

    def test_request_method_validation(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        request['method'] = ''
        with self.assertRaises(AssertionError):
            ring_auth_python.DLSigner(**options).sign(request)

    def test_request_payload_type_validation(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        request['body'] = 'string'
        with self.assertRaises(AssertionError):
            ring_auth_python.DLSigner(**options).sign(request)

    def test_request_host_header_validation(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        request['headers'].pop('host')
        with self.assertRaises(AssertionError):
            ring_auth_python.DLSigner(**options).sign(request)

    def test_blank_payload_hashing(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        request['body'] = b''
        testobj = ring_auth_python.DLSigner(**options)
        self.assertEqual(testobj._get_canonical_request(request).split('\n')[7].lower(),
                         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                         'Hashing method does not work correcly.')

    def test_returning_header_default_date_key(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        request['headers'].pop('X-DL-Date')
        self.assertFalse('X-DL-Date' in request['headers'], 'X-DL-Date still exists in request headers.')
        test_request = ring_auth_python.DLSigner(**options).sign(request)
        self.assertTrue('X-DL-Date' in test_request.keys(), 'Signer did not return X-DL-Date header.')

    def test_returning_actual_date_on_sign(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        request['headers'].pop('X-DL-Date')
        self.assertFalse('X-DL-Date' in request['headers'], 'X-DL-Date still exists in request headers.')
        self.assertEqual(ring_auth_python.DLSigner(**options).sign(request)['X-DL-Date'],
                         datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'),
                         'Default value of X-DL-Date is not equal to actual date.')

    def test_returned_string_to_sign_params(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        test_object = ring_auth_python.DLSigner(**options)
        canonical_request = test_object._get_canonical_request(request)
        string_to_sign = test_object._get_string_to_sign(canonical_request, request['headers']['X-DL-Date']).split('\n')
        self.assertEqual(string_to_sign[1], request['headers']['X-DL-Date'], 'String to sign does not include date.')
        self.assertEqual(string_to_sign[2], '20190121/RING/pulsapi/dl1_request',
                         'String to sign does not include scope value.')
        self.assertTrue(len(string_to_sign[3]) == 64, 'Hashing of body did not work correcly.')

    def test_signed_headers_formatting(self):
        request = self.get_request_dict()

        self.assertEqual(ring_auth_python.DLSigner._get_headers(request)['signed_headers'],
                         'content-type;host;x-dl-date')

    def test_canonical_headers_formatting(self):
        request = self.get_request_dict()

        request['headers'] = {
            'host': 'host',
            'HEADER1': '  val1  ',
            'heaDer2': ' val2',
            'Header3': 'va l3',
            'header4': ''
        }
        self.assertEqual(ring_auth_python.DLSigner._get_headers(request)['canonical_headers'],
                         'header1:val1\nheader2:val2\nheader3:va l3\nheader4:\nhost:host')

    def test_canonical_query_string(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        test_object = ring_auth_python.DLSigner(**options)
        canonical_request = test_object._get_canonical_request(request)
        self.assertEqual(canonical_request.split('\n')[2],
                         'marker=someMarker&max-keys=20&prefix=somePrefix')

    def test_canonical_query_string_with_encoded_values(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        request['uri'] = '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20&test=t^e s'
        test_object = ring_auth_python.DLSigner(**options)
        canonical_request = test_object._get_canonical_request(request)
        self.assertEqual(canonical_request.split('\n')[2],
                         'marker=someMarker&max-keys=20&prefix=somePrefix&test=t%5Ee%20s')

    def test_canonical_query_string_with_encoded_values_and_empty_value(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        request['uri'] = '/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20&test=t^e s&aws'
        test_object = ring_auth_python.DLSigner(**options)
        canonical_request = test_object._get_canonical_request(request)
        self.assertEqual(canonical_request.split('\n')[2],
                         'aws=&marker=someMarker&max-keys=20&prefix=somePrefix&test=t%5Ee%20s')

    def test_sorting_of_query_string(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        request['uri'] = '/examplebucket?zzz=someValue&Aaaa=someValue&aaa=20&test=t^e s&aws'
        test_object = ring_auth_python.DLSigner(**options)
        canonical_request = test_object._get_canonical_request(request)
        self.assertEqual(canonical_request.split('\n')[2],
                         'Aaaa=someValue&aaa=20&aws=&test=t%5Ee%20s&zzz=someValue')

    def test_returned_canonical_request(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        test_object = ring_auth_python.DLSigner(**options)
        canonical_request = test_object._get_canonical_request(request)
        self.assertEqual(canonical_request, 'POST\n' +
                         '/examplebucket' + '\n' +
                         'marker=someMarker&max-keys=20&prefix=somePrefix\n' +
                         'content-type:application/json\n' +
                         'host:tmp\n' +
                         'x-dl-date:20190121T131439Z\n' +
                         'content-type;host;x-dl-date\n' +
                         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def test_returned_canonoical_request_if_no_query_string_provided(self):
        options = self.get_options_dict()
        request = self.get_request_dict()

        request['uri'] = '/examplebucket'
        test_object = ring_auth_python.DLSigner(**options)
        canonical_request = test_object._get_canonical_request(request)
        self.assertEqual(canonical_request, 'POST\n' +
                         '/examplebucket' + '\n' +
                         '\n' +
                         'content-type:application/json\n' +
                         'host:tmp\n' +
                         'x-dl-date:20190121T131439Z\n' +
                         'content-type;host;x-dl-date\n' +
                         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
