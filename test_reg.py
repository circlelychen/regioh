#!/usr/bin/env python
#-*- coding: utf-8 -*-
import os
try: import unittest2 as unittest
except ImportError: import unittest
import regioh as srv
import json
from binascii import hexlify, unhexlify

class RegTestCase(unittest.TestCase):
    """Test for File Operation"""

    def setUp(self):
        from mock import MagicMock
        from Crypto.PublicKey import RSA
        srv.app.config['TESTING'] = True
        self.app = srv.app.test_client()
        mock = self.create_patch(srv.api_helper, 'get_dynamodb_table')
        self.create_patch(srv.api_helper, 'notify_email')
        self.rsakey = RSA.generate(1024)

    def tearDown(self):
        pass

    def create_patch(self, classname, name):
        from mock import patch
        patcher = patch.object(classname, name, autospec=True)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing

    def test_check_nonexist(self):
        rv = self.app.post('/v1/check',
            data = {
                'email': 'cl_chang@farfar.away',
                'pubkey': 'N/A',
                'linkedin_data': 'N/A',
            }
            )
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 'invalid' == jrep['status']

    def test_register(self):
        from Crypto.Cipher import PKCS1_v1_5
        rv = self.app.post('/v1/register',
            data = {
                'email': 'cl_chang@farfar.away',
                'pubkey': self.rsakey.publickey().exportKey(),
                'linkedin_data': 'N/A',
            }
            )
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 'inactive' == jrep['status']
        cipher = unhexlify(jrep['C'])
        prikey = PKCS1_v1_5.new(self.rsakey)
        error = None
        plain = prikey.decrypt(cipher, error)
        assert error is None
        assert hexlify(plain) == jrep['R']

if __name__ == '__main__':
    unittest.main()
