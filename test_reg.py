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
        from regioh.api_helper import generate_security_code
        from regioh.api_helper import addto_dynamodb_signup
        srv.app.config['TESTING'] = True
        srv.app.config['IDENTITY_CODE'] = generate_security_code()
        srv.app.config['LK_ID'] = 'rdlsVH788A'
        srv.app.config['V2_SIGNUP'] = 'v2_signup_test'
        item = addto_dynamodb_signup(srv.app.config['LK_ID'],
                                     token=srv.app.config['IDENTITY_CODE'],
                                     oauth_expires_in='5183999')
        self.app = srv.app.test_client()
        #from mock import MagicMock
        #mock = self.create_patch(srv.api_helper, 'get_dynamodb_table')
        #self.create_patch(srv.api_helper, 'notify_email')
        from Crypto.PublicKey import RSA
        self.rsakey = RSA.generate(1024)

    def tearDown(self):
        pass

    #def create_patch(self, classname, name):
    #    from mock import patch
    #    patcher = patch.object(classname, name, autospec=True)
    #    thing = patcher.start()
    #    self.addCleanup(patcher.stop)
    #    return thing

    def test_register_invalid_security_code(self):
        from regioh.api_helper import generate_security_code
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': generate_security_code(),
                'email': 'truecirclely@gmail.com',
                'pubkey': self.rsakey.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'NO_LINKEDIN_ACCOUNT' == jrep['result']['status']

    def test_register_security_code_expires(self):
        # get dynamo table and modify its expires_in_utc as created_in_utc
        from regioh.api_helper import get_dynamodb_table
        tbl = get_dynamodb_table(srv.app.config['V2_SIGNUP'],
                                 hash_key='token')
        item = tbl.get_item(
            hash_key=srv.app.config['IDENTITY_CODE']
            )
        item['expires_in_utc'] = item['created_in_utc']
        item.put()

        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': srv.app.config['IDENTITY_CODE'],
                'email': 'truecirclely@gmail.com',
                'pubkey': self.rsakey.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'CODE_EXPIRES' == jrep['result']['status']

    @unittest.skip('skip test_v2_register_success')
    def test_v2_register_success(self):
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': srv.app.config['IDENTITY_CODE'],
                'email': 'truecirclely@gmail.com',
                'pubkey': self.rsakey.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code

if __name__ == '__main__':
    unittest.main()
