#!/usr/bin/env python
#-*- coding: utf-8 -*-
import os
try: import unittest2 as unittest
except ImportError: import unittest
import regioh as srv
import json
from binascii import hexlify, unhexlify
from regioh.celery import celery

celery.conf.update(
    CELERY_ALWAYS_EAGER = True,
    )

lk_accounts = {
    'banana110531@gmail.com': {
        'id': 'tmoijVoPVd',
        'oauth_token': '6ba8a7ac-bf3d-495d-8f1f-6a0d7994074d',
        'oauth_token_secret': '1d1e2754-0d24-4cf4-bd70-f364f55c4ac4'
    },
    'cherry110531@gmail.com': {
        'id': 'V1g8BEFEw7',
        'oauth_token': '42e82ea3-9159-4b0f-9735-cef889b2e1c1',
        'oauth_token_secret': '36fb10db-9bab-4956-a46e-a3938871273e'
    }
}

class RegTestCase(unittest.TestCase):
    """Test for File Operation"""

    def setUp(self):
        srv.app.config['TESTING'] = True
        self.init_signup_for_test()
        self.app = srv.app.test_client()
        from Crypto.PublicKey import RSA
        self.rsakey = RSA.generate(1024)
        #from mock import MagicMock
        #mock = self.create_patch(srv.api_helper, 'get_dynamodb_table')
        #self.create_patch(srv.api_helper, 'notify_email')

    def tearDown(self):
        pass

    #def create_patch(self, classname, name):
    #    from mock import patch
    #    patcher = patch.object(classname, name, autospec=True)
    #    thing = patcher.start()
    #    self.addCleanup(patcher.stop)
    #    return thing


    def init_signup_for_test(self):
        from regioh.api_helper import generate_security_code
        from regioh.api_helper import addto_dynamodb_signup
        srv.app.config['IDENTITY_CODE'] = generate_security_code()
        srv.app.config['V2_SIGNUP'] = 'v2_signup_test'
        srv.app.config['V2_AUTH'] = 'v2_auth_test'
        oauth_token = lk_accounts['cherry110531@gmail.com']['oauth_token']
        oauth_token_secret = lk_accounts['cherry110531@gmail.com']['oauth_token_secret']
        #add truecirclely2gmail.com to signup table
        item = addto_dynamodb_signup(lk_accounts['cherry110531@gmail.com']['id'],
                                     token=srv.app.config['IDENTITY_CODE'],
                                     oauth_token=oauth_token,
                                     oauth_token_secret=oauth_token_secret,
                                     oauth_expires_in='5183999')

    def init_auth(self):
        pass

    def test_register_invalid_security_code(self):
        from regioh.api_helper import generate_security_code
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': generate_security_code(),
                'email': 'apple110513@gmail.com',
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
                'email': 'cherry110531@gmail.com',
                'pubkey': self.rsakey.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'CODE_EXPIRES' == jrep['result']['status']

    def test_v2_register_success(self):
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': srv.app.config['IDENTITY_CODE'],
                'email': 'cherry110531@gmail.com',
                'pubkey': self.rsakey.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'SUCCESS' == jrep['result']['status']
        assert self.rsakey.publickey().exportKey() == jrep['result']['pubkey']
        assert lk_accounts['cherry110531@gmail.com']['id'] == jrep['result']['linkedin_id']

if __name__ == '__main__':
    unittest.main()
