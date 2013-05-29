#!/usr/bin/env python
#-*- coding: utf-8 -*-
import os
try: import unittest2 as unittest
except ImportError: import unittest
import regioh as srv
import json
import tempfile

from regioh.celery import celery
from regioh.default_config import PROJECT_ROOT
from gdapi.gdapi import GDAPI

celery.conf.update(
    CELERY_ALWAYS_EAGER = True,
    )

users = {
    'banana110531@gmail.com': {
        'id': 'tmoijVoPVd',
        'oauth_token': '6ba8a7ac-bf3d-495d-8f1f-6a0d7994074d',
        'oauth_token_secret': '1d1e2754-0d24-4cf4-bd70-f364f55c4ac4',
        'cred_file' : 'banana110531@gmail.com.cred.json'
    },
    'cherry110531@gmail.com': {
        'id': 'V1g8BEFEw7',
        'oauth_token': '42e82ea3-9159-4b0f-9735-cef889b2e1c1',
        'oauth_token_secret': '36fb10db-9bab-4956-a46e-a3938871273e',
        'cred_file' : 'cherry110531@gmail.com.cred.json'
    }
}

class RegTestCase(unittest.TestCase):
    """Test for File Operation"""

    def setUp(self):
        from Crypto.PublicKey import RSA
        srv.app.config['TESTING'] = True
        self.actor1 = 'cherry110531@gmail.com'
        self.actor2 = 'banana110531@gmail.com'
        self.rsakey = RSA.generate(1024)

        self.app = srv.app.test_client()
        self.init_signup_for_test(self.actor1)

    def tearDown(self):
        pass

    def init_signup_for_test(self, user):
        from regioh.api_helper import generate_security_code
        from regioh.api_helper import addto_dynamodb_signup
        srv.app.config['IDENTITY_CODE'] = generate_security_code()
        srv.app.config['V2_SIGNUP'] = 'v2_signup_test'
        srv.app.config['V2_AUTH'] = 'v2_auth_test'
        oauth_token = users[user]['oauth_token']
        oauth_token_secret = users[user]['oauth_token_secret']
        #add truecirclely2gmail.com to signup table
        item = addto_dynamodb_signup(users[user]['id'],
                                     token=srv.app.config['IDENTITY_CODE'],
                                     oauth_token=oauth_token,
                                     oauth_token_secret=oauth_token_secret,
                                     oauth_expires_in='5183999')

    def init_auth(self):
        pass

    def test_register_with_invalid_security_code(self):
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

    def test_register_with_expired_security_code(self):
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
                'email': self.actor1,
                'pubkey': self.rsakey.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'CODE_EXPIRES' == jrep['result']['status']

    def test_v2_register_success_with_no_connection(self):
        pass
        #assert 200 == rv.status_code
        #assert 200 == jrep.get('code', None)
        #assert 'SUCCESS' == jrep['result']['status']
        #assert self.rsakey.publickey().exportKey() == jrep['result']['pubkey']
        #assert users[self.actor1]['id'] == jrep['result']['linkedin_id']

    def test_v2_register_success_with_connection(self):
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': srv.app.config['IDENTITY_CODE'],
                'email': self.actor1,
                'pubkey': self.rsakey.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'SUCCESS' == jrep['result']['status']
        assert self.rsakey.publickey().exportKey() == jrep['result']['pubkey']
        assert users[self.actor1]['id'] == jrep['result']['linkedin_id']

        #############################
        # actor1 try to query fid
        # by name and download file
        #############################
        ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT),
                                    'accounts',
                                    users[self.actor1]['cred_file']))
        title = 'Cipherbox LinkedIn Contacts ({0}) DO NOT REMOVE THIS FILE.ioh'.format( self.actor1)
        result = ga.query_title(title, isSharedWithMe=True)
        with open('aaa.txt', 'wb') as fout:
            json.dump(result, fout, indent=2)
        assert len(result) == 1
        assert result[0]['id']

        contact_file_id = result[0]['id']
        _, temp_path = tempfile.mkstemp()
        success = ga.download_file(contact_file_id, temp_path)
        assert success
        with open(temp_path, 'rb') as fin:
            jobj = json.load(fin)
        os.unlink(temp_path)
        assert jobj['contacts']['me']
        assert jobj['contacts']['me']['id'] == users[self.actor1]['id']
        assert jobj['contacts']['me']['status'] == 'active'
        assert jobj['contacts']['me']['pubkey'] == self.rsakey.publickey().exportKey()

    def test_v2_re_register_without_revoke(self):
        pass

    def test_v2_refresh_connection_success(self):
        pass


if __name__ == '__main__':
    unittest.main()
