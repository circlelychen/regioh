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
    'eiffel110531@gmail.com': {
        'id': 'wLvv1_RuLF',
        'oauth_token': '0022fe66-538b-4624-93f6-7f48d9709ecf',
        'oauth_token_secret': 'c4701ac6-a3b2-4be1-ab38-9a71394bab60',
        'cred_file' : 'eiffel110531@gmail.com.cred.json'
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
        srv.app.config['V2_SIGNUP'] = 'v2_signup_test'
        srv.app.config['V2_AUTH'] = 'v2_auth_test'
        self.actor1 = 'cherry110531@gmail.com'
        self.actor2 = 'banana110531@gmail.com'
        self.alone = 'eiffel110531@gmail.com' # no connection guy
        self.rsakey = RSA.generate(1024)

        self.app = srv.app.test_client()

    def tearDown(self):
        from regioh.api_helper import get_dynamodb_table
        for key in users:
            tbl = get_dynamodb_table(srv.app.config['V2_AUTH'])
            if tbl.has_item(hash_key=users[key]['id']):
                item = tbl.get_item(
                    hash_key=users[key]['id'],
                    )
                item.delete()

    def init_signup_for_test(self, user):
        from regioh.api_helper import generate_security_code
        from regioh.api_helper import addto_dynamodb_signup
        srv.app.config['IDENTITY_CODE'] = generate_security_code()
        oauth_token = users[user]['oauth_token']
        oauth_token_secret = users[user]['oauth_token_secret']
        #add truecirclely2gmail.com to signup table
        item = addto_dynamodb_signup(users[user]['id'],
                                     token=srv.app.config['IDENTITY_CODE'],
                                     oauth_token=oauth_token,
                                     oauth_token_secret=oauth_token_secret,
                                     oauth_expires_in='5183999')

    def test_register_with_invalid_security_code(self):
        self.init_signup_for_test(self.alone)
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
        self.init_signup_for_test(self.alone)
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

    def test_v2_alone_register_success(self):
        self.init_signup_for_test(self.alone)
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': srv.app.config['IDENTITY_CODE'],
                'email': self.alone,
                'pubkey': self.rsakey.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'SUCCESS' == jrep['result']['status']
        assert self.rsakey.publickey().exportKey() == jrep['result']['pubkey']
        assert users[self.alone]['id'] == jrep['result']['linkedin_id']

        #############################
        # alone try to query fid
        # by name and download file
        #############################
        ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT),
                                    'accounts',
                                    users[self.alone]['cred_file']))
        title = 'Cipherbox LinkedIn Contacts ({0}) DO NOT REMOVE THIS FILE.ioh'.format(self.alone)
        result = ga.query_title(title, isSharedWithMe=True)
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
        assert jobj['contacts']['me']['id'] == users[self.alone]['id']
        assert jobj['contacts']['me']['status'] == 'active'
        assert jobj['contacts']['me']['pubkey'] == self.rsakey.publickey().exportKey()

    def test_v2_actor1_reg_w_uninstalled_actor2(self):
        self.init_signup_for_test(self.actor1)
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

        ######################################################
        # actor1 query fid # by name and download file
        ######################################################
        ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT),
                                    'accounts',
                                    users[self.actor1]['cred_file']))
        title = 'Cipherbox LinkedIn Contacts ({0}) DO NOT REMOVE THIS FILE.ioh'.format( self.actor1)
        result = ga.query_title(title, isSharedWithMe=True)
        assert len(result) == 1
        assert result[0]['id']

        contact_file_id = result[0]['id']
        _, temp_path = tempfile.mkstemp()
        success = ga.download_file(contact_file_id, temp_path)
        assert success
        with open(temp_path, 'rb') as fin:
            jobj = json.load(fin)
        os.unlink(temp_path)

        # 1. check 'me' exist
        contacts = jobj['contacts']
        assert contacts['me']
        assert contacts['me']['id'] == users[self.actor1]['id']
        assert contacts['me']['status'] == 'active'
        assert contacts['me']['pubkey'] == self.rsakey.publickey().exportKey()

        # 2. check actor2 with 'inactive'
        assert contacts[users[self.actor2]['id']]['id'] == users[self.actor2]['id']
        assert contacts[users[self.actor2]['id']]['status'] == 'inactive'

    def test_v2_actor1_reg_then_actor2_reg(self):
        self.init_signup_for_test(self.actor1)
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

        self.init_signup_for_test(self.actor2)
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': srv.app.config['IDENTITY_CODE'],
                'email': self.actor2,
                'pubkey': self.rsakey.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'SUCCESS' == jrep['result']['status']
        assert self.rsakey.publickey().exportKey() == jrep['result']['pubkey']
        assert users[self.actor2]['id'] == jrep['result']['linkedin_id']

        ######################################################
        # actor2 query fid # by name and download file
        ######################################################
        ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT),
                                    'accounts',
                                    users[self.actor2]['cred_file']))
        title = 'Cipherbox LinkedIn Contacts ({0}) DO NOT REMOVE THIS FILE.ioh'.format( self.actor2)
        result = ga.query_title(title, isSharedWithMe=True)
        assert len(result) == 1
        assert result[0]['id']

        contact_file_id = result[0]['id']
        _, temp_path = tempfile.mkstemp()
        success = ga.download_file(contact_file_id, temp_path)
        assert success
        with open(temp_path, 'rb') as fin:
            jobj = json.load(fin)
        os.unlink(temp_path)
        contacts = jobj['contacts']
        # 1. check 'me'
        assert contacts['me']
        assert contacts['me']['id'] == users[self.actor2]['id']
        assert contacts['me']['status'] == 'active'
        assert contacts['me']['pubkey'] == self.rsakey.publickey().exportKey()
        # 2. check actor2 with 'active'
        assert contacts[users[self.actor1]['id']]['status'] == 'active'

        ######################################################
        # actor1 query fid # by name and download file
        ######################################################
        ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT),
                                    'accounts',
                                    users[self.actor1]['cred_file']))
        title = 'Cipherbox LinkedIn Contacts ({0}) DO NOT REMOVE THIS FILE.ioh'.format( self.actor1)
        result = ga.query_title(title, isSharedWithMe=True)
        assert len(result) == 1
        assert result[0]['id']

        contact_file_id = result[0]['id']
        _, temp_path = tempfile.mkstemp()
        success = ga.download_file(contact_file_id, temp_path)
        assert success
        with open(temp_path, 'rb') as fin:
            jobj = json.load(fin)
        os.unlink(temp_path)
        contacts = jobj['contacts']
        # 1. check 'me'
        assert contacts['me']
        assert contacts['me']['id'] == users[self.actor1]['id']
        assert contacts['me']['status'] == 'active'
        assert contacts['me']['pubkey'] == self.rsakey.publickey().exportKey()
        # 2. check actor1 with 'active'
        assert contacts[users[self.actor2]['id']]['status'] == 'active'

    @unittest.skip('test_v2_re_register_without_revoke')
    def test_v2_re_register_without_revoke(self):
        pass

    @unittest.skip('test_v2_refresh_connection_success')
    def test_v2_refresh_connection_success(self):
        pass

if __name__ == '__main__':
    unittest.main()
