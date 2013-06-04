#!/usr/bin/env python
#-*- coding: utf-8 -*-
import os
import sys
import json
import tempfile
from gdapi.gdapi import GDAPI
try: import unittest2 as unittest
except ImportError: import unittest

path = os.getcwd()
if path not in sys.path:
    sys.path.append(path)

import regioh as srv
from regioh.celery import celery
from regioh.default_config import PROJECT_ROOT

celery.conf.update(
    CELERY_ALWAYS_EAGER = True,
    )

users = {
    'banana110531@gmail.com': {
        'id': 'tmoijVoPVd',
        'access_token': 'AQUNP6Wy4_0iACNX1JHB5IWzZB0wSU349_i3xeuh0AMXPOGKGiXT3D7p1sCaLoYLrxVf9PVJe1f4ETCNd2OcY_CSX90dNtvU7NzT5DdmCYYnkPxlPY1dGSay8cu5ZJsEHhJAY_LDpw91s22EizsY7GlBSyZI64dt4Laci7TVPuSMpBKi4Zw',
        'cred_file' : 'banana110531@gmail.com.cred.json'
    },
    'eiffel110531@gmail.com': {
        'id': 'wLvv1_RuLF',
        'access_token': 'AQWCQV1IomioadETXTpfyq6bnPFQlDVhU5fhm5Qc4Q10yv50rsPjc6oxd-y0D0LHhx7TOmzFZ6kj8UQoTBsXJiCYsBHh7npchRO8fETgULCLY-YzFOM-HUJ_2TYs1isNnOvm_BIWnXJv0Tm-K2ff3Q49_-vaZ_9FtTS1tcPVWhwLRfqvyqk',
        'cred_file' : 'eiffel110531@gmail.com.cred.json'
    },
    'cherry110531@gmail.com': {
        'id': 'V1g8BEFEw7',
        'access_token': 'AQUiX-ek-U6VHVqY2-JrQmfM1bF7OvL0Ayhb5gxzWE9camyrK50ACeTWfQFkGnEeZRegEExIYj8mIIVBIhzVDiCJ-Yhj8hw-hzNOMEpzAxjWEPZNCO2wp15QvqA7Vk3nBoiBGgCVrDRHy1ctoycrrGAhUWBBv4oDOYnBfm71Pol5NLi5nMY',
        'cred_file' : 'cherry110531@gmail.com.cred.json'
    }
}

class RegV2TestCase(unittest.TestCase):
    """Test for File Operation"""

    def setUp(self):
        from Crypto.PublicKey import RSA
        srv.app.config['TESTING'] = True
        srv.app.config['V2_SIGNUP'] = 'v2_signup_test'
        srv.app.config['V2_AUTH'] = 'v2_auth_test'
        self.actor1 = 'cherry110531@gmail.com'
        self.actor1_key = RSA.generate(1024)
        self.actor2 = 'banana110531@gmail.com'
        self.actor2_key = RSA.generate(1024)
        self.alone = 'eiffel110531@gmail.com' # no connection guy
        self.alone_key = RSA.generate(1024)

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

    def init_signup(self, user):
        from regioh.api_helper import generate_security_code
        from regioh.api_helper import addto_dynamodb_signup
        srv.app.config['IDENTITY_CODE'] = generate_security_code()
        access_token = users[user]['access_token']
        #add truecirclely2gmail.com to signup table
        item = addto_dynamodb_signup(users[user]['id'],
                                     token=srv.app.config['IDENTITY_CODE'],
                                     access_token=access_token,
                                     oauth_expires_in='5183999')

    #@unittest.skip('test_v2_re_register_without_revoke')
    def test_register_with_invalid_security_code(self):
        self.init_signup(self.alone)
        from regioh.api_helper import generate_security_code
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': generate_security_code(),
                'email': self.actor1,
                'pubkey': self.actor1_key.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'NO_LINKEDIN_ACCOUNT' == jrep['result']['status']

    #@unittest.skip('test_v2_re_register_without_revoke')
    def test_register_with_expired_security_code(self):
        self.init_signup(self.alone)
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
                'pubkey': self.actor1_key.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'CODE_EXPIRES' == jrep['result']['status']

    #@unittest.skip('test_v2_re_register_without_revoke')
    def test_v2_alone_register_success(self):
        self.init_signup(self.alone)
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': srv.app.config['IDENTITY_CODE'],
                'email': self.alone,
                'pubkey': self.alone_key.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'SUCCESS' == jrep['result']['status']
        assert self.alone_key.publickey().exportKey() == jrep['result']['pubkey']
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
        assert jobj['contacts']['me']['pubkey'] == self.alone_key.publickey().exportKey()

    #@unittest.skip('test_v2_re_register_without_revoke')
    def test_v2_actor1_reg_w_uninstalled_actor2(self):
        self.init_signup(self.actor1)
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': srv.app.config['IDENTITY_CODE'],
                'email': self.actor1,
                'pubkey': self.actor1_key.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'SUCCESS' == jrep['result']['status']
        assert self.actor1_key.publickey().exportKey() == jrep['result']['pubkey']
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
        assert contacts['me']['pubkey'] == self.actor1_key.publickey().exportKey()

        # 2. check actor2 with 'inactive'
        assert contacts[users[self.actor2]['id']]['id'] == users[self.actor2]['id']
        assert contacts[users[self.actor2]['id']]['status'] == 'inactive'

    #@unittest.skip('test_v2_re_register_without_revoke')
    def test_v2_actor1_reg_then_actor2_reg(self):
        self.init_signup(self.actor1)
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': srv.app.config['IDENTITY_CODE'],
                'email': self.actor1,
                'pubkey': self.actor1_key.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code

        self.init_signup(self.actor2)
        rv = self.app.post(
            '/v2/register',
            headers = {'content-type': 'application/json'},
            data = {
                'identity_code': srv.app.config['IDENTITY_CODE'],
                'email': self.actor2,
                'pubkey': self.actor2_key.publickey().exportKey(),
            })
        jrep = json.loads(rv.data)
        assert 200 == rv.status_code
        assert 200 == jrep.get('code', None)
        assert 'SUCCESS' == jrep['result']['status']
        assert self.actor2_key.publickey().exportKey() == jrep['result']['pubkey']
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
        assert contacts['me']['pubkey'] == self.actor2_key.publickey().exportKey()
        # 2. check actor2 with 'active'
        assert contacts[users[self.actor1]['id']]['status'] == 'active'
        assert contacts[users[self.actor1]['id']]['pubkey'] == self.actor1_key.publickey().exportKey()

        ######################################################
        # actor1 query fid # by name and download file
        ######################################################
        ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT),
                                    'accounts',
                                    users[self.actor1]['cred_file']))
        title = 'Cipherbox LinkedIn Contacts ({0}) DO NOT REMOVE THIS FILE.ioh'.format(self.actor1)
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
        assert contacts['me']['pubkey'] == self.actor1_key.publickey().exportKey()
        # 2. check actor1 with 'active'
        assert contacts[users[self.actor2]['id']]['status'] == 'active'
        assert contacts[users[self.actor2]['id']]['pubkey'] == self.actor2_key.publickey().exportKey()



class RegV3TestCase(unittest.TestCase):
    """Test for File Operation"""

    def setUp(self):
        from Crypto.PublicKey import RSA
        srv.app.config['TESTING'] = True
        srv.app.config['V2_SIGNUP'] = 'v2_signup_test'
        srv.app.config['V2_AUTH'] = 'v2_auth_test'
        self.actor1 = 'cherry110531@gmail.com'
        self.actor1_key = RSA.generate(1024)
        self.actor2 = 'banana110531@gmail.com'
        self.actor2_key = RSA.generate(1024)
        self.alone = 'eiffel110531@gmail.com' # no connection guy
        self.alone_key = RSA.generate(1024)

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

    @unittest.skip('test_v2_refresh_connection_success')
    def test_v3_revoke_success(self):
        pass

    @unittest.skip('test_v2_refresh_connection_success')
    def test_v3_refresh_connection_success(self):
        pass

    @unittest.skip('test_v2_re_register_without_revoke')
    def test_v3_re_register_without_revoke(self):
        pass

    @unittest.skip('test_v2_re_register_without_revoke')
    def test_v3_re_register_then_revoke_then_reg(self):
        pass

if __name__ == '__main__':
    unittest.main()
