# -*- coding: utf-8 -*-
"""
"""
import os
from boto import ses
from boto import dynamodb

from regioh import app

# AWS credential 
from default_config import AWS_ACCESS_KEY
from default_config import AWS_SECRET_ACCESS_KEY
from default_config import AWS_SES_SENDER

# Authentication/Authorization for LinkedIn
from default_config import LK_CLIENT_SECRET
from default_config import LK_CLIENT_ID
from default_config import LK_REDIRECT_URL

# Security code life time definition
from default_config import TOKEN_LIFE_TIME

# Dynamodb tables definition 
from default_config import V2_SIGNUP
from default_config import V2_AUTH

# gdapi module for interact with Google Drive
from gdapi.gdapi import GDAPI
#from default_config import GD_CRED_FILE

import requests
import urlparse
import datetime
from requests_oauthlib import OAuth1

import tempfile
import json
from tasks import update_contact_file

GOOGLE_DOWNLOAD_URL = 'https://docs.google.com/uc'

def get_code_check(token):
    ''' (str) -> dict

    return Dict of (status, oauth, email) if token is valid

    >> get_code_check(token)
    {
        "status": <str>,
        "token": <str>,
        "linkedin_id", <str>,
        "access_token", <str>,
        "reg_data": {
            "gmail": <str>
            }
    }
    '''
    from boto.dynamodb.condition import EQ
    from boto.dynamodb.exceptions import DynamoDBKeyNotFoundError
    from default_config import MESSAGE
    tbl = get_dynamodb_table(app.config['V2_SIGNUP'], hash_key='token')
    result = {"status": "no_linkedin_account",
              "token": "",
              "access_token": "",
              "reg_data": ""}
    try:
        item = tbl.get_item(
            hash_key=token,
            attributes_to_get = ['id',
                                'oauth2_data',
                                'access_token',
                                'expires_in_utc']
            )
    except Exception as e:
        # security code does not match any record
        app.logger.debug("[ERROR] hash_key[ {0} ] has no items in {1} table, "
                         "exception: {2}".format(token,
                                                 app.config['V2_SIGNUP'],
                                                 repr(e)))
        result['status'] = MESSAGE['no_linkedin_account']
        result['exception'] = repr(e)
        return result

    # check expires or not
    utc_now = datetime.datetime.utcnow()
    expires_in_utc = datetime.datetime.strptime(
        item['expires_in_utc'],
        "%Y-%m-%d %H:%M")
    if utc_now > expires_in_utc:
        # security code expire
        result['status'] = MESSAGE['code_expired']
        return result

    # security code match and not expire,
    result['status'] = MESSAGE['success']
    result['linkedin_id'] = item['id']
    result['token'] = item['oauth2_data']
    result['access_token'] = item['access_token']
    try:
        status, record = query_dynamodb_reg(item['id'])
    except Exception as e:
        # security code does not match any record
        result['status'] = MESSAGE['no_linkedin_account']
        result['exception'] = repr(e)
        app.logger.error("[FAIL] hash_key[ {0} ] has no items in {1} table, "
                         "exception: {2}".format(item['id'],
                                                 app.config['V2_AUTH'],
                                                 repr(e)))
        return result
    if record:
        result['reg_data'] = {"gmail": record['email']}
    return result

def associate_db_data_v2(linked_connections):
    result = {}
    ids = []
    for linkedin_item in linked_connections:
        result[linkedin_item['id']] = linkedin_item
        result[linkedin_item['id']]['status'] = 'inactive'
        ids.append(linkedin_item['id'])
    tbl = get_dynamodb_table(app.config['V2_AUTH'])
    actives = tbl.batch_get_item(
        ids,
        attributes_to_get = ['linkedin_id', 'status',
                             'pubkey', 'email', 'permid',
                             'pubkey_md5', 'LinkedIn_Contacts_FID'
                            ])
    for active in actives:
        active_id = active['linkedin_id']
        for key in active:
            result[active_id][key] = active[key]
    return result



def notify_email(email, content):
    conn = ses.connect_to_region(
        'us-east-1',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    if not conn:
        raise Exception
    try:
        resp = {'SendEmailResponse': None}
        while not resp.get('SendEmailResponse', None):
            resp = conn.send_email(AWS_SES_SENDER,
                                   'Welcome to Cipherbox',
                                   content,
                                   [email])
        app.logger.info("[SUCCESS] "
                         "AWS_SES_SENDER: {0} "
                         "AWS_SES_RECEIVER: {1} ".format(AWS_SES_SENDER,
                                                         email))
        return True
    except Exception as e:
        app.logger.info("[FAILURE] "
                         "AWS_SES_SENDER: {0} "
                         "AWS_SES_RECEIVER: {1} ".format(AWS_SES_SENDER,
                                                         email))
        return False

def get_dynamodb_table(table_name, hash_key='linkedin_id', range_key=None):
    conn = dynamodb.connect_to_region(
        'ap-northeast-1',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    tables = conn.list_tables()
    if table_name not in tables:
        if not range_key:
            auth_table_schema = conn.create_schema(
                hash_key_name=hash_key,
                hash_key_proto_value=str,
                )
            table = conn.create_table(
                name=table_name,
                schema=auth_table_schema,
                read_units=1,
                write_units=1
                )
        else:
            auth_table_schema = conn.create_schema(
                hash_key_name=hash_key,
                hash_key_proto_value=str,
                range_key_name=hash_key,
                range_key_proto_value=str,
                )
            table = conn.create_table(
                name=table_name,
                schema=auth_table_schema,
                read_units=1,
                write_units=1
                )
    else:
        table = conn.get_table(table_name)
    return table

def addto_dynamodb_reg(linked_id, pubkey='N/A', token='N/A',
                          pubkey_md5='N/A', perm_id='N/A',
                          email='N/A', status='inactive',
                          LinkedIn_Contacts_FID='N/A'):
    """Return status, record"""
    tbl = get_dynamodb_table(app.config['V2_AUTH'])
    if tbl.has_item(hash_key=linked_id):
        item = tbl.get_item(
            hash_key=linked_id,
            )
        item.delete()
    try:
        item = tbl.new_item(
            hash_key=linked_id,
            attrs={
                'permid': perm_id,
                'pubkey': pubkey,
                'pubkey_md5': pubkey_md5,
                'email': email,
                'token': token,
                'status': status,
                'LinkedIn_Contacts_FID': LinkedIn_Contacts_FID,
            }
            )
    except Exception as e:
        app.logger.error(e)
    item.put()
    return item

def addto_dynamodb_signup(linked_id, token='N/A', oauth2_data='N/A',
                          access_token='N/A', oauth_expires_in='N/A'):
    """Return status, record"""
    if app.config['TESTING']:
        tbl = get_dynamodb_table(app.config['V2_SIGNUP'], hash_key='token')
    else:
        tbl = get_dynamodb_table(V2_SIGNUP, hash_key='token')

    if tbl.has_item(hash_key=token):
        item = tbl.get_item(
            hash_key=token,
            )
        item.delete()
    try:
        utc_now = datetime.datetime.utcnow()
        utc_now_10_min_later=utc_now + datetime.timedelta(minutes=TOKEN_LIFE_TIME)

        item = tbl.new_item(
            hash_key=token,
            attrs={
                'id': linked_id,
                'access_token': access_token,
                'oauth_expires_in': oauth_expires_in,
                'oauth2_data': oauth2_data,
                'created_in_utc': utc_now.strftime("%Y-%m-%d %H:%M"),
                'expires_in_utc': utc_now_10_min_later.strftime("%Y-%m-%d %H:%M")
            }
            )
    except Exception as e:
        app.logger.error(e)
    item.put()
    return item

def query_dynamodb_reg(linked_id, pubkey=None, email=None, token=None):
    """Return status, record"""
    tbl = get_dynamodb_table(app.config['V2_AUTH'])
    if not tbl.has_item(hash_key=linked_id):
        return 'invalid', {}
    item = tbl.get_item(
        hash_key=linked_id
        )
    if pubkey and item['pubkey'] != pubkey:
        return 'invalid', {}
    if email and item['email'] != email:
        return 'invalid', {}
    if token and item['token'] != token:
        return 'invalid', {}
    return item['status'], item

def generate_security_code():
    """Generate R-R-R-R-R random string R"""
    import random
    import string
    populate=string.uppercase+string.digits
    return "-".join([ "".join(random.sample(populate, 5)) for i in range(5)])

#def _generate_R():
#    """Generate 256-bit random string R"""
#    from Crypto import Random
#    return Random.new().read(32)

#def compute_C(rsa_pub_key_string, rand32):
#    from Crypto.PublicKey import RSA
#    from Crypto.Cipher import PKCS1_v1_5
#    from binascii import hexlify
#    rsa_pub = RSA.importKey(rsa_pub_key_string)
#    cipher = PKCS1_v1_5.new(rsa_pub)
#    return hexlify(cipher.encrypt(rand32))

def _write_contacts_result(path, code=0, contacts={}, extra={}):
    result = {}
    result['code'] = code

    # insert default extra object  
    if not extra:
        extra = {'code': 200, 'message': 'SUCCESS'}
    result['extra'] = {'code': 200, 'message': 'SUCCESS'}

    # remove 'linkedin_id' element if co-exist 'linkedin_id' and 'id'
    for key in contacts:
        if contacts[key].get('linkedin_id', None) and \
           contacts[key].get('id', None):
            if contacts[key]['linkedin_id'] == contacts[key]['id']:
                del contacts[key]['linkedin_id']
    result['contacts'] = contacts

    with open(path, "wb") as fout:
        json.dump(result, fout, indent=2)

def _get_associated_contacts(reg_item, access_token):
    '''
    >>> _get_associated_contacts(oauth_token, oauth_token_secret)
    {
        "me": {content object}
        "{ID}": {contact object},
        "{ID}": {contact object},
        ...
    }
    '''
    from regioh.LinkedInApi import LinkedInApi
    lkapi = LinkedInApi.LKAPI(client_id=LK_CLIENT_ID, client_secret=LK_CLIENT_SECRET)

    # get linkedIn profile
    status_profile, jobj_profile = lkapi.get_basic_profile(access_token)
    # get linkedIn connections
    linkedin_connections = []
    status, jobj = lkapi.get_connection(access_token)
    if jobj['_total'] != 0:
        linkedin_connections = [x for x in jobj['values'] if x['id'] != 'private']

    # associate connection with reg database
    contacts = associate_db_data_v2(linkedin_connections)

    #add myself as one record in contacts
    contacts['me'] = reg_item
    for index in jobj_profile:
        contacts['me'][index] = jobj_profile[index]
    return contacts

def register_email(linkedin_id, user_email, pubkey, token, record):

    contacts = {}

    file_id, perm_id = upload_contacts_and_share(contacts, user_email)

    # insert new record into dynamo db as contacts['me']
    item = addto_dynamodb_reg(linkedin_id, pubkey=pubkey,
                              token=token, perm_id=perm_id,
                              email=user_email, status='active',
                              LinkedIn_Contacts_FID=file_id)

    # get connetion associated with REG database
    contacts = _get_associated_contacts(item, record['access_token'],)


    #########################
    # must unshare before share to customer
    ########################
    success = unshare(file_id, perm_id)
    if not success:
        app.logger.error('unshare permission fail')
    ########################

    file_id, perm_id = upload_contacts_and_share(contacts, user_email)
    app.logger.debug(" create contact for {0}".format(user_email))

    # for each partner in 'contacts file', update their' "contact files"
    from default_config import ACCOUNTS
    index = 0
    for key in contacts:
        if key == 'me':
            continue
        partner_contact_file_id = contacts[key].get('LinkedIn_Contacts_FID', None)
        if partner_contact_file_id is None:
            continue

        # select a worker from ACCOUNTS to serve customer
        app.logger.debug(" worker {0} update customer {1}".format(
            ACCOUNTS[index % len(ACCOUNTS)],
            key))
        update_contact_file.apply_async(
            (linkedin_id, contacts['me'], contacts[key], ACCOUNTS[index % len(ACCOUNTS)]),
            serializer='json')
        index = index + 1

def _select_master():
    '''
    randomly select google agent from ACCOUNTS
    '''
    import random
    from default_config import PROJECT_ROOT
    from default_config import MASTER
    ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT), 'accounts',
                            MASTER))
    return ga

def _random_select_ga():
    '''
    randomly select google agent from ACCOUNTS
    '''
    import random
    from default_config import PROJECT_ROOT
    from default_config import ACCOUNTS
    index = random.randint(0, len(ACCOUNTS)-1)
    ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT), 'accounts',
                            ACCOUNTS[index]))
    return ga

def upload_contacts_and_share(contacts, user_email):
    '''
    upload contacts file to google drive and share to target user

    1. generate tempfile
    2. upload tempfile
    3. share to user
    '''
    _, temp_path = tempfile.mkstemp()
    with open(temp_path, "wb") as fout:
        _write_contacts_result(temp_path, code=0, contacts=contacts)

    ga = _random_select_ga()
    result = ga.create_or_update_file(app.config['gd_shared_roo_id'],
                                        temp_path,
                                        '{0} ({1}) DO NOT REMOVE THIS FILE.ioh'.format(
                                            'Cipherbox LinkedIn Contacts',
                                            user_email))
    file_id =  result['id']


    perm_id = make_user_reader_for_file(file_id, user_email)

    os.unlink(temp_path)

    return file_id, perm_id

def unshare(file_id, perm_id):
    ga = _random_select_ga()
    return ga.unshare(file_id, perm_id)

def make_user_reader_for_file(file_id, user_email):
    ga = _random_select_ga()
    result = ga.make_user_reader_for_file(file_id, user_email)
    return result['id']

