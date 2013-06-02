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
        "oauth_token": <str>,
        "oauth_token_secret": <str>,
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
              "oauth_token": "",
              "oauth_token_secret": "",
              "reg_data": ""}
    try:
        item = tbl.get_item(
            hash_key=token,
            attributes_to_get = ['id',
                                'oauth1_data',
                                'oauth_token',
                                'oauth_token_secret',
                                'expires_in_utc']
            )
    except Exception as e:
        # security code does not match any record
        app.logger.error("[ERROR] hash_key[ {0} ] has no items in {1} table, "
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
    result['token'] = item['oauth1_data']
    result['oauth_token'] = item['oauth_token']
    result['oauth_token_secret'] = item['oauth_token_secret']
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

def associate_db_data_v2(access_token, access_secret, linked_connections):
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

def addto_dynamodb_signup(linked_id, token='N/A', oauth1_data='N/A',
                          oauth_token='N/A', oauth_token_secret='N/A',
                          oauth_expires_in='N/A'):
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
                'oauth_token': oauth_token,
                'oauth_token_secret': oauth_token_secret,
                'oauth_expires_in': oauth_expires_in,
                'oauth1_data': oauth1_data,
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

#def query_dynamodb_signup(linked_id):
#    """Return status, record"""
#    tbl = get_dynamodb_table(V2_SIGNUP, hash_key='token')
#    if not tbl.has_item(hash_key=linked_id):
#        return 'invalid', {}
#    item = tbl.get_item(
#        hash_key=linked_id
#        )
#    return item

def update_dynamodb(item):
    item.put()

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


#def fetch_public_key(google_file_id):
#    import requests
#    url = GOOGLE_DOWNLOAD_URL
#    resp = requests.get(url,
#                        params={
#                            'export': 'download',
#                            'id': google_file_id,
#                        }
#                       )
#    if resp.status_code == 200:
#        return resp.content
#    return None

###########################################
# helper function for Google Drive 
##########################################
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

def _get_associated_contacts(reg_item, oauth_token, oauth_token_secret):
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
    status_profile, jobj_profile = lkapi.get_basic_profile(oauth_token,
                                                           oauth_token_secret)
    # get linkedIn connections
    linkedin_connections = []
    status, jobj = lkapi.get_connection(oauth_token,oauth_token_secret)
    if jobj['_total'] != 0:
        linkedin_connections = [x for x in jobj['values'] if x['id'] != 'private']

    # associate connection with reg database
    contacts = associate_db_data_v2(oauth_token,oauth_token_secret,
                                    linkedin_connections)

    #add myself as one record in contacts
    contacts['me'] = reg_item
    for index in jobj_profile:
        contacts['me'][index] = jobj_profile[index]
    return contacts

def register_email(linkedin_id, user_email, pubkey, token, record):

    contacts = {}

    #file_id, perm_id = upload_contacts_and_share(contacts, user_email)
    file_id, perm_id = upload_contacts_and_share(contacts, user_email)

    # insert new record into dynamo db as contacts['me']
    item = addto_dynamodb_reg(linkedin_id, pubkey=pubkey,
                              token=token, perm_id=perm_id,
                              email=user_email, status='active',
                              LinkedIn_Contacts_FID=file_id)

    # get connetion associated with REG database
    contacts = _get_associated_contacts(item, record['oauth_token'],
                                        record['oauth_token_secret'])


    #file_id, perm_id = upload_contacts_and_share(contacts, user_email)
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
    file_id = upload_file(app.config['gd_shared_roo_id'], temp_path,
                          '{0} ({1}) DO NOT REMOVE THIS FILE.ioh'.format(
                              'Cipherbox LinkedIn Contacts',
                              user_email))
    #os.unlink(temp_path)
    perm_id = make_user_reader_for_file(file_id, user_email)
    os.unlink(temp_path)
    return file_id, perm_id

def upload_file(parent_id, file_path, file_name):
    '''
    use content in local file_path to

    1. create file if there is no file
    2. update file if there is a file existing

    return file_id
    '''
    ga = _random_select_ga()
    result = ga.create_or_update_file(parent_id, file_path, file_name)
    return result['id']

def update_file(file_id, file_path):
    '''
    use content in local file_path to overwrite remote
    file pointed by file_id

    return file_id
    '''
    ga = _random_select_ga()
    result = ga.update_file(file_id, file_path)
    try:
        #app.logger.info('### \n{0} \n'.format(result))
        return result['id']
    except Exception as e:
        app.logger.error('[error] in update_file' )
        app.logger.error(result)


def download_file(file_id, dest_path):
    ga = _random_select_ga()
    success = ga.download_file(file_id, dest_path)
    return success

def unshare(res_id, perm_id):
    ga = _random_select_ga()
    success = ga.unshare(res_id, perm_id)
    return success


def make_user_reader_for_file(file_id, user_email):
    ga = _random_select_ga()
    result = ga.make_user_reader_for_file(file_id, user_email)
    return result['id']

def check_file_exist(file_id):
    ga = _random_select_ga()
    drive_file = ga.get_file_meta(file_id)
    if drive_file is None:
        return False
    return True

#def create_folder(parent_id, title):
#    '''
#    1. create folder if there is no items
#    2. update folder if there is a item existing
#
#    return folder_id
#    '''
#    ga = _random_select_ga()
#    folder_id = ga.create_folder(parent_id, title)
#    return folder_id


#def get_lk_token_status(linked_id, token):
#    from boto.dynamodb.condition import EQ
#    from default_config import MESSAGE
#
#    # check identity without token.
#    if token == 'Null':
#        status, record = query_dynamodb_reg(linked_id)
#        if not record:
#            return MESSAGE['identical']
#        else:
#            return MESSAGE['identical_and_exist']
#
#    # check identity with token. 
#    message, item = get_token_status(token)
#    if message == MESSAGE['no_linkedin_account'] or \
#       message == MESSAGE['code_expired']:
#        return message
#    if item['linkedin_id'] == linked_id:
#        status, record = query_dynamodb_reg(linked_id)
#        if not record:
#            return MESSAGE['identical']
#        else:
#            return MESSAGE['identical_and_exist']
#    else:
#        return MESSAGE['non_identical']
#

#def get_oauth2_request_url():
#    client_id = LK_CLIENT_ID
#    client_secret = LK_CLIENT_SECRET
#    redirect_url = LK_REDIRECT_URL 
#    authorize_url = 'https://www.linkedin.com/uas/oauth2/authorization'
#    scope = "r_basicprofile%20r_emailaddress"
#    state = "DCEEFWF45453sdffef424"
#
#    params = []
#    params.append("response_type={0}".format("code"))
#    params.append("client_id={0}".format(client_id))
#    params.append("scope={0}".format(scope))
#    params.append("state={0}".format(state))
#    params.append("redirect_uri={0}".format(redirect_url))
#    return "{0}?{1}".format(authorize_url, "&".join(params))

#def get_oauth2_access_token(code):
#    client_id = LK_CLIENT_ID
#    client_secret = LK_CLIENT_SECRET
#    redirect_url = LK_REDIRECT_URL 
#    access_token_url = 'https://www.linkedin.com/uas/oauth2/accessToken'
#    params = {"client_id": client_id, "client_secret": client_secret,
#              "code": code, "grant_type": "authorization_code",
#              "redirect_uri":redirect_url}
#    resp = requests.request('POST', access_token_url, params=params)
#    if resp.status_code == 200:
#        return resp.json()
#    else:
#        return None
#
