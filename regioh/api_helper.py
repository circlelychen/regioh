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
from default_config import SIGNUP
from default_config import V2_SIGNUP
from default_config import AUTH
from default_config import v2_AUTH

# gdapi module for interact with Google Drive
from gdapi.gdapi import GDAPI
from default_config import GD_CRED_FILE

import requests
import urlparse
import datetime
from requests_oauthlib import OAuth1

import tempfile
import json
from tasks import update_contact_file

LINKEDIN_API_URL = 'https://api.linkedin.com/'
GOOGLE_DOWNLOAD_URL = 'https://docs.google.com/uc'

def _linkedin_request(url, access_token, access_secret):
    #use linkedin API with Oauth 1.0 token
    client_id = LK_CLIENT_ID
    client_secret = LK_CLIENT_SECRET
    #url = urlparse.urljoin(LINKEDIN_API_URL,
    #                       'v1/people/~:(id,first-name,last-name,email-address)')
    oauth = OAuth1(client_id, client_secret=client_secret,
                   resource_owner_key=access_token,
                   resource_owner_secret=access_secret)

    resp = requests.get(url,
                        params={
                            'format': 'json'
                        },
                        auth=oauth
                       )
    if resp.status_code == 200:
        return resp.status_code, resp.json()
    return resp.status_code, {'reason': 'unknown error', 'raw': resp.content}
    #resp = requests.get(url=url,
    #                    params={
    #                        "oauth2_access_token": linked_token,
    #                        "format": "json"
    #                    },
    #                    verify=False)
    #

def get_linkedin_basic_profile(access_token, access_secret):
    url = urlparse.urljoin(
        LINKEDIN_API_URL,
        'v1/people/~:(id,first-name,last-name,picture-url,public-profile-url,positions,headline,email-address)')
    return _linkedin_request(url, access_token, access_secret)

def get_linkedin_connection(access_token, access_secret):
    url = urlparse.urljoin(
        LINKEDIN_API_URL, 'v1/people/~/connections'
        ':(id,first-name,last-name,positions,picture-url,public-profile-url)')
    return _linkedin_request(url, access_token, access_secret)

def _access_v1_token(client_id, client_secret, oauth_token, oauth_secret, pin_code):
    access_token_url = 'https://api.linkedin.com/uas/oauth/accessToken'
    oauth = OAuth1(client_id,
                   client_secret=client_secret,
                   resource_owner_key=oauth_token,
                   resource_owner_secret=oauth_secret,
                   verifier=pin_code)
    r = requests.post(url=access_token_url, auth=oauth, verify=False)
    if r.status_code == 200:
        request_token = dict(urlparse.parse_qsl(r.content))
        return (r.status_code,
                r.content,
                request_token['oauth_token'],
                request_token['oauth_token_secret'],
                request_token['oauth_expires_in'])
    return r.status_code, r.content, None, None

def get_oauth1_access_token(oauth_token, oauth_verifier):
    from flask import session
    client_id = LK_CLIENT_ID
    client_secret = LK_CLIENT_SECRET
    try:
        oauth_secret = session[oauth_token]
    except:
        app.logger.error('session[{0}] is None'.format(oauth_token,
                                                       session.get(oauth_token,
                                                                  None)))
        raise KeyError
    session.pop(oauth_token, None)

    app.logger.debug("[check] client_id is {0}".format(client_id))
    app.logger.debug("[check] client_secret is {0}".format(client_secret))
    app.logger.debug("[check] oauth_token is {0}".format(oauth_token))
    app.logger.debug("[check] oauth_secret is {0}".format(oauth_secret))
    app.logger.debug("[check] oauth_verifier is {0}".format(oauth_verifier))

    http_code, http_content, access_token, access_secret, expires_in = _access_v1_token(client_id,
                                                                                        client_secret,
                                                                                        oauth_token,
                                                                                        oauth_secret,
                                                                                        oauth_verifier)
    return http_content, access_token, access_secret, expires_in

def _request_v1_token(client_id, client_secret):
    request_token_url      = 'https://api.linkedin.com/uas/oauth/requestToken'
    oauth = OAuth1(client_id, client_secret=client_secret)
    r = requests.post(url=request_token_url, params={"scope":
                                                     "r_fullprofile r_emailaddress r_network"},
                      auth=oauth, verify=False)
    if r.status_code == 200:
        request_token = dict(urlparse.parse_qsl(r.content))
        return (r.status_code, r.content, request_token['oauth_token'],
                request_token['oauth_token_secret'])
    return r.status_code, r.content, None, None

def get_oauth1_request_url():
    from flask import session
    client_id = LK_CLIENT_ID
    client_secret = LK_CLIENT_SECRET
    app.logger.debug("[check] client_id is {0}".format(client_id))
    app.logger.debug("[check] client_secret is {0}".format(client_secret))

    http_code, http_content, oauth_token, oauth_secret = _request_v1_token(client_id, client_secret)

    # cache oauth_secret into session
    app.logger.debug("[check] client_id is {0}".format(oauth_token))
    app.logger.debug("[check] client_secret is {0}".format(oauth_secret))
    session[oauth_token] = oauth_secret

    authorize_url ='https://api.linkedin.com/uas/oauth/authorize'
    return "{0}?oauth_token={1}".format(authorize_url, oauth_token)

def verify_linkedin_status(linked_ids):
    from boto.dynamodb.condition import EQ
    tbl = get_dynamodb_table(AUTH)
    actives = tbl.scan(scan_filter = {
        "status": EQ('active')
    })#, attributes_to_get = ['linkedin_id', 'status'])
    result = {}
    #for active in actives:
    #    print active
    #    if active.get('linkedin_id', None) is None:
    #        active.delete()

    for linked_id in linked_ids:
        result[linked_id] = 'inactive'
    for active in actives:
        active_id = active['linkedin_id']
        if active_id in linked_ids:
            result[active_id] = 'active'
    return result

def get_token_check(token):
    ''' (str) -> dict

    return Dict of (status, oauth, email) if token is valid

    >> get_token_check(token)
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
    tbl = get_dynamodb_table(V2_SIGNUP, hash_key='token')

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
    except DynamoDBKeyNotFoundError:
        # security code does not match any record
        result['status'] = MESSAGE['no_linkedin_account']
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
    status, record = query_dynamodb_reg(item['id'])
    if record:
        result['reg_data'] = {"gmail": record['email']}
        app.logger.debug("get_token_check [SUCCESS]")
    return result

def associate_db_data_v2(access_token, access_secret, linked_connections):
    result = {}
    ids = []
    for linkedin_item in linked_connections:
        result[linkedin_item['id']] = linkedin_item
        result[linkedin_item['id']]['status'] = 'inactive'
        ids.append(linkedin_item['id'])
    tbl = get_dynamodb_table(v2_AUTH)
    actives = tbl.batch_get_item(
        ids,
        attributes_to_get = ['linkedin_id', 'status',
                             'pubkey', 'email', 'permid',
                             'pubkey_md5', 'contact_fid'
                            ])
    for active in actives:
        active_id = active['linkedin_id']
        for key in active:
            result[active_id][key] = active[key]
    return result

def fetch_public_key(google_file_id):
    import requests
    url = GOOGLE_DOWNLOAD_URL
    resp = requests.get(url,
                        params={
                            'export': 'download',
                            'id': google_file_id,
                        }
                       )
    if resp.status_code == 200:
        return resp.content
    return None

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
                       contact_fid='N/A'):
    """Return status, record"""
    tbl = get_dynamodb_table(AUTH)
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
                'contact_fid': contact_fid,
            }
            )
    except Exception as e:
        app.logger.error(e)
    item.put()
    return item

def addto_dynamodb_reg_v2(linked_id, pubkey='N/A', token='N/A',
                          pubkey_md5='N/A', perm_id='N/A',
                          email='N/A', status='inactive',
                          contact_fid='N/A'):
    """Return status, record"""
    tbl = get_dynamodb_table(v2_AUTH)
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
                'contact_fid': contact_fid,
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
    tbl = get_dynamodb_table(AUTH)
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

def generate_security_code():
    """Generate R-R-R-R-R random string R"""
    import random
    import string
    populate=string.uppercase+string.digits
    return "-".join([ "".join(random.sample(populate, 5)) for i in range(5)])

#def compute_C(rsa_pub_key_string, rand32):
#    from Crypto.PublicKey import RSA
#    from Crypto.Cipher import PKCS1_v1_5
#    from binascii import hexlify
#    rsa_pub = RSA.importKey(rsa_pub_key_string)
#    cipher = PKCS1_v1_5.new(rsa_pub)
#    return hexlify(cipher.encrypt(rand32))


###########################################
# helper function for Google Drive 
##########################################
def _write_contacts_result(fout, code=0, contacts={}, extra={}):
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

    json.dump(result, fout, indent=2)

def register_email(linkedin_id, user_email, pubkey, token, record):

    app.logger.debug("start to get linkedin connections:")
    status, jobj = get_linkedin_connection(record['oauth_token'],
                                           record['oauth_token_secret'])
    linkedin_connections = [x for x in jobj['values'] if x['id'] != 'private']
    app.logger.debug("start to associate db data:")
    contacts = associate_db_data_v2(record['oauth_token'],
                                    record['oauth_token_secret'],
                                    linkedin_connections)

    app.logger.debug("start to get linkedin profile:")
    status_profile, jobj_profile = get_linkedin_basic_profile(record['oauth_token'],
                                                              record['oauth_token_secret'])

    app.logger.debug("start to insert contacts into GD:")
    # insert "contacts file" into GD
    _, temp_path = tempfile.mkstemp()
    with open(temp_path, "wb") as fout:
        json.dump(contacts, fout, indent=2)
    folder_id = create_folder(app.config['gd_shared_roo_id'],
                              user_email)
    file_id = upload_file(folder_id, temp_path)

    # share "contact file" to requester 
    success = unshare(file_id)
    perm_id = make_user_reader_for_file(file_id, user_email)

    # insert new record into dynamo db
    app.logger.debug("start to insert db data:")
    item = addto_dynamodb_reg_v2(linkedin_id, pubkey=pubkey,
                                 token=token, perm_id=perm_id,
                                 email=user_email, status='active',
                                 contact_fid=file_id)

    app.logger.debug("start to insert contacts into GD again:")
    #add myself as one record in contacts
    contacts['me'] = item
    for index in jobj_profile:
        contacts['me'][index] = jobj_profile[index]
    with open(temp_path, "wb") as fout:
        _write_contacts_result(fout, code=0, contacts=contacts)
    update_file(file_id, temp_path)
    os.unlink(temp_path)

    # for each partner in 'contacts file', update their' "contact files"
    app.logger.debug("start to update connections' contacts files:")
    from default_config import ACCOUNTS
    index = 0
    for key in contacts:
        if key == 'me':
            continue
        partner_contact_file_id = contacts[key].get('contact_fid', None)
        if partner_contact_file_id is None:
            continue

        # select a worker from ACCOUNTS to serve customer
        app.logger.debug(" worker {0} update customer {1}".format(
            ACCOUNTS[index % len(ACCOUNTS)],
            key))
        update_contact_file.apply_async(
            (linkedin_id, item, jobj_profile, contacts[key],
             worker_name = ACCOUNTS[index % len(ACCOUNTS)]),
            serializer='json')
        # temp only use cipherbox@cloudioh.com
        #update_contact_file.apply_async(
        #    (linkedin_id, item, jobj_profile, contacts[key]),
        #    serializer='json')
        #index = index + 1

def upload_file(parent_id, file_path):
    '''
    use content in local file_path to

    1. create file if there is no file
    2. update file if there is a file existing

    return file_id
    '''
    ga = GDAPI(GD_CRED_FILE)
    result = ga.create_or_update_file(parent_id, file_path,
                                      'Cipherbox Contacts')
    return result['id']

def update_file(file_id, file_path):
    '''
    use content in local file_path to overwrite remote
    file pointed by file_id

    return file_id
    '''
    ga = GDAPI(GD_CRED_FILE)
    result = ga.update_file(file_id, file_path)
    try:
        app.logger.info('### \n{0} \n'.format(result))
        return result['id']
    except Exception as e:
        app.logger.error('[error] in update_file' )
        app.logger.error(result)


def download_file(file_id, dest_path):
    ga = GDAPI(GD_CRED_FILE)
    success = ga.download_file(file_id, dest_path)
    return success

def create_folder(parent_id, title):
    '''
    1. create folder if there is no items
    2. update folder if there is a item existing

    return folder_id
    '''
    ga = GDAPI(GD_CRED_FILE)
    folder_id = ga.create_folder(parent_id, title)
    return folder_id

def unshare(res_id):
    ga = GDAPI(GD_CRED_FILE)
    success = ga.unshare(res_id)
    return success


def make_user_reader_for_file(file_id, user_email):
    ga = GDAPI(GD_CRED_FILE)
    result = ga.make_user_reader_for_file(file_id, user_email)
    return result['id']

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
