# -*- coding: utf-8 -*-
"""
"""
import os
from boto import ses
from boto import dynamodb
from default_config import AWS_ACCESS_KEY
from default_config import AWS_SECRET_ACCESS_KEY
from default_config import AWS_SES_SENDER
from default_config import LK_CLIENT_SECRET
from default_config import LK_CLIENT_ID
from default_config import LK_REDIRECT_URL
from default_config import TOKEN_LIFE_TIME
from default_config import SIGNUP
from default_config import AUTH
import requests
import urlparse
import datetime
from requests_oauthlib import OAuth1

LINKEDIN_API_URL = 'https://api.linkedin.com/'
GOOGLE_DOWNLOAD_URL = 'https://docs.google.com/uc'

def _linkedin_request(url, access_token, access_secret):
    #use linkedin API with Oauth 1.0 token
    client_id = LK_CLIENT_ID
    client_secret = LK_CLIENT_SECRET
    url = urlparse.urljoin(LINKEDIN_API_URL,
                           'v1/people/~:(id,first-name,last-name,email-address)')
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
    #{{{ resp = requests.get(url=url,
    #                    params={
    #                        "oauth2_access_token": linked_token,
    #                        "format": "json"
    #                    },
    #                    verify=False)
    #}}}

def get_linkedin_basic_profile(access_token, access_secret):
    url = urlparse.urljoin(
        LINKEDIN_API_URL,
        'v1/people/~:(id,first-name,last-name,email-address)')
    return _linkedin_request(url, access_token, access_secret)

#{{{def get_oauth2_access_token(code):
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
#}}}

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
        return (r.status_code, r.content, request_token['oauth_token'],
                request_token['oauth_token_secret'])
    return r.status_code, r.content, None, None

def get_oauth1_access_token(oauth_token, oauth_verifier):
    from flask import session 
    client_id = LK_CLIENT_ID
    client_secret = LK_CLIENT_SECRET
    oauth_secret = session[oauth_token]
    session.pop(oauth_token, None)

    print "[check] client_id is {0}".format(client_id)
    print "[check] client_secret is {0}".format(client_secret)
    print "[check] oauth_token is {0}".format(oauth_token)
    print "[check] oauth_secret is {0}".format(oauth_secret)
    print "[check] oauth_verifier is {0}".format(oauth_verifier)

    http_code, http_content, access_token, access_secret = _access_v1_token(client_id,
                                                client_secret,
                                                oauth_token,
                                                oauth_secret,
                                                oauth_verifier)
    return http_content, access_token, access_secret 

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
    print "[check] client_id is {0}".format(client_id)
    print "[check] client_secret is {0}".format(client_secret)

    http_code, http_content, oauth_token, oauth_secret = _request_v1_token(client_id, client_secret)

    # cache oauth_secret into session
    print "[check] client_id is {0}".format(oauth_token)
    print "[check] client_secret is {0}".format(oauth_secret)
    session[oauth_token] = oauth_secret

    authorize_url ='https://api.linkedin.com/uas/oauth/authorize'
    return "{0}?oauth_token={1}".format(authorize_url, oauth_token)

#{{{def get_oauth2_request_url():
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
#}}}

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

#{{{def get_lk_token_status(linked_id, token):
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
#}}}


def get_token_check(token):
    from boto.dynamodb.condition import EQ
    from default_config import MESSAGE
    tbl = get_dynamodb_table(SIGNUP)
    actives = tbl.scan(
        scan_filter = {
            "token": EQ(token)},
        attributes_to_get = ['linkedin_id',
                             'oauth1_data',
                             'expires_in_utc']
        )

    result = {"status": "",
              "token": "",
              "reg_data": ""}
    if actives.count == 0:
        # security code does not match any record
        result['status'] = MESSAGE['no_linkedin_account']
        return result

    for active in actives:
        utc_now = datetime.datetime.utcnow()
        expires_in_utc = datetime.datetime.strptime(
            active['expires_in_utc'],
            "%Y-%m-%d %H:%M")
        if utc_now > expires_in_utc:
            # security code expire
            result['status'] = MESSAGE['code_expired']
            return result

        # security code match and not expire,
        result['status'] = MESSAGE['success']
        result['token'] = active['oauth1_data']
        status, record = query_dynamodb_reg(active['linkedin_id'])
        if record:
            result['reg_data'] = {"gmail": record['email']}
        return result

    #should not process the following part
    result['status'] = MESSAGE['no_linkedin_account']
    return result

def get_db_data(linked_ids):
    from boto.dynamodb.condition import EQ
    tbl = get_dynamodb_table(AUTH)
    actives = tbl.scan(scan_filter = {
        "status": EQ('active')
    #})
    }, attributes_to_get = ['linkedin_id', 'status',
                           'pubkey', 'email', 'permid', 'pubkey_md5'
                           ])
    result = {}

    for linked_id in linked_ids:
        result[linked_id] = {}
    for active in actives:
        active_id = active['linkedin_id']
        if active_id in linked_ids:
            result[active_id] = active
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
    print "AWS_SES_SENDER: {0}".format(AWS_SES_SENDER)
    try: 
        conn.send_email(AWS_SES_SENDER,
                        'Welcome to Cipherbox',
                        content,
                        [email])
        return True
    except Exception as e:
        return False

def get_dynamodb_table(table_name):
    conn = dynamodb.connect_to_region(
        'ap-northeast-1',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    tables = conn.list_tables()
    if table_name not in tables:
        auth_table_schema = conn.create_schema(
            hash_key_name='linkedin_id',
            hash_key_proto_value=str,
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
                   email='N/A', status='inactive'):
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
            }
            )
    except Exception as e:
        print e
    item.put()
    return item

def addto_dynamodb_signup(linked_id, token='N/A', oauth1_data='N/A'):
    """Return status, record"""
    tbl = get_dynamodb_table(SIGNUP)
    if tbl.has_item(hash_key=linked_id):
        item = tbl.get_item(
            hash_key=linked_id,
            )
        item.delete()
    try:
        utc_now = datetime.datetime.utcnow()
        utc_now_10_min_later=utc_now + datetime.timedelta(minutes=TOKEN_LIFE_TIME)

        item = tbl.new_item(
            hash_key=linked_id,
            attrs={
                'token': token,
                'oauth1_data': oauth1_data,
                'created_in_utc': utc_now.strftime("%Y-%m-%d %H:%M"),
                'expires_in_utc': utc_now_10_min_later.strftime("%Y-%m-%d %H:%M")
            }
            )
    except Exception as e:
        print e
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

def query_dynamodb_signup(linked_id):
    """Return status, record"""
    tbl = get_dynamodb_table(SIGNUP)
    if not tbl.has_item(hash_key=linked_id):
        return 'invalid', {}
    item = tbl.get_item(
        hash_key=linked_id
        )
    return item

def update_dynamodb(item):
    item.put()

def _generate_R():
    """Generate 256-bit random string R"""
    from Crypto import Random
    return Random.new().read(32)

def generate_security_code():
    """Generate R-R-R-R-R random string R"""
    import random
    import string
    populate=string.uppercase+string.digits
    return "-".join([ "".join(random.sample(populate, 5)) for i in range(5)])

def compute_C(rsa_pub_key_string, rand32):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    from binascii import hexlify
    rsa_pub = RSA.importKey(rsa_pub_key_string)
    cipher = PKCS1_v1_5.new(rsa_pub)
    return hexlify(cipher.encrypt(rand32))
