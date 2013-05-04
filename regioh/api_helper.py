# -*- coding: utf-8 -*-
"""
"""
import os
from boto import ses
from boto import dynamodb
from default_config import AWS_ACCESS_KEY
from default_config import AWS_SECRET_ACCESS_KEY
from default_config import AWS_SES_SENDER
import requests
import urlparse

LINKEDIN_API_URL = 'https://api.linkedin.com/'
GOOGLE_DOWNLOAD_URL = 'https://docs.google.com/uc'

CLIENT_ID = 'b7yzd71kbuy5'
CLIENT_SECRET = 'EpF8TeBrNgoj8UMj'
REDIRECT_URI = 'http://192.168.1.10:5000/signup'

def _linkedin_request(url, linked_token):
    #use linkedin API with Oauth 1.0 token
    resp = requests.get(url=url,
                        params={
                            "oauth2_access_token": linked_token,
                            "format": "json"
                        },
                        verify=False)
    if resp.status_code == 200:
        return resp.status_code, resp.json()
    return resp.status_code, {'reason': 'unknown error', 'raw': resp.content}

def get_linkedin_basic_profile(linked_token):
    url = urlparse.urljoin(
        LINKEDIN_API_URL,
        'v1/people/~:(id,first-name,last-name,email-address)')
    return _linkedin_request(url, linked_token.strip())

def retrieve_linkedin_id_and_name(linked_token):
    import requests
    import urlparse
    from requests_oauthlib import OAuth1
    url = urlparse.urljoin(LINKEDIN_API_URL,
                           '/v1/people/~:(id,first-name,last-name)')
    oauth = OAuth1(linked_token['client_id'],
                   client_secret=linked_token['client_secret'],
                   resource_owner_key=linked_token['oauth_token'],
                   resource_owner_secret=linked_token['oauth_secret'])

    resp = requests.get(url,
                        params={
                            'format': 'json'
                        },
                        auth=oauth
                       )
    if resp.status_code == 200:
        return resp.json()['id'], resp.json()['firstName'], resp.json()['lastName']
    return None, None, None

def retrieve_linkedin_id(linked_token):
    import requests
    import urlparse
    from requests_oauthlib import OAuth1
    url = urlparse.urljoin(LINKEDIN_API_URL,
                           '/v1/people/~:(id)')
    oauth = OAuth1(linked_token['client_id'],
                   client_secret=linked_token['client_secret'],
                   resource_owner_key=linked_token['oauth_token'],
                   resource_owner_secret=linked_token['oauth_secret'])

    resp = requests.get(url,
                        params={
                            'format': 'json'
                        },
                        auth=oauth
                       )
    if resp.status_code == 200:
        return resp.json()['id']
    return None

def get_oauth2_access_token(code):
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    redirect_url = REDIRECT_URI 
    access_token_url = 'https://www.linkedin.com/uas/oauth2/accessToken'
    params = {"client_id": client_id, "client_secret": client_secret,
              "code": code, "grant_type": "authorization_code",
              "redirect_uri":redirect_url}
    resp = requests.request('POST', access_token_url, params=params)
    if resp.status_code == 200:
        return resp.json()
    else:
        return None

def get_oauth2_request_url():
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    redirect_url = REDIRECT_URI 
    authorize_url = 'https://www.linkedin.com/uas/oauth2/authorization'
    scope = "r_basicprofile%20r_emailaddress"
    state = "DCEEFWF45453sdffef424"

    params = []
    params.append("response_type={0}".format("code"))
    params.append("client_id={0}".format(client_id))
    params.append("scope={0}".format(scope))
    params.append("state={0}".format(state))
    params.append("redirect_uri={0}".format(redirect_url))
    return "{0}?{1}".format(authorize_url, "&".join(params))

def verify_linkedin_status(linked_ids):
    from boto.dynamodb.condition import EQ
    tbl = get_dynamodb_table()
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

def get_db_data(linked_ids):
    from boto.dynamodb.condition import EQ
    tbl = get_dynamodb_table()
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
    conn.send_email(AWS_SES_SENDER,
                    'IOH Confirmation',
                    content,
                    [email])

def get_dynamodb_table():
    conn = dynamodb.connect_to_region(
        'us-west-2',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    tables = conn.list_tables()
    if 'auth' not in tables:
        auth_table_schema = conn.create_schema(
            hash_key_name='email',
            hash_key_proto_value=str,
            )
        table = conn.create_table(
            name='auth',
            schema=auth_table_schema,
            read_units=1,
            write_units=1
            )
    else:
        table = conn.get_table('auth')
    return table

def addto_dynamodb(email, pubkey=None, token=None,
                   pubkey_md5='N/A', perm_id='N/A',
                   linked_id='N/A', status='inactive'):
    """Return status, record"""
    tbl = get_dynamodb_table()
    if tbl.has_item(hash_key=email):
        item = tbl.get_item(
            hash_key=email,
            )
        #if item['status'] != 'active':
        item.delete()
    item = tbl.new_item(
        hash_key=email,
        attrs={
            'permid': perm_id,
            'pubkey': pubkey,
            'pubkey_md5': pubkey_md5,
            'linkedin_id': linked_id,
            'token': token,
            'status': status,
        }
        )
    #print item
    item.put()
    return item

def query_dynamodb(email, pubkey=None, linked_id=None, token=None):
    """Return status, record"""
    tbl = get_dynamodb_table()
    print email
    if not tbl.has_item(hash_key=email):
        return 'invalid', {}
    item = tbl.get_item(
        hash_key=email
        )
    if pubkey and item['pubkey'] != pubkey:
        return 'invalid', {}
    if linked_id and item['linkedin_id'] != linked_id:
        return 'invalid', {}
    if token and item['token'] != token:
        return 'invalid', {}
    return item['status'], item

def update_dynamodb(item):
    item.put()

def generate_R():
    """Generate 256-bit random string R"""
    from Crypto import Random
    return Random.new().read(32)

def compute_C(rsa_pub_key_string, rand32):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    from binascii import hexlify
    rsa_pub = RSA.importKey(rsa_pub_key_string)
    cipher = PKCS1_v1_5.new(rsa_pub)
    return hexlify(cipher.encrypt(rand32))
