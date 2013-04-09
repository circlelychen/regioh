# -*- coding: utf-8 -*-
"""
"""
import os
from boto import ses
from boto import dynamodb
from default_config import AWS_ACCESS_KEY
from default_config import AWS_SECRET_ACCESS_KEY
from default_config import AWS_SENDER

LINKEDIN_API_URL = 'https://api.linkedin.com/'

def retrieve_linkedin_id(linked_token):
    import requests
    import urlparse
    url = urlparse.urljoin(LINKEDIN_API_URL,
                           '/v1/people/~:(id)')
    resp = requests.get(url,
                        params={
                            'oauth2_access_token': linked_token.strip(),
                            'format': 'json'
                        }
                       )
    if resp.status_code == 200:
        return resp.json()['id']
    return None

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


def notify_email(email, content):
    conn = ses.connect_to_region(
        'us-east-1',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    if not conn:
        raise Exception
    conn.send_email(AWS_SENDER,
                    'IOH Confirmation',
                    content,
                    [email])

def get_dynamodb_table():
    conn = dynamodb.connect_to_region(
        'ap-northeast-1',
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
            read_units=10,
            write_units=10
            )
    else:
        table = conn.get_table('auth')
    return table

def addto_dynamodb(email, pubkey=None, token=None, linked_id='N/A'):
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
            'pubkey': pubkey,
            'linkedin_id': linked_id,
            'token': token,
            'status': 'inactive',
        }
        )
    #print item
    item.put()
    return item

def query_dynamodb(email, pubkey=None, linked_id=None, token=None):
    """Return status, record"""
    tbl = get_dynamodb_table()
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

def generate_OTP():
    from random import choice
    from string import digits
    return ''.join(choice(digits) for x in xrange(6))

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
