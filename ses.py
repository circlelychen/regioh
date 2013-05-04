import os
import boto.ses
import json
from regioh.default_config import AWS_ACCESS_KEY
from regioh.default_config import AWS_SECRET_ACCESS_KEY

AWS_AUTH_FILE = '.aws_auth'
if os.path.isfile(AWS_AUTH_FILE):
    with open(AWS_AUTH_FILE, 'rb') as fin:
        jobj = json.load(fin)
        AWS_ACCESS_KEY = jobj['access_key']
        AWS_SECRET_ACCESS_KEY = jobj['secret_key']

print boto.ses.regions()
conn = boto.ses.connect_to_region(
    'us-east-1',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
conn.verify_email_address('howard_chen@cloudioh.com')
