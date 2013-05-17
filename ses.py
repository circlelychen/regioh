import os
import boto.ses
import json
from regioh.default_config import AWS_ACCESS_KEY
from regioh.default_config import AWS_SECRET_ACCESS_KEY
from regioh.default_config import AWS_SES_SENDER

AWS_AUTH_FILE = '.aws_auth'
if os.path.isfile(AWS_AUTH_FILE):
    with open(AWS_AUTH_FILE, 'rb') as fin:
        jobj = json.load(fin)
        AWS_ACCESS_KEY = jobj['access_key']
        AWS_SECRET_ACCESS_KEY = jobj['secret_key']

print "boto.ses.connect region :{0}".format(boto.ses.regions())
conn = boto.ses.connect_to_region(
    'us-east-1',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

resp = {'SendEmailResponse': None}
while not resp.get('SendEmailResponse', None):
    resp = conn.send_email(AWS_SES_SENDER,
                            'Welcome to Cipherbox',
                            'test',
                            ['cipherbox@cloudioh.com'])
    print resp

