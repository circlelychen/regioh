import os
import boto.ses
import json
import sys

path = os.getcwd()
if path not in sys.path:
    sys.path.append(path)

from regioh.default_config import AWS_ACCESS_KEY
from regioh.default_config import AWS_SECRET_ACCESS_KEY
from regioh.default_config import AWS_SES_SENDER

print "boto.ses.connect region :{0}".format(boto.ses.regions())
conn = boto.ses.connect_to_region(
    'us-east-1',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

resp = conn.send_email(AWS_SES_SENDER,
                       'Welcome to Cipherbox',
                       'test',
                       ['cipherbox@cloudioh.com'])

