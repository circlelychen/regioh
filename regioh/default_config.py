import os
import json
USERNAME = 'admin'
PASSWORD = 'default'
PROJECT_ROOT = os.path.dirname(__file__)

#configuration
DEBUG = True
SECRET_KEY = os.environ.get("SECRET_KEY", '{{SECRET_KEY}}')

AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY", None)
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", None)
AWS_SES_SENDER = os.environ.get("AWS_SES_SENDER", '{{SENDER}}')
AWS_AUTH_FILE = os.path.join(os.path.dirname(PROJECT_ROOT), '.aws_auth')
if os.path.isfile(AWS_AUTH_FILE):
    with open(AWS_AUTH_FILE, 'rb') as fin:
        jobj = json.load(fin)
        AWS_ACCESS_KEY = jobj['access_key']
        AWS_SECRET_ACCESS_KEY = jobj['secret_key']

TWILIO_SID = None
TWILIO_TOKEN = None
TWILIO_FROM = None
TWILIO_FILE = os.path.join(os.path.dirname(PROJECT_ROOT), '.twilio')
if os.path.isfile(TWILIO_FILE):
    with open(TWILIO_FILE, 'rb') as fin:
        jobj = json.load(fin)
        TWILIO_SID = jobj['sid']
        TWILIO_TOKEN = jobj['auth']
        TWILIO_FROM = jobj['from']
