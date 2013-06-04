import os
import json
USERNAME = 'admin'
PASSWORD = 'default'
PROJECT_ROOT = os.path.dirname(__file__)

#configuration
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
        AWS_SES_SENDER = jobj['aws_ses_sender']

LK_AUTH_FILE = os.path.join(os.path.dirname(PROJECT_ROOT), '.lk_auth')
if os.path.isfile(LK_AUTH_FILE):
    with open(LK_AUTH_FILE, 'rb') as fin:
        jobj = json.load(fin)
        LK_CLIENT_ID = jobj['client_id']
        LK_CLIENT_SECRET = jobj['client_secret']
        LK_REDIRECT_URL = jobj['redirect_url']

########################################
# The following part is used by cipherbox_oauth_init
#######################################
GD_AUTH_FILE = os.path.join(os.path.dirname(PROJECT_ROOT), '.gd_auth')
if os.path.isfile(GD_AUTH_FILE):
    with open(GD_AUTH_FILE, 'rb') as fin:
        jobj = json.load(fin)
        GD_CLIENT_ID = jobj['client_id']
        GD_CLIENT_SECRET = jobj['client_secret']
        GD_REDIRECT_URL = jobj['redirect_url']
        GD_LOGIN_HINT = jobj['login_hint']

########################################
# credential for google dirve. gdapi
#######################################
TOKEN_LIFE_TIME = 30
V2_SIGNUP = 'v2_signup'
V2_AUTH = 'v2_auth'
#Dictionary describing response status for REST APIs
MESSAGE = {'success': 'SUCCESS',
           'no_linkedin_account': 'NO_LINKEDIN_ACCOUNT',
           'code_expired': 'CODE_EXPIRES',
           'identical': 'IDENTICAL',
           'identical_and_exist': 'IDENTICAL_AND_EXIST',
           'non_identical': 'NON_IDENTICAL',
          }

################################################
# initial 'regioh' shared folder for accounts
# for uploading/updating files
################################################
MASTER = 'cipherbox@cloudioh.com.cred.json'
ACCOUNTS = [
    #'cipherbox-ca-002@cloudioh.com.cred.json',
    #'cipherbox-ca-003@cloudioh.com.cred.json',
    #'cipherbox-ca-005@cloudioh.com.cred.json',
    #'cipherbox-ca-007@cloudioh.com.cred.json'
    'cipherbox@cloudioh.com.cred.json'
]
