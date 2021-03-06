import logging
import os
import sys
import requests
import json
import urlparse

path = os.getcwd()
if path not in sys.path:
    sys.path.append(path)

from regioh import app

######################################
# Linkedin API 
################################################
from regioh.default_config import LK_CLIENT_SECRET
from regioh.default_config import LK_CLIENT_ID
from regioh.LinkedInApi import LKOAuth1API
from regioh.LinkedInApi import LKOAuth2API
from regioh.LinkedInApi import LinkedInApi
################################################

def _get_linkedin_oauth1_cred_frm_dynamo(user_email):
    from regioh.api_helper import get_dynamodb_table
    from regioh.default_config import V2_AUTH
    from regioh.default_config import V2_SIGNUP
    from boto.dynamodb.condition import EQ

    # get linkedin id by user_email
    tbl = get_dynamodb_table(app.config['V2_AUTH'])
    items = tbl.scan( scan_filter = {'email': EQ(user_email)},
                     attributes_to_get = ['linkedin_id'])

    linkedin_id = None
    for item in items:
        if item:
           linkedin_id = item['linkedin_id']
           break

    # get OAuth id by linkedin_id
    tbl = get_dynamodb_table(app.config['V2_SIGNUP'])
    try:
        items = tbl.scan( scan_filter = {'id': EQ(linkedin_id)},
                        attributes_to_get = ['oauth_token', 'oauth_token_secret'])
    except Exception as e:
        print '[ERROR] invalid primary key with {0}:'.format(linkedin_id)
        sys.exit(0)

    oauth_token = None
    oauth_token_secret = None
    for item in items:
        if item:
            oauth_token = item['oauth_token']
            oauth_token_secret = item['oauth_token_secret']
    return oauth_token, oauth_token_secret

def _get_linkedin_oauth2_cred_frm_dynamo(user_email):
    from regioh.api_helper import get_dynamodb_table
    from regioh.default_config import V2_AUTH
    from regioh.default_config import V2_SIGNUP
    from boto.dynamodb.condition import EQ

    # get linkedin id by user_email
    tbl = get_dynamodb_table(app.config['V2_AUTH'])
    items = tbl.scan( scan_filter = {'email': EQ(user_email)},
                     attributes_to_get = ['linkedin_id'])

    linkedin_id = None
    for item in items:
        if item:
           linkedin_id = item['linkedin_id']
           break

    # get OAuth id by linkedin_id
    tbl = get_dynamodb_table(app.config['V2_SIGNUP'])
    try:
        items = tbl.scan( scan_filter = {'id': EQ(linkedin_id)},
                        attributes_to_get = ['access_token'])
    except Exception as e:
        print '[ERROR] invalid primary key with {0}:'.format(linkedin_id)
        sys.exit(0)

    access_token = None
    for item in items:
        if item and \
           item.get('access_token', None):
            access_token = item['access_token']
    return access_token

def connection(argv):
    if len(argv) < 1:
        sys.exit("Usage: {0} connection <{1}> ".format(
            sys.argv[0], 'user_email', 'output_file'))

    user_email = argv[0]
    access_token = _get_linkedin_oauth2_cred_frm_dynamo(user_email)

    lkapi = LinkedInApi.LKAPI(client_id=LK_CLIENT_ID, client_secret=LK_CLIENT_SECRET)
    status, jobj = lkapi.get_connection(access_token)

    linkedin_connections = []
    if jobj['_total'] != 0:
        app.logger.info(u"total : {0}".format(jobj['_total']))
        linkedin_connections = [x for x in jobj['values'] if x['id'] != 'private']
    for contact in linkedin_connections:
         app.logger.info(u"firstName: {0}, lastName: {1}".format(contact['firstName'],
                                                                 contact['lastName']))
def profile(argv):
    if len(argv) < 1:
        sys.exit("Usage: {0} connection <{1}> <{2}>".format(
            sys.argv[0], 'user_email', 'output_file'))

    user_email = argv[0]
    access_token = _get_linkedin_oauth2_cred_frm_dynamo(user_email)

    lkapi = LinkedInApi.LKAPI(client_id=LK_CLIENT_ID, client_secret=LK_CLIENT_SECRET)
    status, jobj = lkapi.get_basic_profile(access_token)

    app.logger.info(u"profile: ==== \n\n {0}".format(json.dumps(jobj, indent=2)))

def doCommand(cmd, *args):
    if cmd in globals():
        return globals()[cmd](list(args))
    else:
        raise LookupError('command not found')

def main(argv):
    if len(argv) < 2:
        sys.exit("Usage: {0} <{1}>".format(
            argv[0],
            '|'.join([
                'connection',
                'profile'
            ])))
    try:
        doCommand(argv[1], *argv[2:])
    except Exception as e:
        import logging
        logging.basicConfig()
        logging.getLogger().exception(e)

if __name__ == '__main__':
    sys.exit(main(sys.argv))

