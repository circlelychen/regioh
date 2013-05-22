import logging
import os
import sys
import requests
import json
import urlparse

path = os.getcwd()
if path not in sys.path:
    sys.path.append(path)

from regioh.default_config import GD_CLIENT_ID
from regioh.default_config import GD_CLIENT_SECRET
from regioh.default_config import GD_REDIRECT_URL
from regioh.default_config import GD_LOGIN_HINT

def _access_v2_token(client_id, client_secret, authorization_code, redirect_uri):
    access_token_url = 'https://accounts.google.com/o/oauth2/token'
    params = {"client_id": client_id,
              "client_secret": client_secret,
              "code": authorization_code,
              "grant_type": u"authorization_code",
              "redirect_uri":redirect_uri}

    resp = requests.request('POST', access_token_url, data=params)

    if resp.status_code == 200:
        return resp.json()
    else:
        print resp.status_code
        print resp.content
        return None

def get_v2_access_token(paras):
    if len(paras) <= 0:
        sys.exit("Usage: get_v2_access_token <authorization_code>")

    client_id = GD_CLIENT_ID
    client_secret = GD_CLIENT_SECRET
    redirect_uri = GD_REDIRECT_URL
    authorization_code = paras[0]
    content_to_file = _access_v2_token(client_id, client_secret,
                                       authorization_code, redirect_uri)
    return content_to_file

def get_v2_request_url(paras):
    client_id = GD_CLIENT_ID
    client_secret = GD_CLIENT_SECRET
    redirect_url = GD_REDIRECT_URL
    print "Client ID : {0}".format(client_id)
    print "Client Secret : {0}".format(client_id)

    authorize_url = 'https://accounts.google.com/o/oauth2/auth'
    scope = "https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.appdata+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive"
    state = "DCEEFWF45453sdffef424"
    result = "{0}?response_type={5}&client_id={1}&scope={2}&state={3}&redirect_uri={4}".format(authorize_url, client_id, scope, state, redirect_url, "code")
    return result

def create_v2_token(params):
    fout = params[0]
    ticket_url = get_v2_request_url([])
    print "Go to the following link in your browser:\n"
    print "{0} \n".format(ticket_url)
    accepted = 'n'
    while accepted.lower() == 'n':
        accepted = raw_input('Have you authorized me? (y/n) ')
        oauth_verifier = raw_input('What is the authorization code? ')

    content = get_v2_access_token([oauth_verifier])
    with open(fout, 'wb') as fout:
        content['client_id'] = GD_CLIENT_ID
        content['client_secret'] = GD_CLIENT_SECRET
        json.dump(content, fout, indent=2)

def doCommand(cmd, *args):
    if cmd in globals():
        return globals()[cmd](list(args))
    else:
        raise LookupError("Command not recognised")

def main(argv):
    if len(argv) <= 2:
        out_sample = {"access_token": "aa", "id_token": "aa",
                      "expires_in": "aa", "token_type": "aa",
                      "client_id": "aa", "client_secret": "aa",
                      "refresh_token": "aa" }
        sys.exit("Usage: {0} <{1}> <output> \n## output sample ##\n{2}".format(
            argv[0],
            '|'.join([
                'create_v2_token',
            ]),
            json.dumps(out_sample, indent=2)))
    try:
        doCommand(argv[1], *argv[2:])
    except Exception as e:
        logging.basicConfig()
        logging.getLogger().exception(e)
if __name__ =='__main__':
    sys.exit(main(sys.argv))
