# -*- coding: utf-8 -*-
import json
import logging
import requests
import urlparse


class LKOAuth2API(object):
    """LinkedIn OAuath1 API"""

    def __init__(self, client_id=None, client_secret=None):
        if not client_id or not client_secret:
            raise ValueError
        self._client_id = client_id
        self._client_secret = client_secret

    def get_request_url(self):
        from regioh.default_config import LK_REDIRECT_URL
        redirect_url = LK_REDIRECT_URL

        authorize_url = 'https://www.linkedin.com/uas/oauth2/authorization'
        scope = "r_basicprofile%20r_emailaddress%20r_network"
        state = "DCEEFWF45453sdffef424"

        params = []
        params.append("response_type={0}".format("code"))
        params.append("client_id={0}".format(self._client_id))
        params.append("scope={0}".format(scope))
        params.append("state={0}".format(state))
        params.append("redirect_uri={0}".format(redirect_url))
        return "{0}?{1}".format(authorize_url, "&".join(params))

    def get_access_token(self, code):
        from regioh.default_config import LK_REDIRECT_URL
        redirect_url = LK_REDIRECT_URL

        access_token_url = 'https://www.linkedin.com/uas/oauth2/accessToken'
        params = {"client_id": self._client_id, "client_secret": self._client_secret,
                  "code": code, "grant_type": "authorization_code",
                  "redirect_uri":redirect_url}
        resp = requests.request('POST', access_token_url, data=params)
        if resp.status_code == 200:
            return resp.json()
        else:
            return None

if __name__ =='__main__':
    import os
    import sys
    path = os.getcwd()
    if path not in sys.path:
        sys.path.append(path)

    from regioh.default_config import LK_CLIENT_SECRET
    from regioh.default_config import LK_CLIENT_ID
    oauth2 = LKOAuth2API(LK_CLIENT_ID, LK_CLIENT_SECRET)
    print oauth2.get_request_url()

    accepted = 'n'
    while accepted.lower() == 'n':
        accepted = raw_input('Have you authorized me? (y/n) ')
        code = raw_input('What is the authorization code? ')

    print oauth2.get_access_token(code)

