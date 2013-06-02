# -*- coding: utf-8 -*-
import json
import logging
import requests
import urlparse

from regioh import app

class LKOAuth2API(object):
    """LinkedIn OAuath1 API"""

    def __init__(self, client_id=None, client_secret=None):
        if not client_id or not client_secret:
            raise ValueError
        self._client_id = client_id
        self._client_secret = client_secret

    def get_request_url():
        from default_config import LK_REDIRECT_URL
        redirect_url = LK_REDIRECT_URL

        authorize_url = 'https://www.linkedin.com/uas/oauth2/authorization'
        scope = "r_fullprofile%20dr_emailaddres%20dr_network"
        state = "DCEEFWF45453sdffef424"

        params = []
        params.append("response_type={0}".format("code"))
        params.append("client_id={0}".format(self._client_id))
        params.append("scope={0}".format(scope))
        params.append("state={0}".format(state))
        params.append("redirect_uri={0}".format(redirect_url))
        return "{0}?{1}".format(authorize_url, "&".join(params))

    def get_access_token(code):
        from default_config import LK_REDIRECT_URL
        redirect_url = LK_REDIRECT_URL

        access_token_url = 'https://www.linkedin.com/uas/oauth2/accessToken'
        params = {"client_id": self._client_id, "client_secret": self._client_secret,
                  "code": code, "grant_type": "authorization_code",
                  "redirect_uri":redirect_url}
        resp = requests.request('POST', access_token_url, params=params)
        if resp.status_code == 200:
            return resp.json()
        else:
            return None
