
# -*- coding: utf-8 -*-
import json
import logging
import requests
import urlparse
from requests_oauthlib import OAuth1

from regioh import app

class LKOAuth1API(object):
    """LinkedIn OAuath1 API"""

    _request_token_url = 'https://api.linkedin.com/uas/oauth/requestToken'
    _access_token_url = 'https://api.linkedin.com/uas/oauth/accessToken'

    def __init__(self, client_id=None, client_secret=None, ticket=None):
        if not client_id or not client_secret:
            raise ValueError
        self._ticket = ticket
        self._client_id = client_id
        self._client_secret = client_secret

    def _request_ticket(self):
        oauth = OAuth1(self._client_id, client_secret=self._client_secret)
        r = requests.post(url=self._request_token_url, params={"scope":
                                                        "r_fullprofile r_emailaddress r_network"},
                        auth=oauth, verify=False)
        ticket = {'key': None, 'value': None}
        if r.status_code == 200:
            request_token = dict(urlparse.parse_qsl(r.content))
            ticket['key'] = request_token['oauth_token']
            ticket['value'] = request_token['oauth_token_secret']
        return r.status_code, r.content, ticket

    def _access_token(self, oauth_token, oauth_secret, pin_code):
        oauth = OAuth1(self._client_id,
                    client_secret=self._client_secret,
                    resource_owner_key=oauth_token,
                    resource_owner_secret=oauth_secret,
                    verifier=pin_code)
        r = requests.post(url=self._access_token_url, auth=oauth, verify=False)
        if r.status_code == 200:
            request_token = dict(urlparse.parse_qsl(r.content))
            return (r.status_code,
                    r.content,
                    request_token['oauth_token'],
                    request_token['oauth_token_secret'],
                    request_token['oauth_expires_in'])
        return r.status_code, r.content, None, None

    def get_request_url(self):
        self._ticket = None
        #app.logger.debug("[check] client_id is {0}".format(self._client_id))
        #app.logger.debug("[check] client_secret is {0}".format(self._client_secret))

        http_code, http_content, self._ticket = self._request_ticket()

        # cache oauth_secret into session
        #app.logger.debug("[check] client_id is {0}".format(oauth_token))
        #app.logger.debug("[check] client_secret is {0}".format(oauth_secret))

        authorize_url ='https://api.linkedin.com/uas/oauth/authorize'
        return self._ticket, "{0}?oauth_token={1}".format(authorize_url,
                                                    self._ticket['key'])

    def get_access_token(self, oauth_token, oauth_secret, oauth_verifier):
        #app.logger.debug("[check] client_id is {0}".format(client_id))
        #app.logger.debug("[check] client_secret is {0}".format(client_secret))
        #app.logger.debug("[check] oauth_token is {0}".format(oauth_token))
        #app.logger.debug("[check] oauth_secret is {0}".format(self._ticket['key']))
        #app.logger.debug("[check] oauth_verifier is {0}".format(oauth_verifier))

        http_code, http_content, access_token, access_secret, expires_in = self._access_token(
            oauth_token,
            oauth_secret,
            oauth_verifier)
        return http_content, access_token, access_secret, expires_in
