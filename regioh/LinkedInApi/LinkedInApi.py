# -*- coding: utf-8 -*-
import json
import logging
import requests
import urlparse
from requests_oauthlib import OAuth1

class LKAPI(object):
    """Google Drive Wrapperd API"""

    _LINKEDIN_API_URL = 'https://api.linkedin.com/'

    def __init__(self, client_id=None, client_secret=None):
        if not client_id or not client_secret:
            raise ValueError
        self._client_id = client_id
        self._client_secret = client_secret

    def _linkedin_request(self, url, access_token):
        #oauth = OAuth1(self._client_id, client_secret=self._client_secret,
        #               resource_owner_key=oauth_token,
        #               resource_owner_secret=oauth_secret)

        #resp = requests.get(url,
        #                    params={
        #                        'format': 'json'
        #                    },
        #                    auth=oauth
        #                )
        resp = requests.get(url=url,
                            params={
                                "oauth2_access_token": access_token,
                                "format": "json"
                            },
                            verify=False)
        if resp.status_code == 200:
            return resp.status_code, resp.json()
        return resp.status_code, {'reason': 'unknown error', 'raw': resp.content}

    def get_basic_profile(self, access_token=None):
        url = urlparse.urljoin(
            self._LINKEDIN_API_URL,
            'v1/people/~:(id,first-name,last-name,picture-url,public-profile-url,positions,headline,email-address)')
        return self._linkedin_request(url, access_token)

    def get_connection(self, access_token=None):
        url = urlparse.urljoin(
            self._LINKEDIN_API_URL, 'v1/people/~/connections'
            ':(id,first-name,last-name,positions,picture-url,public-profile-url)')
        return self._linkedin_request(url, access_token)

if __name__ == '__main__':
    logger = logging.getLogger('LinkedInApi.LinkedInApi')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)
