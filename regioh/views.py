
# -*- coding: utf-8 -*-
"""
"""
import os
from regioh import app
from flask import Flask, request, session, jsonify, redirect, url_for, render_template
from .exceptions import abort
from api_helper import addto_dynamodb_signup
from api_helper import generate_security_code
from api_helper import notify_email

import json
import base64
import datetime

from regioh.default_config import LK_CLIENT_SECRET
from regioh.default_config import LK_CLIENT_ID
from regioh.LinkedInApi import LKOAuth1API
from regioh.LinkedInApi import LKOAuth2API
from regioh.LinkedInApi import LinkedInApi

@app.route('/signup/start', methods=['GET'])
def signup_start():
    lk_oauth2_api = LKOAuth2API.LKOAuth2API(client_id=LK_CLIENT_ID,
                                            client_secret=LK_CLIENT_SECRET)
    url = lk_oauth2_api.get_request_url()
    return redirect(url)

@app.route('/signup', methods=['GET'])
def signup():
    #Oauth2
    app.logger.debug('asdfadsfa')
    code = request.args.get('code', None)
    state = request.args.get('state', None)
    if not code or not state:
        return redirect(
            url_for('notify',
                    status=base64.b64encode('cancel'),
                    message=base64.b64encode(
                        'Non-Authorized access from LinkedIn')
                   )
            )
    try:
        lk_oauth2_api = LKOAuth2API.LKOAuth2API(client_id=LK_CLIENT_ID,
                                                client_secret=LK_CLIENT_SECRET)
        linkedin_credential = lk_oauth2_api.get_access_token(code)
    except Exception as e:
        abort(401)

    if not linkedin_credential or \
       not linkedin_credential['access_token']:
        return redirect(
            url_for('notify',
                    status=base64.b64encode('linkedin_error'),
                    name=base64.b64encode(first_name.encode('utf-8')),
                    message=base64.b64encode(
                        'Linkedin server for authorization.'
                        )
                    )
            )

    access_token = linkedin_credential['access_token']
    expires_in = linkedin_credential['expires_in']
    lkapi = LinkedInApi.LKAPI(client_id=LK_CLIENT_ID, client_secret=LK_CLIENT_SECRET)
    status, profile = lkapi.get_basic_profile(access_token)
    if status != 200 or not profile:
        app.logger.error('status:{0} \n message:{1}'.format(status,
                                                            profile))
    user_email = profile.get("emailAddress", None)
    first_name = profile.get("firstName", None)
    last_name = profile.get("lastName", None)
    linked_id = profile.get("id", None)

    #check whether account has primary email
    if not user_email:
        return redirect(
            url_for('notify',
                    name=base64.b64encode(first_name.encode('utf-8')),
                    status=base64.b64encode('cancel'),
                    message=base64.b64encode(
                        'Non primary e-mail from LinkedIn'
                        )
                    )
            )
    # The following part will [add/update] account with new token
    # on REG server and send notification
    ########
    security_code = generate_security_code()
    ########
    # use oauth1 access data to replace security code
    #security_code = content
    ########
    item = addto_dynamodb_signup(linked_id, token=security_code,
                                 oauth2_data=json.dumps(linkedin_credential),
                                 access_token=access_token,
                                 oauth_expires_in=expires_in)
    expires_in_utc = datetime.datetime.strptime(
        item.get('expires_in_utc', None),
        "%Y-%m-%d %H:%M")
    title = u"Hi {0} {1},".format(first_name, last_name)
    content = "Below please find your one-time security code for Cipherbox setup."
    footer = "Yours Securely,\n-The Cipherbox Team"
    signature = "Cloudioh Inc.\nwww.cloudioh.com"
    success = notify_email(user_email, "\n\n".join([title, content,
                                                    #base64.b64encode(security_code),
                                                    security_code,
                                                    footer,
                                                    signature
                                                    ]))
    if success:
        return redirect(
            url_for('notify',
                    name=base64.b64encode(first_name.encode('utf-8')),
                    email=base64.b64encode(user_email),
                    status=base64.b64encode('success'),
                    expires_in_utc=base64.b64encode(
                        expires_in_utc.strftime("%Y-%m-%d %H:%S")),
                    message=base64.b64encode(
                        'Your one-time security code has been emailed '
                        'to your LinkedIn primary email address:'
                        )
                    )
            )
    else:
        #send email fail
        return redirect(
            url_for('notify',
                    name=base64.b64encode(first_name.encode('utf-8')),
                    email=base64.b64encode(user_email),
                    status='cancel',
                    message=base64.b64encode(
                        'SESAddressNotVerifiedError'
                        )
                    )
            )

#@app.route('/signup/<status>', methods=['GET'])
#def signup(status):
#    if status == 'cancel':
#        return redirect(
#            url_for('notify',
#                    status=base64.b64encode('cancel'),
#                    message=base64.b64encode(
#                        'Non-Authorized access from LinkedIn')
#                   )
#            )
#    if status == 'success':
#        #Oauth1
#        oauth_token = request.args.get('oauth_token', None)
#        oauth_verifier = request.args.get('oauth_verifier', None)
#        if not oauth_token or not oauth_verifier:
#            app.logger.error('LinkedIn redirect Request failed')
#            abort(401)
#        try:
#            lk_oauth1_api = LKOAuth1API.LKOAuth1API(client_id=LK_CLIENT_ID,
#                                                    client_secret=LK_CLIENT_SECRET)
#            content, access_token, access_secret, expires_in = lk_oauth1_api.get_access_token(oauth_token,
#                                                                                              session[oauth_token],
#                                                                                              oauth_verifier)
#        except Exception as e:
#            abort(401)
#
#        if not access_token or not access_secret:
#            return redirect(
#                url_for('notify',
#                        status=base64.b64encode('linkedin_error'),
#                        name=base64.b64encode(first_name.encode('utf-8')),
#                        message=base64.b64encode(
#                            'Linkedin server for authorization.'
#                            )
#                       )
#                )
#
#        lkapi = LinkedInApi.LKAPI(client_id=LK_CLIENT_ID, client_secret=LK_CLIENT_SECRET)
#        status, profile = lkapi.get_basic_profile(access_token, access_secret)
#        if status != 200 or not profile:
#            app.logger.error('status:{0} \n message:{1}'.format(status,
#                                                                profile))
#        user_email = profile.get("emailAddress", None)
#        first_name = profile.get("firstName", None)
#        last_name = profile.get("lastName", None)
#        linked_id = profile.get("id", None)
#
#        #check whether account has primary email
#        if not user_email:
#            return redirect(
#                url_for('notify',
#                        name=base64.b64encode(first_name.encode('utf-8')),
#                        status=base64.b64encode('cancel'),
#                        message=base64.b64encode(
#                            'Non primary e-mail from LinkedIn'
#                            )
#                        )
#                )
#        # The following part will [add/update] account with new token
#        # on REG server and send notification
#        ########
#        security_code = generate_security_code()
#        ########
#        # use oauth1 access data to replace security code
#        #security_code = content
#        ########
#        item = addto_dynamodb_signup(linked_id, token=security_code,
#                                        oauth1_data=content,
#                                        oauth_token=access_token,
##                                        oauth_token_secret=access_secret,
#                                        oauth_expires_in=expires_in)
#        expires_in_utc = datetime.datetime.strptime(
#            item.get('expires_in_utc', None),
#            "%Y-%m-%d %H:%M")
#        title = u"Hi {0} {1},".format(first_name, last_name)
#        content = "Below please find your one-time security code for Cipherbox setup."
#        footer = "Yours Securely,\n-The Cipherbox Team"
#        signature = "Cloudioh Inc.\nwww.cloudioh.com"
#        success = notify_email(user_email, "\n\n".join([title, content,
#                                                        #base64.b64encode(security_code),
#                                                        security_code,
#                                                        footer,
#                                                        signature
#                                                        ]))
#        if success:
#            return redirect(
#                url_for('notify',
#                        name=base64.b64encode(first_name.encode('utf-8')),
#                        email=base64.b64encode(user_email),
#                        status=base64.b64encode('success'),
#                        expires_in_utc=base64.b64encode(
#                            expires_in_utc.strftime("%Y-%m-%d %H:%S")),
#                        message=base64.b64encode(
#                            'Your one-time security code has been emailed '
#                            'to your LinkedIn primary email address:'
#                            )
#                        )
#                )
#        else:
#            #send email fail
#            return redirect(
#                url_for('notify',
#                        name=base64.b64encode(first_name.encode('utf-8')),
#                        email=base64.b64encode(user_email),
#                        status='cancel',
#                        message=base64.b64encode(
#                            'SESAddressNotVerifiedError'
#                            )
#                        )
#                )
#
#    # Oauth1
#    if status == 'start':
#        lk_oauth1_api = LKOAuth1API.LKOAuth1API(client_id=LK_CLIENT_ID,
#                                                client_secret=LK_CLIENT_SECRET)
#        ticket, url = lk_oauth1_api.get_request_url()
#        session[ticket['key']] = ticket['value']
#        return redirect(url)
#    else:
#        return redirect(url_for('home'))

@app.route('/notify', methods=['GET'])
def notify():
    name = None
    email = None
    message = None
    expires_in_utc = None
    status = None
    if request.args.get('name',None):
        name = base64.b64decode(request.args['name']).decode('utf-8')
        #name = request.args['name']
    if request.args.get('email',None):
        email = base64.b64decode(request.args['email'])
    if request.args.get('expires_in_utc',None):
        expires_in_utc = base64.b64decode(request.args['expires_in_utc'])
    if request.args.get('message',None):
        message = base64.b64decode(request.args['message'])
    if request.args.get('status',None):
        status = base64.b64decode(request.args['status'])
    return render_template('notify.html',
                           name=name,
                           email=email,
                           expires_in_utc=expires_in_utc,
                           message=message,
                           status = status
                          )

@app.route('/home', methods=['GET'])
def home():
    return render_template('home.html')

