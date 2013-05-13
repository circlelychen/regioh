
# -*- coding: utf-8 -*-
"""
"""
import os
from regioh import app
from flask import Flask, request, jsonify, redirect, url_for, render_template
from .exceptions import abort
from api_helper import get_linkedin_basic_profile
from api_helper import addto_dynamodb_signup
from api_helper import generate_security_code
from api_helper import notify_email
from api_helper import get_oauth1_request_url
from api_helper import get_oauth1_access_token
import json
import base64
import datetime

@app.route('/signup/<status>', methods=['GET'])
def signup(status):
    if status == 'cancel':
        return redirect(
            url_for('notify',
                    status=base64.b64encode('cancel'),
                    message=base64.b64encode(
                        'Non-Authorized access from LinkedIn')
                   )
            )
    if status == 'success':
        #Oauth1
        oauth_token = request.args.get('oauth_token', None)
        oauth_verifier = request.args.get('oauth_verifier', None)
        content, access_token, access_secret = get_oauth1_access_token(oauth_token,
                                                                   oauth_verifier)
        if not access_token or not access_secret:
            return redirect(
                url_for('notify',
                        status=base64.b64encode('linkedin_error'),
                        name=base64.b64encode(first_name.encode('utf-8')),
                        message=base64.b64encode(
                            'Linkedin server server for authorization.'
                            )
                       )
                )

        status, profile = get_linkedin_basic_profile(access_token, access_secret)
        if status == 200 and profile :
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
            item = addto_dynamodb_signup(linked_id, token=security_code, oauth1_data=content)
            expires_in_utc = datetime.datetime.strptime(
                item.get('expires_in_utc', None),
                "%Y-%m-%d %H:%M")
            title = u"Hi {0} {1},".format(first_name, last_name)
            print title
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

    # Oauth1
    if status == 'start':
        return redirect(get_oauth1_request_url())
    else:
        return redirect(url_for('home'))


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

