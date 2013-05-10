
# -*- coding: utf-8 -*-
"""
"""
import os
from regioh import app
from flask import Flask, request, jsonify, redirect, url_for, render_template
from .exceptions import abort
from api_helper import get_oauth2_access_token
from api_helper import get_oauth2_request_url
from api_helper import get_linkedin_basic_profile
from api_helper import addto_dynamodb_reg
from api_helper import addto_dynamodb_signup
from api_helper import query_dynamodb_reg
from api_helper import update_dynamodb
from api_helper import generate_security_code
from api_helper import notify_email
from api_helper import get_oauth1_request_url
import json
import base64
import datetime

@app.route('/signup', methods=['GET'])
def signup():
    if request.args.get('error', None):
        #redirect by Linked Authentication Server if user cancel
        return redirect(
            url_for('notify',
                    message=base64.b64encode(
                        'Non-Authorized access from LinkedIn')
                   )
            )
    if request.args.get('code', None) and request.args.get('state', None):
        #redirect by Linked Authentication Server if user allow
        code = request.args.get('code', None)
        token = get_oauth2_access_token(code)
        if not token and not token.get("access_token", None):
            return redirect(
                url_for('notify',
                        status=base64.b64encode('linkedin_error'),
                        name = base64.b64encode(first_name),
                        message=base64.b64encode(
                            'Linkedin server server for authorization.'
                            )
                       )
                )

        #retrive linkedin _id, and primary e-mail from Linkedin Server
        status, profile = get_linkedin_basic_profile(token.get("access_token"))
        if status == 200 and profile :
            user_email = profile.get("emailAddress", None)
            first_name = profile.get("firstName", None)
            last_name = profile.get("lastName", None)
            linked_id = profile.get("id", None)

            #check whether account has primary email
            if not user_email:
                return redirect(
                    url_for('notify',
                            name = base64.b64encode(first_name),
                            message=base64.b64encode(
                                'Non primary e-mail from LinkedIn'
                                )
                           )
                    )
            # The following part will [add/update] account with new token
            # on REG server and send notification
            security_code = generate_security_code()
            item = addto_dynamodb_signup(linked_id, token=security_code)
            expires_in_utc = datetime.datetime.strptime(
                item.get('expires_in_utc', None),
                "%Y-%m-%d %H:%M")
            title = "Hi {0} {1},".format(first_name, last_name)
            content = "Below please find your one-time security code for Cipherbox setup." 
            footer = "Yours Securely,\n-The Cipherbox Team"
            signature = "Cloudioh Inc.\nwww.cloudioh.com"
            success = notify_email(user_email, "\n\n".join([title, content,
                                                            security_code, footer,
                                                            signature
                                                           ]))
            if success:
                return redirect(
                    url_for('notify',
                            name=base64.b64encode(first_name),
                            email=base64.b64encode(user_email),
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
                            name=base64.b64encode(first_name),
                            email=base64.b64encode(user_email),
                            message=base64.b64encode(
                                'SESAddressNotVerifiedError'
                                )
                           )
                    )

    # Oauth1
    return redirect(get_oauth1_request_url())
    # Oauth2
    #return redirect(get_oauth2_request_url())


@app.route('/notify', methods=['GET'])
def notify():
    name = None
    email = None
    message = None
    expires_in_utc = None
    status = None
    if request.args.get('name',None):
        name = base64.b64decode(request.args['name'])
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

