
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
from api_helper import addto_dynamodb
from api_helper import query_dynamodb
import json
import base64

@app.route('/signup', methods=['GET'])
def signup():
    if request.args.get('error', None):
        return redirect(url_for('notify',
                               message=base64.b64encode(
                                   'Non-Authorized access from LinkedIn')
                               )
                       )

    if request.args.get('code', None) and request.args.get('state', None):
        code = request.args.get('code', None)
        token = get_oauth2_access_token(code)

        #retrive linkedin _id, and primary e-mail
        status, profile = get_linkedin_basic_profile(token.get("access_token"))
        if status == 200 and profile :
            user_email = profile.get("emailAddress", None)
            first_name = profile.get("firstName", None)
            last_name = profile.get("lastName", None)
            linked_id = profile.get("id", None)

            #check validation for Linkedin User
            if not user_email:
                return redirect(url_for('notify',
                                       name = base64.b64encode(first_name),
                                       message=base64.b64encode(
                                           'Non primary e-mail from LinkedIn')
                                       )
                               )
            #check status for Linkedin User
            status, record = query_dynamodb(user_email)
            if status == u'active':
                return redirect(url_for('notify',
                                       name=base64.b64encode(first_name),
                                       message=base64.b64encode(
                                           'Already registered')
                                       )
                               )
            elif status == u'inactive':  # mean a pending activation is on the way
                return redirect(url_for('notify',
                                       name=base64.b64encode(first_name),
                                       email=base64.b64encode(user_email),
                                       message=base64.b64encode(
                                           'Registration Pending. '
                                           'Please check your primary email address:'
                                           )
                                       )
                               )
            elif status == u'invalid':
                pass
            else:  # 'empty'
                pass

            #generate security code and email it to user
            from api_helper import generate_security_code
            from api_helper import notify_email
            security_code = generate_security_code()
            if linked_id:
                addto_dynamodb(user_email, token=security_code,
                               linked_id=linked_id, status='inactive'
                              )

            # now email with security code
            title = "Hi {0} {1}".format(first_name, last_name)
            content = "Below please find your one-time security code for Cipherbox setup." 
            footer = "Yours Securely,\n-The Cipherbox Team"
            signature = "Cloudioh Inc.\nwww.cloudioh.com"
            notify_email(user_email, "\n\n".join([title, content,
                                                  security_code, footer,
                                                  signature
                                                 ]))
            return redirect(url_for('notify',
                                   name=base64.b64encode(first_name),
                                   email=base64.b64encode(user_email),
                                   message=base64.b64encode(
                                       'Your one-time security code has been emailed '
                                       'to your LinkedIn primary email address:'
                                       )
                                  )
                           )

    #redirect to oauth2 page for LinkedIn user
    return redirect(get_oauth2_request_url())


@app.route('/notify', methods=['GET'])
def notify():
    name = None
    email = None
    message = None
    if request.args.get('name',None):
        name = base64.b64decode(request.args['name'])
    if request.args.get('email',None):
        email = base64.b64decode(request.args['email'])
    if request.args.get('message',None):
        message = base64.b64decode(request.args['message'])
    return render_template('notify.html',
                           name=name,
                           email=email,
                           message=message
                          )

@app.route('/home', methods=['GET'])
def home():
    return render_template('home.html')

