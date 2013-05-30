# -*- coding: utf-8 -*-
"""
"""
import os
from regioh import app
from flask import Flask, request, session, jsonify, redirect, url_for, render_template
from regioh.exceptions import abort
#from regioh.api_helper import fetch_public_key
from regioh.api_helper import query_dynamodb_reg
from regioh.api_helper import update_dynamodb
from regioh.api_helper import get_code_check
from regioh.utils import extract_request_data
from regioh.utils import _format_response
import json

@app.route('/v3/register', methods=['POST'])
@extract_request_data
def register():
    from regioh.api_helper import register_email
    from regioh.default_config import MESSAGE
    item = get_code_check(session['security_code'])
    if item['status'] == MESSAGE['success']:
        register_email(item['linkedin_id'], session['user_email'],
                       session['pubkey'], session['security_code'], item)

        #item['pubkey'] = session['pubkey']
    item = _format_response(item)
    return jsonify(code=200, result=item, status=item)

@app.route('/v3/authenticate', methods=['POST'])
@extract_request_data
def authenticate():
    from regioh.api_helper import auth_email
    from regioh.default_config import MESSAGE
    item = get_code_check(session['security_code'])
    if item['status'] == MESSAGE['success']:
        auth_email(item['linkedin_id'], session['user_email'],
                   session['pubkey'], session['security_code'], item)

        #item = _format_response(item)
        #item['pubkey'] = session['pubkey']
    item = _format_response(item)
    return jsonify(code=200, result=item, status=item)

@app.route('/v3/revoke_key', methods=['POST'])
@extract_request_data
def revoke_key():
    abort(400)

@app.route('/v3/refresh_contacts', methods=['POST'])
@extract_request_data
def refresh_contacts():
    abort(400)

if __name__ == '__main__':
    app.run(host='0.0.0.0')
