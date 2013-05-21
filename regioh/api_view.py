# -*- coding: utf-8 -*-
"""
"""
import os
from regioh import app
from flask import Flask, request, jsonify, redirect, url_for, render_template
from .exceptions import abort
from api_helper import fetch_public_key
from api_helper import query_dynamodb_reg
#from api_helper import get_db_data
from api_helper import update_dynamodb
from api_helper import verify_linkedin_status
from api_helper import get_token_check
import json

def _extract_request_data(request):
    if request.form:
        user_email = request.form.get('email', None)
        pub_key = request.form.get('pubkey', None)
        pub_key_md5 = request.form.get('pubkey_md5', 'N/A')
        permid = request.form.get('permid', 'N/A')
        linked_data = request.form.get('linkedin_data', None)
        token = request.form.get('token', None)
        linkedin_id = request.form.get('linkedin_id', None)
        security_code = request.form.get('identity_code', None)
    else:
        try:
            jreq = json.loads(request.data)
        except:
            abort(400, {'message': 'incorrect POST data: {0}'.format(request.data)})
        user_email = jreq.get('email', None)
        pub_key_md5 = jreq.get('pubkey_md5', '')
        permid = jreq.get('permid', '')
        pub_key = jreq.get('pubkey', None)
        linked_data = jreq.get('linkedin_data', {})
        token = jreq.get('token', None)
        linkedin_id = jreq.get('linkedin_id', None)
        security_code = jreq.get('identity_code', None)
    return user_email, pub_key, linked_data, token, pub_key_md5, permid, linkedin_id, security_code

@app.route('/v2/register', methods=['POST'])
def v2_register():
    from default_config import MESSAGE
    from api_helper import addto_dynamodb_reg
    user_email, pubkey, linked_token, _, key_md5, perm_id, linkedin_id, token = _extract_request_data(request)

    item = get_token_check(token)
    if item['status'] == MESSAGE['success']:
        from api_helper import register_email
        linkedin_id = item['linkedin_id']
        register_email(linkedin_id, user_email, pubkey, token, item)

        item['pubkey'] = pubkey
        del item['oauth_token']
        del item['oauth_token_secret']
        del item['token']
        del item['reg_data']
        return jsonify(code=200, result=item, status=item)
    else:
        del item['oauth_token']
        del item['oauth_token_secret']
        del item['token']
        del item['reg_data']
        return jsonify(code=200, result=item, status=item)

#@app.route('/v1/check', methods=['POST'])
#def v1_check():
#    """Verify if the (email, public key) is active/present"""
#    user_email, _, linked_data, _, _, _, linkedin_id, security_code = _extract_request_data(request)
#    if user_email is None or linkedin_id is None:
#        abort(400, {'code': 400,
#                    'message': 'missing email or linked id'
#                   })
#    status, record = query_dynamodb_reg(linkedin_id, email=user_email)
#    return jsonify(code=200, status=status)

#@app.route('/v1/fetch_token', methods=['GET'])
#def v1_fetch_token():
#    """return linkedin access token if token valid"""
#    identity_code = request.args.get('identity_code',None)
#    if not identity_code:
#        abort(400, {'code': 400,
#                    'message': 'missing code'
#                   })
#    item = get_token_check(identity_code)
#    return jsonify(code=200, status=item)

#@app.route('/v1/register', methods=['POST'])
#def v1_register():
#    from default_config import MESSAGE
#    from api_helper import addto_dynamodb_reg
#    user_email, pubkey_id, linked_token, _, key_md5, perm_id, linkedin_id, token = _extract_request_data(request)
#
#    item = get_token_check(token)
#    if item['status'] == MESSAGE['success']:
#        addto_dynamodb_reg(linkedin_id, pubkey=pubkey_id,
#                           token=token,pubkey_md5=key_md5,
#                           perm_id=perm_id, email=user_email,
#                           status='active'
#                          )
#        return jsonify(code=200, status='active')
#    else:
#        return jsonify(code=200, status=item)


#@app.route('/v1/linkedin', methods=['POST'])
#def v1_linkedin():
#    try:
#        jreq = json.loads(request.data)
#    except:
#        abort(400, {'message': 'incorrect POST data: {0}'.format(request.data)})
#    linked_ids = jreq.get('linkedin_ids', [])
#    result = verify_linkedin_status(linked_ids)
#    return jsonify(code=200, status=result)

#@app.route('/v1/fetch_data', methods=['POST'])
#def v1_fetch_data():
#    try:
#        jreq = json.loads(request.data)
#    except:
#        abort(400, {'message': 'incorrect POST data: {0}'.format(request.data)})
#    linked_ids = jreq.get('linkedin_ids', [])
#    result = get_db_data(linked_ids)
#    return jsonify(code=200, status=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0')
