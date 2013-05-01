# -*- coding: utf-8 -*-
"""
"""
import os
from regioh import app
from flask import Flask, request, jsonify
from .exceptions import abort
from api_helper import addto_dynamodb
from api_helper import fetch_public_key
from api_helper import query_dynamodb
from api_helper import get_db_data
from api_helper import retrieve_linkedin_id
from api_helper import update_dynamodb
from api_helper import verify_linkedin_status
import json

def _extract_request_data(request):
    if request.form:
        user_email = request.form.get('email', None)
        pub_key = request.form.get('pubkey', None)
        pub_key_md5 = request.form.get('pubkey_md5', 'N/A')
        permid = request.form.get('permid', 'N/A')
        linked_data = request.form.get('linkedin_data', None)
        token = request.form.get('token', None)
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
        print linked_data
        token = jreq.get('token', None)
    return user_email, pub_key, linked_data, token, pub_key_md5, permid

@app.route('/v1/check', methods=['POST'])
def v1_check():
    """Verify if the (email, public key) is active/present"""
    user_email, _, linked_id, _, _, _ = _extract_request_data(request)
    if user_email is None or linked_id is None:
        abort(400, {'code': 400,
                    'message': 'missing email or linked id'
                   })
    status, record = query_dynamodb(user_email, linked_id=linked_id)
    return jsonify(code=200, status=status)


@app.route('/v1/register', methods=['POST'])
def v1_register():
    from api_helper import generate_R
    from api_helper import compute_C
    from api_helper import notify_email
    from binascii import hexlify
    user_email, pubkey_id, linked_token, _, key_md5, perm_id = _extract_request_data(request)
    status, record = query_dynamodb(user_email)
#    if status == u'active':
#        abort(403, {'code': 403, 'message': 'Already registered'})
#    elif status == u'inactive':  # mean a pending activation is on the way
#        abort(403, {'code': 403, 'message': 'Pending registration'})
#    elif status == u'invalid':
#        pass
#    else:  # 'empty'
#        pass
    R = generate_R()
    #pub_key = fetch_public_key(pubkey_id)
    #C = compute_C(pub_key, R)
    linked_id = retrieve_linkedin_id(linked_token)
    if linked_id:
        # store in dynamoDB
        if record.get('linkedin_id', None) and \
           linked_id != record['linkedin_id']:
            return jsonify(code=403, status='inactive')

        addto_dynamodb(user_email, pubkey_id, token=hexlify(R),
                       pubkey_md5=key_md5, perm_id=perm_id,
                       linked_id=linked_id, status='active'
                      )
    # now email with C
#    notify_email(user_email, C)
#    if app.config['TESTING']:
#        return jsonify(code=200, status='inactive', C=C, R=hexlify(R))
#    else:
        return jsonify(code=200, status='active')
    return jsonify(code=200, status='inactive')


@app.route('/v1/resend', methods=['POST'])
def v1_resend():
    from api_helper import compute_C
    from api_helper import notify_email
    from binascii import unhexlify
    user_email, pubkey_id, _, _, _, _ = _extract_request_data(request)
    status, record = query_dynamodb(user_email, pub_key)
    if status != u'inactive':  # mean a pending activation is on the way
        abort(403, {'code': 403, 'message': 'Invalid registration'})
    pub_key = fetch_public_key(pubkey_id)
    C = compute_C(pub_key, unhexlify(record['token']))
    # store in dynamoDB
    update_dynamodb(record)
    # now email with C
    notify_email(user_email, C)
    return jsonify(code=200, status='inactive')


@app.route('/v1/confirm', methods=['POST'])
def v1_confirm():
    from binascii import hexlify
    user_email, _, linked_token, token, _, _ = _extract_request_data(request)
    status, record = query_dynamodb(user_email, token=token)
    if status == u'active':
        pass
        #abort(403, {'code': 403, 'message': 'Invalid confirmation'})
    elif status == u'invalid':
        abort(404, {'code': 404, 'message': 'No such record'})
    else:  # 'empty'
        pass
    # use linked_data to verify the user id
    linked_id = retrieve_linkedin_id(linked_token)
    if linked_id:
        record['linkedin_id'] = linked_id
        record['status'] = u'active'
        update_dynamodb(record)
    return jsonify(code=200, status=record['status'])

@app.route('/v1/linkedin', methods=['POST'])
def v1_linkedin():
    try:
        jreq = json.loads(request.data)
    except:
        abort(400, {'message': 'incorrect POST data: {0}'.format(request.data)})
    linked_ids = jreq.get('linkedin_ids', [])
    result = verify_linkedin_status(linked_ids)
    return jsonify(code=200, status=result)

@app.route('/v1/fetch_data', methods=['POST'])
def v1_fetch_data():
    try:
        jreq = json.loads(request.data)
    except:
        abort(400, {'message': 'incorrect POST data: {0}'.format(request.data)})
    linked_ids = jreq.get('linkedin_ids', [])
    result = get_db_data(linked_ids)
    return jsonify(code=200, status=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0')
